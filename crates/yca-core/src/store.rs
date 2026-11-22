//! The folder that holds one PKI: the CA certificates, every certificate
//! issued from them and a register of what was issued.
//!
//! One certificate authority, one folder: everything that belongs to it
//! is in here and nowhere else, and deleting the folder deletes it all.
//! Everything in it is a plain file that other tools can read.
//!
//! The private keys of the CAs are never in it; they cannot leave their
//! YubiKeys. The private key of a certificate that was issued with a new
//! key is: it lies in that certificate's folder, with the files that go
//! onto the device.
//!
//! ```text
//! ca.toml               which CAs belong here and which YubiKey holds each
//! root.pem              root CA certificate
//! <root CA name>.crt    the same, in the form devices install to trust it
//! issuing.pem           issuing CA certificate
//! attestation/          each YubiKey's proof that its CA key was made inside it
//! certificates/<name>/  one folder per issued certificate, named after it,
//!                       with the files for its device and nothing else, in
//!                       the form the device's upload form asks for
//!                       (fullchain.crt and private-key.key, or
//!                       certificate.crt and intermediate-ca.crt beside the
//!                       key, or one certificate.p12)
//! certificates/<group>/<name>/
//!                       the same for a certificate that was sorted into a
//!                       group: the groups are folders here as well
//! register/             the register's own copy of every certificate, one
//!                       file each named by serial number
//! crl/                  the current revocation list of each CA
//! index.toml            the register: one entry per issued certificate
//! ```
//!
//! The files in a certificate's folder are there for its owner to take:
//! they can be written again in another form, and deleting one costs the
//! register nothing, since it reads its own copy.
//!
//! More than one program may have the folder open at once: the window, the
//! command line, an agent working through either. Every change takes the
//! folder for itself for as long as it lasts, by a lock on the file
//! `.lock`, and starts from what is on the disk at that moment, so that
//! no two changes are made from the same stale copy and one of them lost.
//!
//! A certificate can be deleted from the register. One that was revoked
//! and has not expired leaves its revocation behind, so that the
//! revocation lists go on naming it.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration as Patience, Instant};

use serde::{Deserialize, Serialize};
use sha2::Digest;
use time::{Duration, OffsetDateTime};
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::revocation_list::CertificateRevocationList;

use zeroize::Zeroizing;

use crate::authority::encode_pem;
use crate::device::CaRole;
use crate::export::{
    CERTIFICATE_FILE, ExportForm, ExportSource, FULLCHAIN_FILE, INTERMEDIATE_FILE, KEY_FILE,
    P12_FILE, P12Encryption, P12Options, export, key_from_p12, p12_encryption,
};
use crate::{
    Attestation, Error, ExportFile, IssuedCertificate, KeyPair, LeafProfile, LeafRequest,
    PublicKeyData, RevocationList, Revoked,
};

const META_FILE: &str = "ca.toml";
/// Tells whoever finds the folder what it is, that it holds no private
/// keys and whether to back it up.
const README_FILE: &str = "README.txt";
const README: &str = include_str!("workspace-readme.txt");
const INDEX_FILE: &str = "index.toml";
/// Where each certificate has a folder of its own.
const CERTIFICATES_DIR: &str = "certificates";
/// Where the register keeps its own copy of every certificate, one file
/// each named by serial number. The folders under `certificates/` hold
/// what the devices get, in whatever form that is, a `.p12` file that
/// only opens with a password among them; the register cannot depend on
/// reading the certificate back from there.
const REGISTER_DIR: &str = "register";
/// The files yca itself puts into a certificate's folder, which go when
/// the certificate is deleted, and the one Finder leaves behind when the
/// folder was looked at. Anything else found there is left alone.
const CERTIFICATE_FILES: [&str; 6] = [
    CERTIFICATE_FILE,
    FULLCHAIN_FILE,
    INTERMEDIATE_FILE,
    KEY_FILE,
    P12_FILE,
    ".DS_Store",
];
/// Those of them that hold a private key. Wherever files of a folder go,
/// these go first: if what follows fails, what is left behind is public.
const KEY_FILES: [&str; 2] = [KEY_FILE, P12_FILE];

/// The name a file of a certificate's folder is written under before it
/// takes its own. One that is found was left by a write that did not
/// finish, and may hold a private key like the file it was to become.
fn temporary(name: &str) -> String {
    format!(".{name}.tmp")
}
const ATTESTATION_DIR: &str = "attestation";
const CRL_DIR: &str = "crl";
const RETIRED_DIR: &str = "retired";
/// The layout of the workspace. A build of yca refuses one it does not
/// know, which can only be a newer one: there is none from before.
const FORMAT_VERSION: u32 = 1;

/// How long before its end a certificate counts as expiring soon.
const EXPIRES_SOON: Duration = Duration::days(30);

/// The file whose lock says that a program is changing the workspace.
const LOCK_FILE: &str = ".lock";
/// How long a change waits for another program's change to finish. One
/// change takes milliseconds; waiting longer means something is stuck.
const LOCK_PATIENCE: Patience = Patience::from_secs(10);

/// The workspace, held for one change. Let go of when dropped: closing
/// the file gives up its lock.
struct Held {
    _lock: fs::File,
}

/// The longest name a group of certificates may have, in characters.
const GROUP_NAME_LIMIT: usize = 60;

/// One CA of this PKI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaEntry {
    /// Subject of the CA certificate.
    pub subject: String,
    /// Serial number of the YubiKey that holds the CA key.
    pub yubikey: u32,
    /// When the CA certificate expires.
    #[serde(with = "time::serde::rfc3339")]
    pub not_after: OffsetDateTime,
    /// Number of the last revocation list this CA signed; zero if it has
    /// not signed one.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub crl_number: u64,
}

fn is_zero(number: &u64) -> bool {
    *number == 0
}

/// An issuing CA that was replaced, as when its YubiKey was lost. The
/// certificates it signed stay valid, but its key is gone: they can be
/// neither renewed by it nor revoked one by one. What remains possible is
/// for the root CA to revoke the retired CA as a whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetiredCa {
    /// Subject of its certificate.
    pub subject: String,
    /// Serial number of its certificate, in lowercase hexadecimal.
    pub serial: String,
    /// Key identifier of its certificate, which the register entries of
    /// the certificates it signed carry as `issuer_key_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// When its certificate expires.
    #[serde(with = "time::serde::rfc3339")]
    pub not_after: OffsetDateTime,
    /// When the root CA revoked it, if it did.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub revoked_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Meta {
    version: u32,
    root: CaEntry,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issuing: Option<CaEntry>,
    /// Issuing CAs that were replaced, oldest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    retired: Vec<RetiredCa>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Index {
    #[serde(default, rename = "certificate")]
    certificates: Vec<Record>,
    /// What is left of revoked certificates that were deleted from the
    /// register before they expired.
    #[serde(default, rename = "revocation", skip_serializing_if = "Vec::is_empty")]
    revocations: Vec<KeptRevocation>,
}

/// The revocation of a certificate that is no longer in the register.
/// Deleting a certificate must not make devices accept it again, so this
/// much of it stays until it would have expired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct KeptRevocation {
    serial: String,
    issued_by: CaRole,
    #[serde(with = "time::serde::rfc3339")]
    not_after: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    revoked_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issuer_key_id: Option<String>,
}

/// The register entry of one issued certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// Serial number of the certificate, in lowercase hexadecimal.
    pub serial: String,
    /// What the certificate is for.
    pub profile: LeafProfile,
    /// The names it was issued for.
    pub names: Vec<String>,
    /// Which CA signed it.
    pub issued_by: CaRole,
    /// When it was issued.
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
    /// When it expires.
    #[serde(with = "time::serde::rfc3339")]
    pub not_after: OffsetDateTime,
    /// When it was revoked, if it was.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub revoked_at: Option<OffsetDateTime>,
    /// Serial number of the certificate this one was issued to replace,
    /// for the same key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces: Option<String>,
    /// Key identifier of the CA certificate that signed it. Tells the
    /// certificates of the current issuing CA from those of one it
    /// replaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_key_id: Option<String>,
    /// The group its owner sorted it into, if any: a customer, a site,
    /// whatever they go by. A group exists by having certificates in it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Where the certificate's folder is under `certificates/`: its name,
    /// behind the name of its group's folder if it is in a group
    /// (`Customer A/nas.example.com`).
    pub folder: String,
}

/// The folder of one certificate, inside the workspace: where its files
/// for the device go, a private key among them if yca made the key.
///
/// It is made before the YubiKey signs, so that nothing is signed and then
/// has nowhere to go. If it is still empty when it is let go of, as after
/// a wrong PIN, it is removed again instead of piling up beside the next
/// attempt's.
#[derive(Debug)]
pub struct CertificateFolder {
    name: String,
    path: PathBuf,
    group: Option<String>,
    /// Whether a certificate was entered into the register with this
    /// folder. From then on the register names the folder, and it stays
    /// even while nothing is in it.
    recorded: std::cell::Cell<bool>,
}

impl CertificateFolder {
    /// Where the folder is under `certificates/`: the certificate's first
    /// name, with a number where that name was taken, behind the name of
    /// the group's folder if the certificate goes into a group.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The group the certificate goes into, as the workspace spells it.
    pub fn group(&self) -> Option<&str> {
        self.group.as_deref()
    }

    /// Where the folder is.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Writes one file of the certificate's bundle into the folder. A file
    /// that holds a private key is readable by its owner only.
    ///
    /// The file is replaced in one step. Written over where it lies, a
    /// file that is the only place a private key is in would be empty for
    /// a moment, and a crash in that moment would lose the key.
    pub fn write(&self, file: &ExportFile) -> Result<(), Error> {
        let path = self.path.join(&file.name);
        let temporary = self.path.join(temporary(&file.name));
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        if file.holds_private_key {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let written = options
            .open(&temporary)
            .and_then(|mut target| {
                std::io::Write::write_all(&mut target, &file.contents)?;
                // On the disk before it takes the place of what was there.
                target.sync_all()
            })
            .map_err(|e| io_error(&temporary, e))
            .and_then(|()| fs::rename(&temporary, &path).map_err(|e| io_error(&path, e)));
        if written.is_err() {
            // What did not become the file must not stay beside it: it may
            // be a private key under a name nobody looks for.
            let _ = fs::remove_file(&temporary);
        }
        written
    }
}

/// What writing a certificate's files anew takes.
#[derive(Debug, Clone, Copy)]
pub struct Repack<'a> {
    /// The form to write them in.
    pub form: ExportForm,
    /// The password of the `.p12` file the folder holds now. Needed where
    /// the private key is inside that file and nowhere else.
    pub opens: Option<&'a str>,
    /// The password for the `.p12` file to write, for
    /// [`ExportForm::Pkcs12`].
    pub password: Option<&'a str>,
    /// How to encrypt that file.
    pub encryption: P12Encryption,
}

/// A certificate's folder after its files were written anew.
#[derive(Debug)]
pub struct Repacked {
    /// Where the folder is.
    pub folder: PathBuf,
    /// The files it holds now.
    pub files: Vec<ExportFile>,
}

/// What the folder of a renewed certificate is written from: the form the
/// files of the certificate it replaces are in, and their private key
/// where the workspace has it. A renewal keeps the key, so the new folder
/// holds everything the old one did, and stays complete whatever becomes
/// of the old certificate.
pub struct Renewal {
    form: ExportForm,
    key: Option<Zeroizing<Vec<u8>>>,
    /// For a `.p12` file: its password and how it is encrypted, which the
    /// new file gets too.
    p12: Option<(Zeroizing<String>, P12Encryption)>,
}

impl Renewal {
    /// The files of the renewed certificate.
    pub fn files(&self, issued: &IssuedCertificate, label: &str) -> Result<Vec<ExportFile>, Error> {
        export(
            self.form,
            ExportSource {
                issued,
                private_key_der: self.key.as_ref().map(|key| key.as_slice()),
            },
            self.p12.as_ref().map(|(password, encryption)| P12Options {
                password,
                encryption: *encryption,
                label,
            }),
        )
    }
}

impl Drop for CertificateFolder {
    fn drop(&mut self) {
        if self.recorded.get() {
            return;
        }
        // Only ever removes an empty folder; one with files in it stays.
        // The same goes for the folder of a group this would have been
        // the first certificate of.
        if fs::remove_dir(&self.path).is_ok()
            && self.group.is_some()
            && let Some(group) = self.path.parent()
        {
            let _ = fs::remove_dir(group);
        }
    }
}

/// The fingerprints of a certificate: what a device shows when it asks
/// whether to trust it, so that the two can be held side by side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprints {
    /// SHA-256, as pairs of capital hexadecimal digits with spaces between.
    pub sha256: String,
    /// SHA-1, the same way. Windows calls it the thumbprint and shows no
    /// other.
    pub sha1: String,
}

/// A certificate that was deleted from the register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deleted {
    /// The register entry as it was.
    pub record: Record,
    /// The certificate was revoked and has not expired: its revocation is
    /// kept, and the revocation lists of its CA go on naming it.
    pub revocation_kept: bool,
}

/// How the revocation list a CA signed last stands against the register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrlStatus {
    /// Number of that list; `None` if the CA has not signed one yet.
    pub number: Option<u64>,
    /// Until when devices treat that list as current.
    pub next_update: Option<OffsetDateTime>,
    /// Revoked certificates the list does not name. Devices keep accepting
    /// them until they are given a newer list.
    pub unlisted: usize,
}

/// Where a certificate stands right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// In use and not close to its end.
    Valid,
    /// Still valid, but within 30 days of expiring.
    ExpiresSoon,
    /// Past its end.
    Expired,
    /// Revoked before its end.
    Revoked,
}

impl Record {
    /// Where this certificate stands at `now`.
    pub fn status(&self, now: OffsetDateTime) -> Status {
        if self.revoked_at.is_some() {
            Status::Revoked
        } else if now >= self.not_after {
            Status::Expired
        } else if now >= self.not_after - EXPIRES_SOON {
            Status::ExpiresSoon
        } else {
            Status::Valid
        }
    }
}

/// An open PKI folder.
#[derive(Debug)]
pub struct Store {
    dir: PathBuf,
    meta: Meta,
    index: Index,
}

impl Store {
    /// Starts a new PKI folder around a root CA certificate. The folder
    /// must not already hold a PKI.
    pub fn create(
        dir: impl Into<PathBuf>,
        root_certificate_der: &[u8],
        yubikey: u32,
    ) -> Result<Self, Error> {
        let dir = dir.into();
        if dir.join(META_FILE).exists() {
            return Err(Error::Store(format!(
                "{} already is a workspace folder",
                dir.display()
            )));
        }

        let root = parse(root_certificate_der)?;
        require_ca(&root)?;
        if root.subject().as_raw() != root.issuer().as_raw()
            || root.verify_signature(Some(root.public_key())).is_err()
        {
            return Err(Error::Store(
                "the root CA certificate is not self-signed".to_owned(),
            ));
        }

        fs::create_dir_all(dir.join(CERTIFICATES_DIR)).map_err(|e| io_error(&dir, e))?;
        let store = Self {
            meta: Meta {
                version: FORMAT_VERSION,
                root: ca_entry(&root, yubikey),
                issuing: None,
                retired: Vec::new(),
            },
            index: Index::default(),
            dir,
        };
        store.write(&ca_file(CaRole::Root), &encode_pem(root_certificate_der))?;
        store.write_toml(INDEX_FILE, &store.index)?;
        // Not yet marked as a workspace, so reading the root back works
        // off the entry in memory.
        store.root_for_devices()?;
        store.write(README_FILE, README)?;
        // Written last: its presence is what marks the folder as a PKI.
        store.write_toml(META_FILE, &store.meta)?;
        Ok(store)
    }

    /// Whether `dir` already holds a PKI.
    pub fn exists(dir: impl AsRef<Path>) -> bool {
        dir.as_ref().join(META_FILE).exists()
    }

    /// Opens an existing PKI folder.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, Error> {
        let dir = dir.into();
        if !dir.join(META_FILE).exists() {
            return Err(Error::Store(format!(
                "{} is not a workspace folder",
                dir.display()
            )));
        }
        let meta: Meta = read_toml(&dir.join(META_FILE))?;
        check_format(&dir, meta.version)?;
        let index: Index = read_toml(&dir.join(INDEX_FILE))?;
        // Folders are moved and emptied by what the register says, so a
        // register that points out of the workspace is not gone by.
        let astray = index
            .certificates
            .iter()
            .find(|record| !plain_folder(&record.folder));
        if let Some(record) = astray {
            return Err(Error::Store(format!(
                "the register names a folder outside the workspace for certificate {}",
                record.serial
            )));
        }
        let store = Self { dir, meta, index };
        store.check_cas()?;
        Ok(store)
    }

    /// Makes sure the CA certificates in the folder still belong together:
    /// a root that signed itself, and an issuing CA that this root signed.
    ///
    /// The folder is plain files, often in a place that is synchronised
    /// elsewhere. This catches a CA certificate that was exchanged on its
    /// own. Someone who exchanges both is caught later, by the YubiKeys:
    /// they hold the real certificates, and a key that holds another CA
    /// than the folder says is refused.
    fn check_cas(&self) -> Result<(), Error> {
        let changed = |what: &str| {
            Error::Store(format!(
                "{what} in {}. Something other than yca changed this folder; restore it from \
                 a backup, or start a new workspace from the YubiKeys",
                self.dir.display()
            ))
        };
        let root_der = self.ca_certificate_der(CaRole::Root)?;
        let root = parse(&root_der)?;
        if root.subject().as_raw() != root.issuer().as_raw()
            || root.verify_signature(Some(root.public_key())).is_err()
        {
            return Err(changed("the root CA certificate is not a root's"));
        }
        if self.meta.issuing.is_some() {
            let issuing_der = self.ca_certificate_der(CaRole::Issuing)?;
            let issuing = parse(&issuing_der)?;
            if issuing.verify_signature(Some(root.public_key())).is_err() {
                return Err(changed(
                    "the issuing CA certificate is not signed by the root CA",
                ));
            }
        }
        Ok(())
    }

    /// Adds or replaces the issuing CA. Its certificate must be signed by
    /// this PKI's root.
    pub fn set_issuing(&mut self, certificate_der: &[u8], yubikey: u32) -> Result<(), Error> {
        let _held = self.hold()?;
        let issuing = parse(certificate_der)?;
        require_ca(&issuing)?;
        let root_der = self.ca_certificate_der(CaRole::Root)?;
        let root = parse(&root_der)?;
        if issuing.subject().as_raw() == issuing.issuer().as_raw()
            || issuing.verify_signature(Some(root.public_key())).is_err()
        {
            return Err(Error::Store(
                "the issuing CA certificate is not signed by the root CA of this workspace"
                    .to_owned(),
            ));
        }

        // A replaced issuing CA stays on file: the certificates it issued
        // remain valid and still need it in their chain.
        if self.meta.issuing.is_some() {
            let previous_der = self.ca_certificate_der(CaRole::Issuing)?;
            if previous_der != certificate_der {
                let previous = parse(&previous_der)?;
                let dir = self.dir.join(RETIRED_DIR);
                fs::create_dir_all(&dir).map_err(|e| io_error(&dir, e))?;
                let key_id = key_identifier(&previous);
                let name = key_id.as_deref().unwrap_or("unidentified");
                self.write(
                    &format!("{RETIRED_DIR}/issuing-{name}.pem"),
                    &encode_pem(&previous_der),
                )?;
                // Its last revocation list goes with it. Left where it was,
                // it would be taken for the new CA's, and handed to devices
                // that need a list of the new one.
                for form in ["crl.pem", "crl"] {
                    let list = self.dir.join(CRL_DIR).join(format!("issuing.{form}"));
                    if list.is_file() {
                        let kept = dir.join(format!("issuing-{name}.{form}"));
                        fs::rename(&list, &kept).map_err(|e| io_error(&list, e))?;
                    }
                }
                let serial = serial_number(&previous);
                if !self.meta.retired.iter().any(|ca| ca.serial == serial) {
                    self.meta.retired.push(RetiredCa {
                        subject: previous.subject().to_string(),
                        serial,
                        key_id,
                        not_after: previous.validity().not_after.to_datetime(),
                        revoked_at: None,
                    });
                }
            }
        }

        self.write(&ca_file(CaRole::Issuing), &encode_pem(certificate_der))?;
        self.meta.issuing = Some(ca_entry(&issuing, yubikey));
        self.write_toml(META_FILE, &self.meta)
    }

    /// Keeps a YubiKey's proof that the CA key was generated inside it.
    pub fn save_attestation(&self, role: CaRole, attestation: &Attestation) -> Result<(), Error> {
        let dir = self.dir.join(ATTESTATION_DIR);
        fs::create_dir_all(&dir).map_err(|e| io_error(&dir, e))?;
        let name = role_name(role);
        self.write(
            &format!("{ATTESTATION_DIR}/{name}.pem"),
            &encode_pem(&attestation.certificate_der),
        )?;
        self.write(
            &format!("{ATTESTATION_DIR}/{name}-intermediate.pem"),
            &encode_pem(&attestation.intermediate_der),
        )
    }

    /// The fingerprints of one of the CA certificates.
    pub fn ca_fingerprints(&self, role: CaRole) -> Result<Fingerprints, Error> {
        let der = self.ca_certificate_der(role)?;
        Ok(Fingerprints {
            sha256: spaced_hex(&sha2::Sha256::digest(&der)),
            // The two crates each bring their own `Digest`.
            sha1: spaced_hex(&<sha1::Sha1 as sha1::Digest>::digest(&der)),
        })
    }

    /// The root CA certificate as a file to give to devices that are to
    /// trust this CA: binary (DER) with the ending `.crt`, which macOS,
    /// Windows, iOS and Android all open as a certificate to install, and
    /// named after the CA, as it will be read on the device.
    ///
    /// Written when the workspace is made, and again here if it is
    /// missing or not what it should be. Returns where the file is.
    pub fn root_for_devices(&self) -> Result<PathBuf, Error> {
        let der = self.ca_certificate_der(CaRole::Root)?;
        let root = parse(&der)?;
        let name = root
            .subject()
            .iter_common_name()
            .next()
            .and_then(|name| name.as_str().ok())
            .map_or_else(|| "root CA".to_owned(), folder_name);
        let file = format!("{name}.crt");
        let path = self.dir.join(&file);
        if fs::read(&path).ok().as_deref() != Some(der.as_slice()) {
            self.write_bytes(&file, &der)?;
        }
        Ok(path)
    }

    /// The proof kept for one of the CAs that its key was generated inside
    /// its YubiKey. `None` if there is none, or if what is kept is not
    /// about the CA certificate this workspace has now.
    pub fn attestation(&self, role: CaRole) -> Option<Attestation> {
        let name = role_name(role);
        let read = |file: String| read_pem(&self.dir.join(ATTESTATION_DIR).join(file)).ok();
        let attestation = Attestation {
            certificate_der: read(format!("{name}.pem"))?,
            intermediate_der: read(format!("{name}-intermediate.pem"))?,
        };
        let ca = self.ca_certificate_der(role).ok()?;
        attestation.vouches_for(&ca).then_some(attestation)
    }

    /// The folder this PKI lives in.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// What is known about one of the CAs. The issuing CA is `None` until
    /// it has been added.
    pub fn ca(&self, role: CaRole) -> Option<&CaEntry> {
        match role {
            CaRole::Root => Some(&self.meta.root),
            CaRole::Issuing => self.meta.issuing.as_ref(),
        }
    }

    /// The issuing CAs that were replaced, oldest first.
    pub fn retired(&self) -> &[RetiredCa] {
        &self.meta.retired
    }

    /// The replaced issuing CA that signed a certificate, if one did. Such
    /// a certificate cannot be revoked on its own any more.
    pub fn retired_issuer(&self, record: &Record) -> Option<&RetiredCa> {
        let issuer = record.issuer_key_id.as_ref()?;
        self.meta
            .retired
            .iter()
            .filter(|_| record.issued_by == CaRole::Issuing)
            .find(|ca| ca.key_id.as_ref() == Some(issuer))
    }

    /// Marks a replaced issuing CA as revoked, for when its YubiKey may be
    /// in someone else's hands. Devices learn of it from the next
    /// revocation list of the root CA, and then refuse every certificate
    /// the retired CA signed.
    pub fn revoke_retired(
        &mut self,
        serial: &str,
        now: OffsetDateTime,
    ) -> Result<&RetiredCa, Error> {
        let _held = self.hold()?;
        let position = self
            .meta
            .retired
            .iter()
            .position(|ca| ca.serial == serial)
            .ok_or_else(|| {
                Error::Store(format!(
                    "no replaced issuing CA with serial number {serial}"
                ))
            })?;
        if self.meta.retired[position].revoked_at.is_some() {
            return Err(Error::Store(
                "this issuing CA is already revoked".to_owned(),
            ));
        }
        self.meta.retired[position].revoked_at = Some(whole_seconds(now));
        self.write_toml(META_FILE, &self.meta)?;
        Ok(&self.meta.retired[position])
    }

    /// The CA that signs certificates from day to day: the issuing CA, or
    /// the root CA of a workspace that has none, as when the whole
    /// authority is kept on a single YubiKey.
    pub fn everyday_ca(&self) -> CaRole {
        match self.meta.issuing {
            Some(_) => CaRole::Issuing,
            None => CaRole::Root,
        }
    }

    /// The certificate of one of the CAs.
    pub fn ca_certificate_der(&self, role: CaRole) -> Result<Vec<u8>, Error> {
        if self.ca(role).is_none() {
            return Err(Error::Store(format!("this workspace has no {role} yet")));
        }
        read_pem(&self.dir.join(ca_file(role)))
    }

    /// Every certificate issued so far, oldest first.
    pub fn records(&self) -> &[Record] {
        &self.index.certificates
    }

    /// Finds a certificate by its serial number or by an unambiguous
    /// beginning of it.
    pub fn find(&self, serial: &str) -> Result<&Record, Error> {
        let wanted = serial.trim().to_ascii_lowercase().replace(':', "");
        if wanted.is_empty() {
            return Err(Error::Store("a serial number is required".to_owned()));
        }
        let mut matching = self
            .index
            .certificates
            .iter()
            .filter(|record| record.serial.starts_with(&wanted));
        match (matching.next(), matching.next()) {
            (Some(record), None) => Ok(record),
            (None, _) => Err(Error::Store(format!(
                "no certificate with serial number {wanted}"
            ))),
            (Some(_), Some(_)) => Err(Error::Store(format!(
                "more than one serial number starts with {wanted}"
            ))),
        }
    }

    /// The certificate a register entry stands for.
    pub fn certificate_der(&self, record: &Record) -> Result<Vec<u8>, Error> {
        read_pem(&self.register_copy(&record.serial))
    }

    /// Where the register keeps its own copy of a certificate.
    fn register_copy(&self, serial: &str) -> PathBuf {
        self.dir.join(REGISTER_DIR).join(format!("{serial}.pem"))
    }

    /// The folder of an entry's certificate, whether it is there or not.
    fn folder_of(&self, record: &Record) -> PathBuf {
        self.dir.join(CERTIFICATES_DIR).join(&record.folder)
    }

    /// The form a certificate's files are in, going by what its folder
    /// holds. `None` if it holds none of them.
    ///
    /// A certificate the root CA signed has no intermediate CA, so with
    /// or without a file for one comes to the same; that is called
    /// [`ExportForm::Fullchain`] here.
    pub fn form(&self, record: &Record) -> Option<ExportForm> {
        let folder = self.folder_of(record);
        let has = |name: &str| folder.join(name).is_file();
        let sealed = has(P12_FILE);
        let key_in_clear = has(KEY_FILE);
        let apart = if has(FULLCHAIN_FILE) {
            Some(ExportForm::Fullchain)
        } else if has(CERTIFICATE_FILE) {
            Some(match record.issued_by {
                CaRole::Root => ExportForm::Fullchain,
                CaRole::Issuing => ExportForm::Separate,
            })
        } else {
            None
        };
        // A key in clear beside a `.p12` file means that going from one to
        // the other was interrupted. The folder is then called by the form
        // whose key lies open, never "p12": nobody is to believe a key is
        // behind a password while it is not. Writing the files again
        // finishes what was begun.
        match (sealed, key_in_clear, apart) {
            (true, false, _) | (true, true, None) => Some(ExportForm::Pkcs12),
            (_, _, apart) => apart,
        }
    }

    /// Whether the private key of a certificate is in its folder, in a
    /// file of its own or inside a `.p12` file. A certificate issued for
    /// a device's own request has none here.
    pub fn has_key(&self, record: &Record) -> bool {
        let folder = self.folder_of(record);
        KEY_FILES.iter().any(|name| folder.join(name).is_file())
    }

    /// The CA certificate that has to travel with a certificate: that of
    /// the issuing CA that signed it, which may be one that was replaced
    /// since. `None` for a certificate the root CA signed.
    fn intermediate_der(&self, record: &Record, der: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if record.issued_by == CaRole::Root {
            return Ok(None);
        }
        let retired_file = |ca: &RetiredCa| {
            let name = ca.key_id.as_deref().unwrap_or("unidentified");
            self.dir
                .join(RETIRED_DIR)
                .join(format!("issuing-{name}.pem"))
        };
        // The one the register names, then the issuing CA of today, then
        // every one that was replaced: the entry of a certificate whose CA
        // has no key identifier does not say which it was.
        let candidates = self
            .retired_issuer(record)
            .map(retired_file)
            .into_iter()
            .chain([self.dir.join(ca_file(CaRole::Issuing))])
            .chain(self.meta.retired.iter().map(retired_file));
        // A chain that does not hold is worse than none: only a CA whose
        // key made the signature is taken.
        let leaf = parse(der)?;
        for file in candidates {
            if let Ok(found) = read_pem(&file)
                && parse(&found)
                    .is_ok_and(|ca| leaf.verify_signature(Some(ca.public_key())).is_ok())
            {
                return Ok(Some(found));
            }
        }
        Err(Error::Store(
            "the certificate of the CA that signed it is not in this workspace".to_owned(),
        ))
    }

    /// The private key of a certificate, out of its folder: from the file
    /// it has to itself, or from inside the `.p12` file, which takes that
    /// file's password. `None` where the folder holds no key.
    fn key_in(
        &self,
        folder: &Path,
        opens: Option<&str>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        let in_clear = folder.join(KEY_FILE);
        if in_clear.is_file() {
            return Ok(Some(Zeroizing::new(read_pem(&in_clear)?)));
        }
        let sealed = folder.join(P12_FILE);
        if !sealed.is_file() {
            return Ok(None);
        }
        let password = opens.ok_or_else(|| {
            Error::InvalidRequest(
                "the private key is inside the .p12 file, which takes its password".to_owned(),
            )
        })?;
        let contents = fs::read(&sealed).map_err(|e| io_error(&sealed, e))?;
        key_from_p12(&contents, password).map(Some)
    }

    /// Writes the files of a certificate again in another form, for a
    /// device whose upload form turned out to ask for something else.
    /// Nothing is issued and no YubiKey is needed: the certificate, its
    /// chain and its private key are all in the workspace already.
    ///
    /// The folder ends up with the files of the new form and none of the
    /// old. A private key is written in its new place before it is
    /// removed from the old one.
    pub fn repackage(&mut self, serial: &str, repack: Repack<'_>) -> Result<Repacked, Error> {
        let _held = self.hold()?;
        let record = self.find(serial)?.clone();
        let path = self.folder_of(&record);
        let der = self.certificate_der(&record)?;
        let intermediate = self.intermediate_der(&record, &der)?;
        let key = self.key_in(&path, repack.opens)?;
        let issued = IssuedCertificate::from_der(der, intermediate)?;
        let label = record.names.first().map_or("certificate", String::as_str);
        let files = export(
            repack.form,
            ExportSource {
                issued: &issued,
                private_key_der: key.as_ref().map(|key| key.as_slice()),
            },
            repack.password.map(|password| P12Options {
                password,
                encryption: repack.encryption,
                label,
            }),
        )?;

        // Made again if somebody took it away.
        fs::create_dir_all(&path).map_err(|e| io_error(&path, e))?;
        let folder = CertificateFolder {
            name: record.folder.clone(),
            path: path.clone(),
            group: record.group.clone(),
            recorded: std::cell::Cell::new(true),
        };
        for file in &files {
            folder.write(file)?;
        }
        // What the folder held in its former form goes, a private key
        // first. Stopped anywhere after this line, the folder holds the
        // key once in the place it is meant to be, or it still holds it
        // in clear and `form` says so; never a key in clear that the
        // folder is not called by.
        let kept = |name: &str| files.iter().any(|file| file.name == name);
        for old in KEY_FILES.into_iter().chain(CERTIFICATE_FILES) {
            if old != ".DS_Store" && !kept(old) {
                remove_file(&path.join(old))?;
            }
        }
        // And whatever a write that did not finish left behind.
        for name in CERTIFICATE_FILES {
            remove_file(&path.join(temporary(name)))?;
        }
        // The register did not change, but what it is shown with did: the
        // form, and whether the key is there. Written again, the register
        // tells a window that watches it to look.
        self.write_toml(INDEX_FILE, &self.index)?;
        Ok(Repacked {
            folder: path,
            files,
        })
    }

    /// What a renewal of a certificate writes its files from, read before
    /// the YubiKey signs: a wrong password for a `.p12` file, which the
    /// key is inside of, then costs nothing. `opens` is that password; it
    /// is needed only where the folder holds a `.p12` file.
    ///
    /// A key in the folder that does not belong to the certificate is
    /// refused rather than handed out with a certificate it cannot be used
    /// with.
    pub fn renewal(&self, old: &Record, opens: Option<&str>) -> Result<Renewal, Error> {
        let folder = self.folder_of(old);
        let key = self.key_in(&folder, opens)?;
        if let Some(key) = &key {
            let der = self.certificate_der(old)?;
            let certificate = parse(&der)?;
            let belongs = KeyPair::try_from(key.as_slice()).is_ok_and(|key| {
                certificate.public_key().raw == key.subject_public_key_info().as_slice()
            });
            if !belongs {
                return Err(Error::Store(format!(
                    "the private key in the folder of certificate {} does not belong to it",
                    old.serial
                )));
            }
        }
        let form = self.form(old).unwrap_or_default();
        let p12 = match (form, opens) {
            (ExportForm::Pkcs12, Some(password)) => {
                let sealed = folder.join(P12_FILE);
                let contents = fs::read(&sealed).map_err(|e| io_error(&sealed, e))?;
                Some((
                    Zeroizing::new(password.to_owned()),
                    p12_encryption(&contents),
                ))
            }
            _ => None,
        };
        Ok(Renewal { form, key, p12 })
    }

    /// Puts a certificate among the register's own copies.
    fn keep_copy(&self, serial: &str, pem: &str) -> Result<(), Error> {
        let copies = self.dir.join(REGISTER_DIR);
        fs::create_dir_all(&copies).map_err(|e| io_error(&copies, e))?;
        self.write(&format!("{REGISTER_DIR}/{serial}.pem"), pem)
    }

    /// Where the files of a certificate are, to show them to their owner:
    /// the certificate's folder. `None` if that is gone.
    pub fn certificate_location(&self, record: &Record) -> Option<PathBuf> {
        let place = self.folder_of(record);
        place.exists().then_some(place)
    }

    /// The groups the certificates are sorted into, by name. There is no
    /// list of groups kept anywhere: a group is there while a certificate
    /// is in it.
    pub fn groups(&self) -> Vec<String> {
        let mut groups: Vec<String> = Vec::new();
        for group in self
            .index
            .certificates
            .iter()
            .filter_map(|r| r.group.as_ref())
        {
            if !groups.contains(group) {
                groups.push(group.clone());
            }
        }
        groups.sort_by_key(|group| group.to_lowercase());
        groups
    }

    /// A group's name as the workspace will keep it: tidied of stray
    /// spaces, and spelled like the group that is already there if it only
    /// differs in upper and lower case, so that "office" and "Office" do
    /// not become two groups. `None` for a name that is empty: no group.
    pub fn group_name(&self, wanted: &str) -> Result<Option<String>, Error> {
        let name = wanted.split_whitespace().collect::<Vec<_>>().join(" ");
        if name.is_empty() {
            return Ok(None);
        }
        if name.chars().count() > GROUP_NAME_LIMIT {
            return Err(Error::Store(format!(
                "the name of a group can be {GROUP_NAME_LIMIT} characters long at most"
            )));
        }
        if name.chars().any(char::is_control) {
            return Err(Error::Store(
                "the name of a group cannot hold control characters".to_owned(),
            ));
        }
        let known = self
            .groups()
            .into_iter()
            .find(|group| group.to_lowercase() == name.to_lowercase());
        Ok(Some(known.unwrap_or(name)))
    }

    /// The folder of a group under `certificates/`: the one its
    /// certificates are in already, or for a new group one named after it.
    /// A name that a certificate's own folder or another group's has
    /// there gets a number.
    fn group_folder(&self, group: &str) -> String {
        let top = |folder: &str| folder.split('/').next().unwrap_or(folder).to_lowercase();
        let existing = self
            .index
            .certificates
            .iter()
            .filter(|record| record.group.as_deref() == Some(group))
            .filter_map(|record| record.folder.split_once('/'))
            .map(|(folder, _)| folder.to_owned())
            .next();
        if let Some(folder) = existing {
            return folder;
        }
        let taken: Vec<String> = self
            .index
            .certificates
            .iter()
            .map(|record| top(&record.folder))
            .collect();
        let safe = folder_name(group);
        (1u32..)
            .map(|attempt| match attempt {
                1 => safe.clone(),
                n => format!("{safe} {n}"),
            })
            .find(|candidate| !taken.contains(&candidate.to_lowercase()))
            .expect("there is always another number")
    }

    /// Makes the folder for a certificate that is about to be issued. It
    /// is named after the certificate's first name, the way its owner
    /// thinks of it; a name that is taken, as by the certificate this one
    /// renews, gets a number. A certificate that goes into a group has its
    /// folder inside the group's.
    pub fn new_certificate_folder(
        &self,
        first_name: &str,
        group: Option<&str>,
    ) -> Result<CertificateFolder, Error> {
        let group = match group {
            Some(name) => self.group_name(name)?,
            None => None,
        };
        let within = group.as_deref().map(|group| self.group_folder(group));
        let mut base = self.dir.join(CERTIFICATES_DIR);
        if let Some(within) = &within {
            base.push(within);
        }
        fs::create_dir_all(&base).map_err(|e| io_error(&base, e))?;
        let safe = folder_name(first_name);
        for attempt in 1u32.. {
            let leaf = match attempt {
                1 => safe.clone(),
                n => format!("{safe} {n}"),
            };
            let path = base.join(&leaf);
            match fs::create_dir(&path) {
                Ok(()) => {
                    let name = match &within {
                        Some(within) => format!("{within}/{leaf}"),
                        None => leaf,
                    };
                    return Ok(CertificateFolder {
                        name,
                        path,
                        group,
                        recorded: std::cell::Cell::new(false),
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(io_error(&path, e)),
            }
        }
        unreachable!("the loop only ends by returning")
    }

    /// Moves a certificate into a group, or with `None` out of any. Its
    /// folder moves along, into the folder of the group, so that the
    /// workspace on the disk is sorted the way the list is.
    pub fn set_group(&mut self, serial: &str, group: Option<&str>) -> Result<&Record, Error> {
        let _held = self.hold()?;
        let serial = self.find(serial)?.serial.clone();
        let position = self
            .index
            .certificates
            .iter()
            .position(|record| record.serial == serial)
            .expect("find returned an entry of this register");
        let group = match group {
            Some(name) => self.group_name(name)?,
            None => None,
        };
        if self.index.certificates[position].group == group {
            return Ok(&self.index.certificates[position]);
        }

        let certificates = self.dir.join(CERTIFICATES_DIR);
        let before = self.index.certificates[position].folder.clone();
        // A certificate whose folder somebody took away has nothing to
        // move.
        let from = Some(certificates.join(&before)).filter(|folder| folder.is_dir());
        let mut after = before.clone();
        if let Some(from) = &from {
            let old = &before;
            let within = group.as_deref().map(|group| self.group_folder(group));
            let mut parent = certificates.clone();
            if let Some(within) = &within {
                parent.push(within);
            }
            fs::create_dir_all(&parent).map_err(|e| io_error(&parent, e))?;
            let wanted = old.rsplit('/').next().unwrap_or(old);
            let leaf = (1u32..)
                .map(|attempt| match attempt {
                    1 => wanted.to_owned(),
                    n => format!("{wanted} {n}"),
                })
                .find(|candidate| !parent.join(candidate).exists())
                .expect("there is always another number");
            let to = parent.join(&leaf);
            fs::rename(from, &to).map_err(|e| io_error(&to, e))?;
            after = match &within {
                Some(within) => format!("{within}/{leaf}"),
                None => leaf,
            };
        }

        let previous = self.index.certificates[position].clone();
        self.index.certificates[position].group = group;
        self.index.certificates[position].folder = after.clone();
        if let Err(error) = self.write_toml(INDEX_FILE, &self.index) {
            // The register could not be told, so the folder goes back to
            // where the register says it is.
            if let Some(from) = &from {
                let _ = fs::rename(certificates.join(&after), from);
            }
            self.index.certificates[position] = previous;
            return Err(error);
        }
        // The folder of a group nothing is left in goes with its last
        // certificate.
        if let Some(parent) = from.as_deref().and_then(Path::parent)
            && parent != certificates
        {
            remove_if_empty(parent);
        }
        Ok(&self.index.certificates[position])
    }

    /// Enters a freshly issued certificate into the register and keeps it
    /// in a folder of its own, made here. Refuses a certificate that the
    /// named CA did not sign.
    pub fn record(
        &mut self,
        issued: &IssuedCertificate,
        request: &LeafRequest,
        issued_by: CaRole,
        replaces: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<&Record, Error> {
        // A certificate that replaces another stays in its group.
        let group = replaces
            .and_then(|serial| self.index.certificates.iter().find(|r| r.serial == serial))
            .and_then(|replaced| replaced.group.clone());
        let folder = self.new_certificate_folder(&request.names()[0], group.as_deref())?;
        self.record_in(&folder, issued, request, issued_by, replaces, now)
    }

    /// The same, into a folder that was made before the YubiKey signed.
    pub fn record_in(
        &mut self,
        folder: &CertificateFolder,
        issued: &IssuedCertificate,
        request: &LeafRequest,
        issued_by: CaRole,
        replaces: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<&Record, Error> {
        let _held = self.hold()?;
        let ca_der = self.ca_certificate_der(issued_by)?;
        let ca = parse(&ca_der)?;
        let issuer_key_id = key_identifier(&ca);
        let certificate = parse(issued.der())?;
        if certificate.verify_signature(Some(ca.public_key())).is_err() {
            return Err(Error::Store(format!(
                "the certificate was not signed by the {issued_by} of this workspace"
            )));
        }
        let serial = issued.serial()?;
        if self.index.certificates.iter().any(|r| r.serial == serial)
            || self.index.revocations.iter().any(|r| r.serial == serial)
        {
            return Err(Error::Store(format!(
                "serial number {serial} is already in the register"
            )));
        }

        // The file first, so the register never points at nothing.
        self.keep_copy(&serial, &issued.pem())?;
        self.index.certificates.push(Record {
            serial,
            profile: request.profile(),
            names: request.names().to_vec(),
            issued_by,
            issued_at: whole_seconds(now),
            not_after: issued.not_after(),
            revoked_at: None,
            replaces: replaces.map(str::to_owned),
            issuer_key_id,
            group: folder.group.clone(),
            folder: folder.name.clone(),
        });
        self.write_toml(INDEX_FILE, &self.index)?;
        folder.recorded.set(true);
        Ok(self
            .index
            .certificates
            .last()
            .expect("an entry was just added"))
    }

    /// Takes the workspace for one change, and reads the register and the
    /// list of CAs afresh: another program may have changed them since
    /// this one looked. Whatever is decided and written while the result
    /// is held is decided on what the disk really says, and no other
    /// program writes in between.
    fn hold(&mut self) -> Result<Held, Error> {
        let path = self.dir.join(LOCK_FILE);
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| io_error(&path, e))?;
        let started = Instant::now();
        loop {
            match lock.try_lock() {
                Ok(()) => break,
                Err(fs::TryLockError::WouldBlock) if started.elapsed() < LOCK_PATIENCE => {
                    std::thread::sleep(Patience::from_millis(25));
                }
                Err(fs::TryLockError::WouldBlock) => {
                    return Err(Error::Store(
                        "another program is changing this workspace; try again in a moment"
                            .to_owned(),
                    ));
                }
                Err(fs::TryLockError::Error(e)) => return Err(io_error(&path, e)),
            }
        }
        self.meta = read_toml(&self.dir.join(META_FILE))?;
        // Another program may have moved the workspace on since it was
        // opened here.
        check_format(&self.dir, self.meta.version)?;
        self.index = read_toml(&self.dir.join(INDEX_FILE))?;
        Ok(Held { _lock: lock })
    }

    /// Something that changes whenever the register or the list of CAs is
    /// written, by whichever program: for one that shows the workspace to
    /// notice that it should look again. `None` if the folder is gone.
    pub fn stamp(dir: impl AsRef<Path>) -> Option<String> {
        let mut stamp = String::new();
        for name in [META_FILE, INDEX_FILE] {
            let file = fs::metadata(dir.as_ref().join(name)).ok()?;
            let written = file.modified().ok()?;
            let since = written.duration_since(std::time::UNIX_EPOCH).ok()?;
            stamp.push_str(&format!("{}.{}.", since.as_nanos(), file.len()));
        }
        Some(stamp)
    }

    /// Marks a certificate as revoked. Devices only learn of it from the
    /// next CRL the CA signs.
    pub fn revoke(&mut self, serial: &str, now: OffsetDateTime) -> Result<&Record, Error> {
        let _held = self.hold()?;
        let serial = self.find(serial)?.serial.clone();
        let position = self
            .index
            .certificates
            .iter()
            .position(|record| record.serial == serial)
            .expect("find returned an entry of this register");
        if self.index.certificates[position].revoked_at.is_some() {
            return Err(Error::Store(format!(
                "certificate {serial} is already revoked"
            )));
        }
        if self
            .retired_issuer(&self.index.certificates[position])
            .is_some()
        {
            // Marking it would promise something no list can keep.
            return Err(Error::Store(format!(
                "certificate {serial} was signed by an issuing CA that has been replaced; \
                 with that CA's key gone, no revocation list can name it"
            )));
        }
        self.index.certificates[position].revoked_at = Some(whole_seconds(now));
        self.write_toml(INDEX_FILE, &self.index)?;
        Ok(&self.index.certificates[position])
    }

    /// Deletes a certificate from the register, and from the workspace
    /// the files yca put into its folder, a private key among them if
    /// there was one. A certificate that is installed somewhere is not
    /// affected: one that is still valid goes on working, and can no
    /// longer be revoked from here.
    ///
    /// A certificate that was revoked and has not expired leaves its
    /// revocation behind, so the revocation lists of its CA name it for
    /// as long as a device could otherwise accept it.
    pub fn delete(&mut self, serial: &str, now: OffsetDateTime) -> Result<Deleted, Error> {
        let _held = self.hold()?;
        let serial = self.find(serial)?.serial.clone();
        let position = self
            .index
            .certificates
            .iter()
            .position(|record| record.serial == serial)
            .expect("find returned an entry of this register");
        // The private key first, while the entry is still there to find
        // its folder by. If anything fails from here on, what is left is
        // public, and a key never lies about with no entry that leads to
        // it.
        let folder = self.folder_of(&self.index.certificates[position]);
        for name in KEY_FILES {
            remove_file(&folder.join(name))?;
            remove_file(&folder.join(temporary(name)))?;
        }
        let record = self.index.certificates.remove(position);

        // Revocations nobody needs any more go out on the same occasion.
        self.index.revocations.retain(|kept| now < kept.not_after);
        let kept = record
            .revoked_at
            .filter(|_| now < record.not_after)
            .map(|revoked_at| KeptRevocation {
                serial: record.serial.clone(),
                issued_by: record.issued_by,
                not_after: record.not_after,
                revoked_at,
                issuer_key_id: record.issuer_key_id.clone(),
            });
        let revocation_kept = kept.is_some();
        self.index.revocations.extend(kept);

        // Then the register, so it never points at a certificate that is
        // gone, and after it the certificate's files and the register's
        // own copy.
        self.write_toml(INDEX_FILE, &self.index)?;
        for name in CERTIFICATE_FILES {
            remove_file(&folder.join(name))?;
            remove_file(&folder.join(temporary(name)))?;
        }
        // Gone with its files, unless somebody put more in there, and the
        // folder of its group with it if this was the last.
        let _ = fs::remove_dir(&folder);
        if let Some(parent) = folder.parent()
            && parent != self.dir.join(CERTIFICATES_DIR)
        {
            remove_if_empty(parent);
        }
        remove_file(&self.register_copy(&record.serial))?;
        Ok(Deleted {
            record,
            revocation_kept,
        })
    }

    /// The certificates that belong on the next revocation list of a CA:
    /// those it issued that are revoked and have not expired yet,
    /// including those deleted from the register since. An expired
    /// certificate is refused anyway and need not be listed.
    ///
    /// After the issuing CA was replaced, the certificates of the old one
    /// are not listed: only the CA that issued a certificate may revoke
    /// it, and the old one's key is gone. The root CA's list names the
    /// replaced issuing CAs themselves, where they were revoked.
    pub fn revoked(&self, role: CaRole, now: OffsetDateTime) -> Vec<Revoked> {
        let current = self
            .ca_certificate_der(role)
            .ok()
            .and_then(|der| parse(&der).ok().and_then(|ca| key_identifier(&ca)));
        let in_register = self.index.certificates.iter().filter_map(|record| {
            Some((
                &record.serial,
                record.issued_by,
                record.not_after,
                record.revoked_at?,
                &record.issuer_key_id,
            ))
        });
        let deleted = self.index.revocations.iter().map(|kept| {
            (
                &kept.serial,
                kept.issued_by,
                kept.not_after,
                kept.revoked_at,
                &kept.issuer_key_id,
            )
        });
        in_register
            .chain(deleted)
            .filter(|(_, issued_by, not_after, ..)| *issued_by == role && now < *not_after)
            // Entries written before the identifier was recorded count as
            // the current CA's.
            .filter(|(.., issuer)| issuer.is_none() || **issuer == current)
            .map(|(serial, _, _, revoked_at, _)| Revoked {
                serial: serial.clone(),
                revoked_at,
            })
            .chain(
                self.meta
                    .retired
                    .iter()
                    .filter(|ca| role == CaRole::Root && now < ca.not_after)
                    .filter_map(|ca| {
                        Some(Revoked {
                            serial: ca.serial.clone(),
                            revoked_at: ca.revoked_at?,
                        })
                    }),
            )
            .collect()
    }

    /// How the revocation list a CA signed last stands against the
    /// register: whether there is one, how long devices treat it as
    /// current, and how many revoked certificates it does not name yet.
    pub fn crl_status(&self, role: CaRole, now: OffsetDateTime) -> Result<CrlStatus, Error> {
        let revoked = self.revoked(role, now);
        let none = CrlStatus {
            number: None,
            next_update: None,
            unlisted: revoked.len(),
        };
        let path = self.dir.join(crl_file(role));
        if !path.exists() {
            return Ok(none);
        }
        let der = read_pem(&path)?;
        let (_, list) = CertificateRevocationList::from_der(&der)
            .map_err(|e| Error::Store(format!("could not read {}: {e}", path.display())))?;
        // Only a list this CA signed is its list: one a replaced issuing CA
        // left behind is not.
        let ca_der = self.ca_certificate_der(role)?;
        if list.verify_signature(parse(&ca_der)?.public_key()).is_err() {
            return Ok(none);
        }
        let listed: Vec<String> = list
            .iter_revoked_certificates()
            .map(|entry| {
                entry
                    .raw_serial()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect()
            })
            .collect();
        Ok(CrlStatus {
            number: self.ca(role).map(|ca| ca.crl_number),
            next_update: list.next_update().map(|time| time.to_datetime()),
            unlisted: revoked
                .iter()
                .filter(|entry| !listed.contains(&entry.serial))
                .count(),
        })
    }

    /// The number the next revocation list of a CA has to carry.
    pub fn next_crl_number(&self, role: CaRole) -> Result<u64, Error> {
        let ca = self
            .ca(role)
            .ok_or_else(|| Error::Store(format!("this workspace has no {role} yet")))?;
        Ok(ca.crl_number + 1)
    }

    /// Keeps a freshly signed revocation list as the current one of its
    /// CA, in the two forms devices ask for: PEM (`<ca>.crl.pem`) and DER
    /// (`<ca>.crl`). Returns the folder they are in and their names.
    pub fn save_crl(
        &mut self,
        role: CaRole,
        list: &RevocationList,
    ) -> Result<(PathBuf, [String; 2]), Error> {
        let _held = self.hold()?;
        if list.number() != self.next_crl_number(role)? {
            return Err(Error::Store(format!(
                "revocation list number {} is out of sequence",
                list.number()
            )));
        }
        let dir = self.dir.join(CRL_DIR);
        fs::create_dir_all(&dir).map_err(|e| io_error(&dir, e))?;
        let pem = format!("{}.crl.pem", role_name(role));
        let der = format!("{}.crl", role_name(role));
        self.write_bytes(&format!("{CRL_DIR}/{der}"), list.der())?;
        self.write(&format!("{CRL_DIR}/{pem}"), &list.pem())?;

        let entry = match role {
            CaRole::Root => Some(&mut self.meta.root),
            CaRole::Issuing => self.meta.issuing.as_mut(),
        };
        entry.expect("next_crl_number found this CA").crl_number = list.number();
        self.write_toml(META_FILE, &self.meta)?;
        Ok((dir, [pem, der]))
    }

    fn write_toml(&self, name: &str, value: &impl Serialize) -> Result<(), Error> {
        let text = toml::to_string(value)
            .map_err(|e| Error::Store(format!("could not encode {name}: {e}")))?;
        self.write(name, &text)
    }

    /// Replaces a file in one step, so a crash never leaves half of one.
    fn write(&self, name: &str, contents: &str) -> Result<(), Error> {
        self.write_bytes(name, contents.as_bytes())
    }

    fn write_bytes(&self, name: &str, contents: &[u8]) -> Result<(), Error> {
        let path = self.dir.join(name);
        let temporary = self.dir.join(format!("{name}.tmp"));
        fs::write(&temporary, contents).map_err(|e| io_error(&temporary, e))?;
        fs::rename(&temporary, &path).map_err(|e| io_error(&path, e))
    }
}

/// Removes a file; one that is not there is as good as removed.
fn remove_file(path: &Path) -> Result<(), Error> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(path, error)),
    }
}

/// Whether a folder named in the register is where a certificate's folder
/// can be: one name below `certificates/`, or two for a certificate in a
/// group, and nothing that leads elsewhere.
fn plain_folder(folder: &str) -> bool {
    let names: Vec<&str> = folder.split('/').collect();
    names.len() <= 2
        && names
            .iter()
            .all(|name| !name.is_empty() && *name != "." && *name != ".." && !name.contains('\\'))
}

/// Removes a folder that has nothing left in it. What Finder leaves in
/// every folder it has shown does not count as something.
fn remove_if_empty(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    if entries
        .filter_map(Result::ok)
        .all(|entry| entry.file_name() == ".DS_Store")
    {
        let _ = fs::remove_file(dir.join(".DS_Store"));
        let _ = fs::remove_dir(dir);
    }
}

/// A name fit for a folder or a file: what a certificate or a CA is
/// called, with whatever a file system could take amiss replaced.
/// `fd00::1` and `*.example.com` are names of certificates too. Spaces
/// stay: "Home Root CA" should read as it was written.
fn folder_name(name: &str) -> String {
    let safe: String = name
        .trim()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || "-_.@ ".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    // A folder called "." or ".." would be somewhere else entirely, and
    // one that starts with a dot is hidden from its owner.
    match safe.trim_start_matches('.') {
        "" => "certificate".to_owned(),
        visible => visible.to_owned(),
    }
}

fn ca_entry(certificate: &X509Certificate<'_>, yubikey: u32) -> CaEntry {
    CaEntry {
        subject: certificate.subject().to_string(),
        yubikey,
        not_after: certificate.validity().not_after.to_datetime(),
        crl_number: 0,
    }
}

/// The subject key identifier of a certificate, in hexadecimal.
fn key_identifier(certificate: &X509Certificate<'_>) -> Option<String> {
    certificate
        .iter_extensions()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(identifier) => Some(
                identifier
                    .0
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
            ),
            _ => None,
        })
}

/// Bytes as pairs of capital hexadecimal digits with spaces between, the
/// way certificate fingerprints are shown.
fn spaced_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The serial number of a certificate, in lowercase hexadecimal.
fn serial_number(certificate: &X509Certificate<'_>) -> String {
    certificate
        .raw_serial()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn role_name(role: CaRole) -> &'static str {
    match role {
        CaRole::Root => "root",
        CaRole::Issuing => "issuing",
    }
}

fn ca_file(role: CaRole) -> String {
    format!("{}.pem", role_name(role))
}

fn crl_file(role: CaRole) -> String {
    format!("{CRL_DIR}/{}.crl.pem", role_name(role))
}

fn whole_seconds(moment: OffsetDateTime) -> OffsetDateTime {
    moment
        .replace_nanosecond(0)
        .expect("zero is a valid nanosecond")
}

fn parse(der: &[u8]) -> Result<X509Certificate<'_>, Error> {
    X509Certificate::from_der(der)
        .map(|(_, certificate)| certificate)
        .map_err(|e| Error::Parse(e.to_string()))
}

fn require_ca(certificate: &X509Certificate<'_>) -> Result<(), Error> {
    let is_ca = certificate
        .basic_constraints()
        .map_err(|e| Error::Parse(e.to_string()))?
        .is_some_and(|ext| ext.value.ca);
    if is_ca { Ok(()) } else { Err(Error::NotCa) }
}

fn read_toml<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, Error> {
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    toml::from_str(&text)
        .map_err(|e| Error::Store(format!("could not read {}: {e}", path.display())))
}

fn read_pem(path: &Path) -> Result<Vec<u8>, Error> {
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    pem::parse(text)
        .map(pem::Pem::into_contents)
        .map_err(|e| Error::Store(format!("could not read {}: {e}", path.display())))
}

/// Refuses a workspace laid out in a way this build does not know.
fn check_format(dir: &Path, version: u32) -> Result<(), Error> {
    if version == FORMAT_VERSION {
        return Ok(());
    }
    Err(Error::Store(format!(
        "{} was written by a newer version of yca (format {version}); use that version, or a \
         newer one, to work with it",
        dir.display()
    )))
}

fn io_error(path: &Path, error: std::io::Error) -> Error {
    Error::Store(format!("{}: {error}", path.display()))
}
