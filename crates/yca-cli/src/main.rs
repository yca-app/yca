//! `yca`: the command line over `yca-core`.
//!
//! Whatever the window can do, this can do too, for people who would
//! rather type, for scripts, and for AI agents: `--json` makes every
//! command answer with one JSON document, and `yca mcp` serves the same
//! things to a program that speaks the Model Context Protocol.

mod mcp;

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use time::{Duration, OffsetDateTime};
use yca_core::device::{self, CaRole, Device};
use yca_core::view;
use yca_core::{
    Authority, CaKeyType, CertificateFolder, Error, ExportFile, ExportForm, ExportSource,
    IssuedCertificate, KeyPair, LeafProfile, LeafRequest, NewCa, P12Encryption, P12Options,
    PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_RSA_SHA256, Record, Repack, RsaKeySize,
    SigningRequest, Status, Store, YubiKeySigner,
};
use zeroize::Zeroizing;

/// Whether the answer goes out as one JSON document. What is otherwise
/// said along the way then goes to standard error, so that standard output
/// holds the document and nothing else.
static JSON: AtomicBool = AtomicBool::new(false);
/// What a command has to say for itself in JSON, set as it gets there.
static RESULT: Mutex<Option<serde_json::Value>> = Mutex::new(None);

/// Says something to the person at the terminal.
macro_rules! say {
    ($($arg:tt)*) => {
        if crate::JSON.load(std::sync::atomic::Ordering::Relaxed) {
            eprintln!($($arg)*)
        } else {
            println!($($arg)*)
        }
    };
}

/// Keeps what a command answers with when it is asked for JSON.
fn answer(value: serde_json::Value) {
    *RESULT.lock().unwrap_or_else(|e| e.into_inner()) = Some(value);
}

/// The workspace as every client is shown it: what a command that changed
/// it answers with.
fn answer_with_workspace(store: &Store) -> Result<()> {
    answer(serde_json::to_value(view::workspace(store)?)?);
    Ok(())
}

/// What issuing a certificate answers with.
fn answer_with_certificate(
    issued: &IssuedCertificate,
    names: &[String],
    folder: Option<&Path>,
) -> Result<()> {
    answer(serde_json::json!({
        "serial": issued.serial()?,
        "names": names,
        "notAfter": view::timestamp(issued.not_after()),
        "folder": folder.map(|folder| folder.to_string_lossy()),
    }));
    Ok(())
}

#[derive(Parser)]
#[command(
    name = "yca",
    version,
    about = "CA for YubiKey: your own certificate authority, kept on YubiKeys"
)]
struct Cli {
    /// Answer with one JSON document on standard output, for scripts and
    /// agents. What is otherwise printed goes to standard error.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show connected YubiKeys. Reads only, changes nothing on the key.
    Devices,

    /// Issue a certificate, signed by the CA on a connected YubiKey.
    ///
    /// Asks for the PIN on the terminal and, if the key requires it, waits
    /// for a touch. Nothing is written to the YubiKey.
    Issue {
        /// What the certificate is for.
        #[arg(long, value_enum)]
        profile: Profile,

        /// Host name or IP address for a server or gateway (repeat for more
        /// names); a name or e-mail address for a client.
        #[arg(long = "name", required = true)]
        names: Vec<String>,

        /// Expire after this many days instead of as late as possible.
        #[arg(long)]
        days: Option<u32>,

        /// Sign with the root CA instead of the issuing CA. Only for a
        /// device that cannot handle a certificate chain. A workspace
        /// without an issuing CA signs with its root CA anyway.
        #[arg(long)]
        root: bool,

        /// Serial number of the YubiKey, if more than one fits.
        #[arg(long)]
        device: Option<u32>,

        /// Workspace folder to enter the certificate into. Its files then
        /// go into a folder of its own there. Without a workspace the
        /// certificate is issued but not kept track of.
        #[arg(long)]
        store: Option<PathBuf>,

        /// Group to sort the certificate into in the workspace, such as a
        /// customer or a site. A group that is not there yet is made.
        #[arg(long, requires = "store")]
        group: Option<String>,

        #[command(flatten)]
        export: ExportArgs,

        /// Key type of the new certificate.
        #[arg(long, value_enum, default_value_t = Algorithm::Rsa)]
        algorithm: Algorithm,
    },

    /// Start a workspace folder from the CAs on the connected YubiKeys, or add
    /// the issuing CA to an existing folder. Reads the YubiKeys only and
    /// needs no PIN.
    Adopt {
        /// The workspace folder.
        #[arg(long)]
        store: PathBuf,

        /// Serial number of the YubiKey with the root CA, if more than one
        /// root is connected.
        #[arg(long)]
        root_device: Option<u32>,

        /// Serial number of the YubiKey with the issuing CA, if more than
        /// one is connected.
        #[arg(long)]
        issuing_device: Option<u32>,
    },

    /// List the certificates in a workspace folder.
    List {
        /// The workspace folder.
        #[arg(long)]
        store: PathBuf,

        /// Show only the certificates of this group.
        #[arg(long)]
        group: Option<String>,
    },

    /// Sort certificates into a group, such as a customer or a site, or
    /// take them out of their group.
    ///
    /// A group is made by naming it and is gone once nothing is left in
    /// it. In the workspace, the folder of each certificate moves into the
    /// folder of its group.
    Group {
        /// The workspace folder.
        #[arg(long)]
        store: PathBuf,

        /// Serial number of a certificate, or its beginning; repeat for
        /// more than one.
        #[arg(long = "serial", required = true)]
        serials: Vec<String>,

        /// The group to put them into.
        #[arg(long, required_unless_present = "none", conflicts_with = "none")]
        name: Option<String>,

        /// Take them out of their group instead.
        #[arg(long)]
        none: bool,
    },

    /// Issue a new certificate for the key of an existing one, for example
    /// to change a host name. The private key stays on the device; only
    /// the new certificate has to be installed. Its folder gets the files
    /// in the form of the old one, key included; a key inside a .p12 file
    /// takes that file's password (or YCA_P12_OPENS), and the new file opens
    /// with the same one.
    Reissue {
        /// The workspace folder.
        #[arg(long)]
        store: PathBuf,

        /// Serial number of the certificate to replace, or its beginning.
        #[arg(long)]
        serial: String,

        /// New names. Without any, the names stay as they are.
        #[arg(long = "name")]
        names: Vec<String>,

        /// Expire after this many days instead of as late as possible.
        #[arg(long)]
        days: Option<u32>,

        /// Mark the old certificate as revoked.
        #[arg(long)]
        revoke_old: bool,

        /// Serial number of the YubiKey, if more than one fits.
        #[arg(long)]
        device: Option<u32>,
    },

    /// Mark a certificate as revoked in the workspace folder.
    Revoke {
        /// The workspace folder.
        #[arg(long)]
        store: PathBuf,

        /// Serial number of the certificate, or its beginning.
        #[arg(long)]
        serial: String,
    },

    /// Delete a certificate from the workspace folder: its entry in the
    /// list and its folder with the files, a private key included.
    ///
    /// A certificate that is installed somewhere is not affected: one that
    /// is still valid goes on working and can no longer be revoked from
    /// here. To stop a certificate from working, revoke it instead.
    Delete {
        /// The workspace folder.
        #[arg(long)]
        store: PathBuf,

        /// Serial number of the certificate, or its beginning.
        #[arg(long)]
        serial: String,
    },

    /// Have the root CA revoke an issuing CA that was replaced, for when
    /// its YubiKey turns out to be in someone else's hands. Needs no
    /// YubiKey; devices learn of it from the root CA's next revocation
    /// list (`yca crl --root`).
    RevokeCa {
        /// The workspace folder.
        #[arg(long)]
        store: PathBuf,

        /// Serial number of the replaced issuing CA's certificate, as
        /// `yca list --json` shows it. Not needed if only one was replaced.
        #[arg(long)]
        serial: Option<String>,
    },

    /// Show what a computer or phone needs in order to trust this CA: the
    /// root CA certificate as a file to install there, and its
    /// fingerprints to compare.
    Trust {
        /// The workspace folder.
        #[arg(long)]
        store: PathBuf,
    },

    /// Serve the workspace to an AI agent over the Model Context Protocol,
    /// on standard input and output. The agent reads and sorts by itself;
    /// whatever takes a PIN and a touch it hands to the app's window,
    /// where the person signs.
    Mcp,

    /// Sign a revocation list (CRL) naming every revoked certificate of
    /// one CA. This is the file a VPN gateway needs in order to refuse a
    /// revoked certificate.
    Crl {
        /// The workspace folder.
        #[arg(long)]
        store: PathBuf,

        /// Sign the root CA's list instead of the issuing CA's. The root
        /// lists the certificates it issued directly. A workspace without
        /// an issuing CA has only the root CA's list.
        #[arg(long)]
        root: bool,

        /// Serial number of the YubiKey, if more than one fits.
        #[arg(long)]
        device: Option<u32>,
    },

    /// Issue a certificate for a request (CSR) made by a device that keeps
    /// its own private key.
    SignCsr {
        /// The request file, PEM or DER.
        #[arg(long)]
        csr: PathBuf,

        /// What the certificate is for.
        #[arg(long, value_enum)]
        profile: Profile,

        /// Names to put in the certificate. Without any, the names the
        /// device asked for are used.
        #[arg(long = "name")]
        names: Vec<String>,

        /// Expire after this many days instead of as late as possible.
        #[arg(long)]
        days: Option<u32>,

        /// Sign with the root CA instead of the issuing CA. Only for a
        /// device that cannot handle a certificate chain. A workspace
        /// without an issuing CA signs with its root CA anyway.
        #[arg(long)]
        root: bool,

        /// Serial number of the YubiKey, if more than one fits.
        #[arg(long)]
        device: Option<u32>,

        /// Workspace folder to enter the certificate into. Its files then
        /// go into a folder of its own there.
        #[arg(long)]
        store: Option<PathBuf>,

        /// Group to sort the certificate into in the workspace, such as a
        /// customer or a site. A group that is not there yet is made.
        #[arg(long, requires = "store")]
        group: Option<String>,

        /// What the upload form of the device asks for; decides which
        /// files are written. There is no private key among them: it
        /// stays in the device.
        #[arg(long, value_enum, default_value_t = Files::Fullchain)]
        files: Files,

        /// Directory to write the files to when there is no workspace
        /// (default: out).
        #[arg(long, conflicts_with = "store")]
        out: Option<PathBuf>,
    },

    /// Write the files of a certificate again in another form, for a
    /// device whose upload form asks for something else than was chosen
    /// when it was issued. Nothing is issued and no YubiKey is needed.
    ///
    /// The certificate's folder ends up with the files of the new form
    /// and none of the old. Out of a .p12 file, the private key takes
    /// that file's password; into one, a new password.
    Repackage {
        /// The workspace folder.
        #[arg(long)]
        store: PathBuf,

        /// Serial number of the certificate, or its beginning.
        #[arg(long)]
        serial: String,

        /// What the upload form of the device asks for.
        #[arg(long, value_enum)]
        files: Files,

        /// Encryption of the .p12 file, for --files p12.
        #[arg(long, value_enum, default_value_t = P12::Modern)]
        p12: P12,
    },

    /// Ask a YubiKey to prove that its CA key was generated inside it.
    /// Reads only, needs no PIN.
    Attest {
        /// Serial number of the YubiKey.
        #[arg(long)]
        device: u32,
    },

    /// Replace the factory PIN, PUK and management key of a YubiKey with
    /// your own. WRITES TO THE YUBIKEY, but leaves keys and certificates
    /// alone: a CA that is already there keeps working with the new PIN.
    Protect {
        /// Serial number of the YubiKey.
        #[arg(long)]
        device: u32,
    },

    /// Change the PIN of a YubiKey. WRITES TO THE YUBIKEY, but only the
    /// PIN: the CA on it keeps working, with the new one.
    Pin {
        /// Serial number of the YubiKey.
        #[arg(long)]
        device: u32,
    },

    /// Set a new PIN with the PUK, for a PIN that is forgotten or locked.
    /// WRITES TO THE YUBIKEY, but only the PIN.
    Unblock {
        /// Serial number of the YubiKey.
        #[arg(long)]
        device: u32,
    },

    /// Reset the PIV application of a YubiKey to its factory state.
    /// DESTROYS every PIV key and certificate on it, the CA included.
    ///
    /// For a YubiKey whose PIN and PUK are both lost, or to start over.
    /// Needs neither PIN nor PUK. Afterwards the PIN is 123456 and the PUK
    /// 12345678 again. FIDO2, OATH and OpenPGP on the same YubiKey are not
    /// touched.
    Reset {
        /// Serial number of the YubiKey to wipe. Always required.
        #[arg(long)]
        device: u32,
    },

    /// Create a new root CA on a YubiKey. WRITES TO THE YUBIKEY.
    ///
    /// Generates the CA key inside the YubiKey, signs the root certificate
    /// with it and stores the certificate next to the key. A YubiKey that
    /// already holds something in slot 9c is left alone unless --replace is
    /// given and confirmed.
    InitRoot {
        /// Name of the new root CA.
        #[arg(long)]
        name: String,

        /// Serial number of the YubiKey to write to. Always required, so a
        /// key is never picked by accident.
        #[arg(long)]
        device: u32,

        /// Type of the CA key.
        #[arg(long, value_enum, default_value_t = CaKey::P384)]
        key: CaKey,

        /// Destroy what slot 9c holds now and put the new CA there.
        #[arg(long)]
        replace: bool,

        /// Directory to write the root certificate and the attestation to.
        #[arg(long, default_value = "out")]
        out: PathBuf,
    },

    /// Create the issuing CA on a second YubiKey, signed by the root CA.
    /// WRITES TO THE YUBIKEY named by --device.
    ///
    /// Both YubiKeys have to be connected: the key is generated inside the
    /// new one and the root signs its certificate. Also how a lost issuing
    /// CA is replaced; devices keep trusting the same root.
    InitIssuing {
        /// Name of the new issuing CA.
        #[arg(long)]
        name: String,

        /// Serial number of the YubiKey to write to. Always required.
        #[arg(long)]
        device: u32,

        /// Serial number of the YubiKey with the root CA, if more than one
        /// root is connected.
        #[arg(long)]
        root_device: Option<u32>,

        /// Type of the CA key.
        #[arg(long, value_enum, default_value_t = CaKey::P384)]
        key: CaKey,

        /// Destroy what slot 9c holds now and put the new CA there.
        #[arg(long)]
        replace: bool,

        /// Workspace folder to enter the new issuing CA into.
        #[arg(long)]
        store: Option<PathBuf>,

        /// Have the root CA revoke the issuing CA this one replaces, for
        /// when its YubiKey was stolen rather than lost or broken. Devices
        /// that check the root CA's revocation list then refuse every
        /// certificate the old issuing CA signed.
        #[arg(long, requires = "store")]
        revoke_old: bool,

        /// For testing with a single YubiKey: sign with a root that is
        /// made in memory and thrown away, instead of a root on a second
        /// YubiKey. The resulting CA is of no real use.
        #[arg(long, hide = true, conflicts_with_all = ["root_device", "store"])]
        throwaway_root: bool,

        /// Directory to write the certificate and the attestation to.
        #[arg(long, default_value = "out")]
        out: PathBuf,
    },

    /// Build a throwaway CA with in-memory keys and issue one TLS server
    /// certificate. The CA keys are never written anywhere, so this CA
    /// cannot issue anything again. For trying out the output only.
    Demo {
        /// Host name or IP address of the server; repeat for more names.
        #[arg(long = "host", required = true)]
        hosts: Vec<String>,

        #[command(flatten)]
        export: ExportArgs,

        /// Key type for the CAs and the server certificate.
        #[arg(long, value_enum, default_value_t = Algorithm::Rsa)]
        algorithm: Algorithm,
    },
}

/// Which files the issued certificate is written as, and where.
#[derive(clap::Args)]
struct ExportArgs {
    /// What the upload form of the device asks for; decides which files
    /// are written.
    #[arg(long, value_enum, default_value_t = Files::Fullchain)]
    files: Files,

    /// Encryption of the .p12 file, for --files p12.
    #[arg(long, value_enum, default_value_t = P12::Modern)]
    p12: P12,

    /// Directory to write the files to when there is no workspace to keep
    /// them (default: out).
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Files {
    /// fullchain.crt (the certificate followed by the intermediate CA)
    /// and private-key.key. For a form with a field for the certificate
    /// and one for the private key.
    Fullchain,
    /// certificate.crt, intermediate-ca.crt and private-key.key. For a
    /// form with a field for each.
    Separate,
    /// certificate.p12: everything in one file that opens with a
    /// password. For a form with one file and a password, and for laptops
    /// and phones.
    P12,
}

impl From<Files> for ExportForm {
    fn from(files: Files) -> Self {
        match files {
            Files::Fullchain => ExportForm::Fullchain,
            Files::Separate => ExportForm::Separate,
            Files::P12 => ExportForm::Pkcs12,
        }
    }
}

impl From<P12> for P12Encryption {
    fn from(p12: P12) -> Self {
        match p12 {
            P12::Modern => P12Encryption::Modern,
            P12::Compatible => P12Encryption::Compatible,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum P12 {
    /// AES-256 with SHA-256
    Modern,
    /// Triple DES with SHA-1, for older systems
    Compatible,
}

#[derive(Clone, Copy, ValueEnum)]
enum Profile {
    TlsServer,
    TlsClient,
    IpsecGateway,
    IpsecClient,
}

impl Profile {
    fn request(self, names: &[String]) -> Result<LeafRequest> {
        let single = || match names {
            [name] => Ok(name.as_str()),
            _ => bail!("a client certificate takes exactly one --name"),
        };
        Ok(match self {
            Profile::TlsServer => LeafRequest::tls_server(names)?,
            Profile::IpsecGateway => LeafRequest::ipsec_gateway(names)?,
            Profile::TlsClient => LeafRequest::tls_client(single()?)?,
            Profile::IpsecClient => LeafRequest::ipsec_client(single()?)?,
        })
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum CaKey {
    /// ECC P-384
    P384,
    /// ECC P-256
    P256,
}

#[derive(Clone, Copy, ValueEnum)]
enum Algorithm {
    /// RSA 2048 with SHA-256
    Rsa,
    /// ECDSA P-256 with SHA-256
    Ecdsa,
}

impl Algorithm {
    fn generate(self) -> Result<KeyPair> {
        let key = match self {
            Algorithm::Rsa => KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048),
            Algorithm::Ecdsa => KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256),
        };
        key.context("could not generate a key")
    }
}

fn main() {
    let cli = Cli::parse();
    let json = cli.json;
    JSON.store(json, Ordering::Relaxed);
    let done = run(cli.command);
    if !json {
        if let Err(error) = done {
            eprintln!("Error: {error:#}");
            std::process::exit(1);
        }
        return;
    }
    // One document, whatever happened: what the command answers with, a
    // plain yes if it has nothing to add, or what went wrong.
    match done {
        Ok(()) => {
            let said = RESULT.lock().unwrap_or_else(|e| e.into_inner()).take();
            println!(
                "{}",
                said.unwrap_or_else(|| serde_json::json!({ "ok": true }))
            );
        }
        Err(error) => {
            println!("{}", serde_json::json!({ "error": format!("{error:#}") }));
            std::process::exit(1);
        }
    }
}

fn run(command: Command) -> Result<()> {
    match command {
        Command::Mcp => mcp::serve(),
        Command::Trust { store } => trust(&store),
        Command::RevokeCa { store, serial } => revoke_ca(&store, serial.as_deref()),
        Command::Devices => devices(),
        Command::Issue {
            profile,
            names,
            days,
            root,
            device,
            store,
            group,
            export,
            algorithm,
        } => issue(
            profile,
            &names,
            days,
            root,
            device,
            store.as_deref(),
            group.as_deref(),
            &export,
            algorithm,
        ),
        Command::Adopt {
            store,
            root_device,
            issuing_device,
        } => adopt(&store, root_device, issuing_device),
        Command::List { store, group } => list(&store, group.as_deref()),
        Command::Group {
            store,
            serials,
            name,
            none: _,
        } => group(&store, &serials, name.as_deref()),
        Command::Reissue {
            store,
            serial,
            names,
            days,
            revoke_old,
            device,
        } => reissue(&store, &serial, names, days, revoke_old, device),
        Command::Revoke { store, serial } => revoke(&store, &serial),
        Command::Delete { store, serial } => delete(&store, &serial),
        Command::Crl {
            store,
            root,
            device,
        } => crl(&store, root, device),
        Command::SignCsr {
            csr,
            profile,
            names,
            days,
            root,
            device,
            store,
            group,
            files,
            out,
        } => sign_csr(
            &csr,
            profile,
            names,
            days,
            root,
            device,
            store.as_deref(),
            group.as_deref(),
            files,
            out.as_deref(),
        ),
        Command::Repackage {
            store,
            serial,
            files,
            p12,
        } => repackage(&store, &serial, files, p12),
        Command::Attest { device } => attest(device),
        Command::Protect { device } => protect(device),
        Command::Pin { device } => change_pin(device),
        Command::Unblock { device } => unblock(device),
        Command::Reset { device } => reset(device),
        Command::InitRoot {
            name,
            device,
            key,
            replace,
            out,
        } => init_root(&name, device, key, replace, &out),
        Command::InitIssuing {
            name,
            device,
            key,
            replace,
            throwaway_root: true,
            out,
            ..
        } => init_issuing_under_throwaway_root(&name, device, key, replace, &out),
        Command::InitIssuing {
            name,
            device,
            root_device,
            key,
            replace,
            store,
            revoke_old,
            throwaway_root: false,
            out,
        } => init_issuing(
            &name,
            device,
            root_device,
            key,
            replace,
            store.as_deref().map(|dir| EnterInto { dir, revoke_old }),
            &out,
        ),
        Command::Demo {
            hosts,
            export,
            algorithm,
        } => demo(&hosts, &export, algorithm),
    }
}

fn devices() -> Result<()> {
    let found = device::list_devices()?;
    if JSON.load(Ordering::Relaxed) {
        answer(serde_json::to_value(view::devices(found, None))?);
        return Ok(());
    }
    if found.usable.is_empty() && found.unusable.is_empty() {
        say!("No YubiKey connected.");
        return Ok(());
    }

    for key in &found.usable {
        let (major, minor, patch) = key.firmware;
        say!("YubiKey {}", key.serial);
        say!("  firmware:      {major}.{minor}.{patch}");
        say!("  reader:        {}", key.reader);
        say!("  PIN attempts:  {} left", key.pin_attempts_left);
        if key.factory.any() {
            let still_factory: Vec<_> = [
                (key.factory.pin, "PIN"),
                (key.factory.puk, "PUK"),
                (key.factory.management_key, "management key"),
            ]
            .into_iter()
            .filter(|(factory, _)| *factory == Some(true))
            .map(|(_, name)| name)
            .collect();
            say!(
                "  WARNING:       factory {} still in place; run `yca protect --device {}`",
                still_factory.join(", "),
                key.serial
            );
        }
        match &key.ca {
            Some(ca) => {
                say!("  holds:         {} \"{}\"", ca.role, ca.subject);
                say!("  CA valid to:   {}", ca.not_after.date());
                match &ca.key {
                    Some(info) => {
                        let origin = match info.generated_on_device {
                            Some(true) => "generated inside the YubiKey",
                            Some(false) => "imported from outside",
                            None => "origin unknown",
                        };
                        say!("  CA key:        {}, {origin}", info.algorithm);
                        say!(
                            "  to sign:       {}{}",
                            if info.pin_for_every_signature {
                                "PIN every time"
                            } else {
                                "PIN once"
                            },
                            if info.touch_required {
                                " and a touch"
                            } else {
                                ""
                            }
                        );
                    }
                    None => say!("  CA key:        firmware too old to describe it"),
                }
                if ca
                    .key
                    .as_ref()
                    .is_some_and(|info| !info.matches_certificate)
                {
                    say!("  WARNING: the key in slot 9c is not the key of this certificate");
                }
            }
            None => say!("  holds:         no CA"),
        }
        let other: Vec<_> = key
            .occupied_slots
            .iter()
            .filter(|slot| !slot.is_signature_slot)
            .map(|slot| slot.slot.as_str())
            .collect();
        if !other.is_empty() {
            say!("  other slots:   {}", other.join(", "));
        }
        if key.ca.is_none() && key.signature_slot_in_use() {
            say!("  note: slot 9c holds a certificate that is not a CA");
        }
    }
    for reader in &found.unusable {
        say!("{}: not usable ({})", reader.reader, reader.reason);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn issue(
    profile: Profile,
    names: &[String],
    days: Option<u32>,
    root: bool,
    serial: Option<u32>,
    store: Option<&Path>,
    group: Option<&str>,
    export_args: &ExportArgs,
    algorithm: Algorithm,
) -> Result<()> {
    let mut request = profile.request(names)?;
    if let Some(days) = days {
        request = request.valid_for(Duration::days(days.into()))?;
    }
    let mut store = store.map(Store::open).transpose()?;
    let role = signing_role(root, store.as_ref());

    // Everything that can go wrong with the files is settled before the
    // YubiKey signs, so a certificate is never issued and then lost.
    let password = match export_args.files {
        Files::P12 => Some(p12_password()?),
        Files::Fullchain | Files::Separate => None,
    };
    let folder = folder_in(store.as_ref(), export_args.out.as_deref(), &names[0], group)?;

    let authority = open_ca(role, serial, store.as_ref())?;
    let key = algorithm.generate()?;
    let now = OffsetDateTime::now_utc();
    let issued = sign(&authority, |ca| ca.issue(&request, &key, now))?;
    if let (Some(store), Some(folder)) = (&mut store, &folder) {
        store.record_in(folder, &issued, &request, role, None, now)?;
    }
    answer_with_certificate(&issued, names, folder.as_ref().map(|folder| folder.path()))?;

    write_bundle(
        export_args,
        &target(folder.as_ref(), export_args.out.as_deref()),
        &issued,
        &key,
        &names[0],
        password.as_ref().map(|password| password.as_str()),
    )?;
    say!();
    say!("Certificate for {}", names.join(", "));
    say!("Valid until {}", issued.not_after().date());
    if let Some(store) = &store {
        say!(
            "Entered into {} as {}",
            store.dir().display(),
            short(&issued.serial()?)
        );
    }
    Ok(())
}

/// Finds the YubiKey holding the CA of the wanted role, asks for its PIN
/// and opens the CA. With a workspace folder, the CA on the YubiKey must be the
/// one the folder knows.
fn open_ca(
    role: CaRole,
    serial: Option<u32>,
    store: Option<&Store>,
) -> Result<Authority<YubiKeySigner>> {
    let found = device::list_devices()?;
    let device = found.select_ca(role, serial)?;
    let ca = device
        .ca
        .as_ref()
        .expect("select_ca returns a key with a CA");
    say!(
        "Signing with YubiKey {}: {} \"{}\"",
        device.serial,
        ca.role,
        ca.subject
    );
    if device.factory.pin == Some(true) {
        say!(
            "WARNING: this YubiKey still has its factory PIN, which everybody knows. \
             Run `yca protect --device {}`.",
            device.serial
        );
    }
    let connected = found.usable.len();
    let root_also_connected = found.usable.iter().any(|other| {
        other.serial != device.serial && other.ca.as_ref().is_some_and(|ca| ca.role == CaRole::Root)
    });
    if root_also_connected {
        say!(
            "Note: the YubiKey with the root CA is connected too. It is not needed for this \
             and is safer unplugged."
        );
    }

    if ca
        .key
        .as_ref()
        .is_some_and(|info| !info.matches_certificate)
    {
        bail!("the key in slot 9c of this YubiKey is not the key of the CA certificate next to it");
    }

    if let Some(store) = store
        && store.ca_certificate_der(role)? != ca.certificate_der
    {
        bail!(
            "YubiKey {} holds a different {role} than the workspace folder {}",
            device.serial,
            store.dir().display()
        );
    }

    let pin = prompt_pin(device)?;
    let authority = Authority::open_on_yubikey(device.serial, &pin)?;
    drop(pin);

    if authority.key().touch_required() {
        announce_touch(connected, device.serial);
    }
    Ok(authority)
}

/// Runs one signing operation and, if the YubiKey refused, reports why.
/// The signing interface itself only says that the key refused; the signer
/// remembers the reason.
fn sign<T>(
    authority: &Authority<YubiKeySigner>,
    operation: impl FnOnce(&Authority<YubiKeySigner>) -> Result<T, Error>,
) -> Result<T> {
    operation(authority).map_err(|e| authority.key().take_last_error().unwrap_or(e).into())
}

fn adopt(dir: &Path, root_device: Option<u32>, issuing_device: Option<u32>) -> Result<()> {
    let found = device::list_devices()?;

    let mut store = if Store::exists(dir) {
        say!("Workspace folder {} already exists.", dir.display());
        Store::open(dir)?
    } else {
        let device = found
            .select_ca(CaRole::Root, root_device)
            .context("starting a workspace folder needs the YubiKey with the root CA connected")?;
        let ca = device
            .ca
            .as_ref()
            .expect("select_ca returns a key with a CA");
        let store = Store::create(dir, &ca.certificate_der, device.serial)?;
        say!("Started workspace folder {}.", dir.display());
        say!(
            "  root CA:     \"{}\" on YubiKey {}",
            ca.subject,
            device.serial
        );
        keep_attestation(&store, CaRole::Root, device.serial)?;
        store
    };

    match found.select_ca(CaRole::Issuing, issuing_device) {
        Ok(device) => {
            let ca = device
                .ca
                .as_ref()
                .expect("select_ca returns a key with a CA");
            let known = store
                .ca(CaRole::Issuing)
                .is_some_and(|entry| entry.yubikey == device.serial)
                && store.ca_certificate_der(CaRole::Issuing)? == ca.certificate_der;
            if known {
                say!("  issuing CA:  \"{}\" is already in the folder", ca.subject);
            } else {
                store.set_issuing(&ca.certificate_der, device.serial)?;
                say!(
                    "  issuing CA:  \"{}\" on YubiKey {}",
                    ca.subject,
                    device.serial
                );
                keep_attestation(&store, CaRole::Issuing, device.serial)?;
            }
        }
        Err(e) if issuing_device.is_some() => return Err(e.into()),
        Err(_) if store.ca(CaRole::Issuing).is_some() => {}
        Err(_) => {
            say!("  issuing CA:  none yet; connect its YubiKey and run adopt again to add it")
        }
    }
    answer_with_workspace(&store)
}

fn keep_attestation(store: &Store, role: CaRole, serial: u32) -> Result<()> {
    match yca_core::attest_ca_on_yubikey(serial)? {
        Some(attestation) => {
            store.save_attestation(role, &attestation)?;
            say!("               its key was generated inside the YubiKey (attestation kept)");
        }
        None => say!("               this firmware cannot attest where the key was generated"),
    }
    Ok(())
}

fn list(dir: &Path, group: Option<&str>) -> Result<()> {
    let store = Store::open(dir)?;
    answer_with_workspace(&store)?;
    for role in [CaRole::Root, CaRole::Issuing] {
        if let Some(ca) = store.ca(role) {
            say!(
                "{role}: \"{}\" on YubiKey {}, valid until {}",
                ca.subject,
                ca.yubikey,
                ca.not_after.date()
            );
        }
    }
    for ca in store.retired() {
        say!(
            "replaced issuing CA: \"{}\", valid until {}{}",
            ca.subject,
            ca.not_after.date(),
            match ca.revoked_at {
                Some(at) => format!(", revoked on {}", at.date()),
                None => String::new(),
            }
        );
    }
    say!();
    if store.records().is_empty() {
        say!("No certificates issued yet.");
        return Ok(());
    }

    // One group alone, if one was asked for, in whatever case it was typed.
    let only = match group {
        Some(name) => match store.group_name(name)? {
            Some(name) if store.groups().contains(&name) => Some(name),
            _ => {
                say!("No certificates in a group called \"{}\".", name.trim());
                return Ok(());
            }
        },
        None => None,
    };
    let groups = store.groups();
    // The column is only there for a workspace that has groups.
    let group_width = match (&only, groups.is_empty()) {
        (None, false) => {
            let longest = groups.iter().map(|group| group.chars().count()).max();
            longest.unwrap_or(0).max("GROUP".len()) + 2
        }
        _ => 0,
    };

    let now = OffsetDateTime::now_utc();
    say!(
        "{:<14}{:<14}{:<12}{:<15}{:<9}{:<group_width$}NAMES",
        "SERIAL",
        "STATUS",
        "EXPIRES",
        "PROFILE",
        "SIGNED",
        if group_width > 0 { "GROUP" } else { "" }
    );
    for record in store.records() {
        if only.is_some() && record.group != only {
            continue;
        }
        say!(
            "{:<14}{:<14}{:<12}{:<15}{:<9}{:<group_width$}{}{}",
            short(&record.serial),
            status_name(record.status(now)),
            record.not_after.date().to_string(),
            profile_name(record.profile),
            match record.issued_by {
                CaRole::Root => "root",
                CaRole::Issuing if store.retired_issuer(record).is_some() => "replaced",
                CaRole::Issuing => "issuing",
            },
            match (&record.group, group_width) {
                (_, 0) => "",
                (Some(group), _) => group.as_str(),
                (None, _) => "-",
            },
            record.names.join(", "),
            match &record.replaces {
                Some(old) => format!("  (replaces {})", short(old)),
                None => String::new(),
            }
        );
    }
    Ok(())
}

fn reissue(
    dir: &Path,
    serial: &str,
    names: Vec<String>,
    days: Option<u32>,
    revoke_old: bool,
    device: Option<u32>,
) -> Result<()> {
    let mut store = Store::open(dir)?;
    let old: Record = store.find(serial)?.clone();
    let previous = store.certificate_der(&old)?;
    let names = if names.is_empty() {
        old.names.clone()
    } else {
        names
    };
    let mut request = LeafRequest::for_profile(old.profile, &names)?;
    if let Some(days) = days {
        request = request.valid_for(Duration::days(days.into()))?;
    }
    say!(
        "Reissuing {} ({}) for the same key as: {}",
        short(&old.serial),
        old.names.join(", "),
        names.join(", ")
    );

    // The key, out of the password-protected file if it is in one, before
    // the YubiKey signs: a wrong password then costs nothing.
    let opens = match store.form(&old) {
        Some(ExportForm::Pkcs12) if store.has_key(&old) => Some(p12_opens()?),
        _ => None,
    };
    let renewal = store.renewal(&old, opens.as_ref().map(|password| password.as_str()))?;
    // The new certificate stays in the group of the one it replaces.
    let folder = store.new_certificate_folder(&names[0], old.group.as_deref())?;

    // The CA that signed the old certificate signs the new one.
    let authority = open_ca(old.issued_by, device, Some(&store))?;
    let now = OffsetDateTime::now_utc();
    let issued = sign(&authority, |ca| ca.reissue(&request, &previous, now))?;
    store.record_in(
        &folder,
        &issued,
        &request,
        old.issued_by,
        Some(&old.serial),
        now,
    )?;
    answer_with_certificate(&issued, &names, Some(folder.path()))?;
    // A certificate of a replaced issuing CA cannot be revoked on its own.
    let revoke_old = revoke_old && store.retired_issuer(&old).is_none();
    if revoke_old {
        store.revoke(&old.serial, now)?;
    }

    // The files come in the form the old ones are in, with the same key:
    // the folder of the new certificate is complete on its own.
    Target::Folder(&folder).write_all(&renewal.files(&issued, &names[0])?)?;
    say!();
    say!("The private key did not change; install only the new certificate.");
    say!("Valid until {}", issued.not_after().date());
    if revoke_old {
        say!(
            "The old certificate {} is marked as revoked.",
            short(&old.serial)
        );
    } else if old.revoked_at.is_none() {
        say!(
            "The old certificate {} stays valid until {} unless you revoke it.",
            short(&old.serial),
            old.not_after.date()
        );
    }
    Ok(())
}

fn group(dir: &Path, serials: &[String], name: Option<&str>) -> Result<()> {
    let mut store = Store::open(dir)?;
    let name = match name {
        Some(name) => match store.group_name(name)? {
            Some(name) => Some(name),
            None => {
                bail!("a group needs a name; to take certificates out of their group, pass --none")
            }
        },
        None => None,
    };
    // Every serial number is looked up before anything moves, so a
    // mistyped one does not leave the job half done.
    let mut found = Vec::new();
    for serial in serials {
        found.push(store.find(serial)?.serial.clone());
    }
    for serial in &found {
        let record = store.set_group(serial, name.as_deref())?;
        say!(
            "{}  {}  ->  {}",
            short(&record.serial),
            record.names.join(", "),
            match &record.group {
                Some(group) => format!("group \"{group}\""),
                None => "no group".to_owned(),
            }
        );
        let record = record.clone();
        if let Some(folder) = store.certificate_location(&record) {
            say!("              its files are in {}", folder.display());
        }
    }
    answer_with_workspace(&store)
}

fn revoke_ca(dir: &Path, serial: Option<&str>) -> Result<()> {
    let mut store = Store::open(dir)?;
    let serial = match serial {
        Some(serial) => serial.trim().to_ascii_lowercase().replace(':', ""),
        None => {
            let mut standing = store.retired().iter().filter(|ca| ca.revoked_at.is_none());
            match (standing.next(), standing.next()) {
                (Some(ca), None) => ca.serial.clone(),
                (None, _) => bail!("this workspace has no replaced issuing CA left to revoke"),
                (Some(_), Some(_)) => bail!(
                    "more than one issuing CA was replaced; say which with --serial \
                     (`yca list --json` shows them)"
                ),
            }
        }
    };
    let ca = store.revoke_retired(&serial, OffsetDateTime::now_utc())?;
    say!(
        "Marked the replaced issuing CA \"{}\" as revoked.",
        ca.subject
    );
    say!(
        "Devices learn of it from the root CA's revocation list: run `yca crl --root` and \
         install the result on the devices that check certificates."
    );
    answer_with_workspace(&store)
}

fn trust(dir: &Path) -> Result<()> {
    let store = Store::open(dir)?;
    let file = store.root_for_devices()?;
    let prints = store.ca_fingerprints(CaRole::Root)?;
    say!("To make a computer or phone trust this CA, install this file on it as a trusted");
    say!("root certificate:");
    say!();
    say!("  {}", file.display());
    say!();
    say!("It is the root CA certificate and not a secret. If the device shows a");
    say!("fingerprint when it asks, it should be one of these:");
    say!();
    say!("  SHA-256  {}", prints.sha256);
    say!("  SHA-1    {}", prints.sha1);
    say!();
    say!("The app has the steps for macOS, Windows, iPhone and Android, in the menu of");
    say!("the root CA.");
    answer(serde_json::json!({
        "file": file.to_string_lossy(),
        "sha256": prints.sha256,
        "sha1": prints.sha1,
    }));
    Ok(())
}

fn revoke(dir: &Path, serial: &str) -> Result<()> {
    let mut store = Store::open(dir)?;
    let record = store.revoke(serial, OffsetDateTime::now_utc())?.clone();
    answer_with_workspace(&store)?;
    say!(
        "Marked {} ({}) as revoked.",
        short(&record.serial),
        record.names.join(", ")
    );
    say!(
        "Devices only learn of it from a revocation list: run `yca crl{}` and install the \
         result on the devices that check certificates.",
        match record.issued_by {
            CaRole::Root => " --root",
            CaRole::Issuing => "",
        }
    );
    Ok(())
}

fn delete(dir: &Path, serial: &str) -> Result<()> {
    let mut store = Store::open(dir)?;
    let now = OffsetDateTime::now_utc();
    let deleted = store.delete(serial, now)?;
    answer_with_workspace(&store)?;
    let record = &deleted.record;
    say!(
        "Deleted {} ({}) from the list, with its files in the workspace.",
        short(&record.serial),
        record.names.join(", ")
    );
    if deleted.revocation_kept {
        say!(
            "It stays on the revocation list until it would have expired on {}.",
            record.not_after.date()
        );
    } else if record.revoked_at.is_none() && now < record.not_after {
        say!(
            "The certificate itself goes on working until {} and can no longer be revoked \
             from here.",
            record.not_after.date()
        );
    }
    Ok(())
}

/// Which CA signs: the root when asked for, and otherwise the one the
/// workspace signs with from day to day, which is the root too where the
/// whole authority is kept on one YubiKey.
fn signing_role(root: bool, store: Option<&Store>) -> CaRole {
    match store {
        _ if root => CaRole::Root,
        Some(store) => store.everyday_ca(),
        None => CaRole::Issuing,
    }
}

fn crl(dir: &Path, root: bool, device: Option<u32>) -> Result<()> {
    let mut store = Store::open(dir)?;
    let role = signing_role(root, Some(&store));
    let now = OffsetDateTime::now_utc();
    let revoked = store.revoked(role, now);
    let number = store.next_crl_number(role)?;
    say!(
        "Revocation list number {number} of the {role}: {} certificate(s).",
        revoked.len()
    );

    let authority = open_ca(role, device, Some(&store))?;
    let list = sign(&authority, |ca| ca.revocation_list(&revoked, number, now))?;
    let (folder, [pem, der]) = store.save_crl(role, &list)?;
    answer(serde_json::json!({
        "number": number,
        "nextUpdate": view::timestamp(list.next_update()),
        "revokedCertificates": revoked.len(),
        "folder": folder.to_string_lossy(),
        "files": [pem, der],
    }));

    say!();
    say!("Wrote to {}:", folder.display());
    say!("  {pem}  the revocation list in PEM form");
    say!("  {der}      the same in DER form, for devices that want that");
    say!();
    say!(
        "Devices treat it as current until {}; sign a new one before then.",
        list.next_update().date()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn sign_csr(
    csr: &Path,
    profile: Profile,
    names: Vec<String>,
    days: Option<u32>,
    root: bool,
    device: Option<u32>,
    store: Option<&Path>,
    group: Option<&str>,
    files: Files,
    out: Option<&Path>,
) -> Result<()> {
    // The device has its key and gives it to nobody, so there is nothing
    // to be the key in a file that holds everything.
    if files == Files::P12 {
        bail!(
            "a .p12 file holds the private key, which stays in the device that made the \
             request; choose --files fullchain or --files separate"
        );
    }
    let bytes = fs::read(csr).with_context(|| format!("could not read {}", csr.display()))?;
    let signing_request = SigningRequest::parse(&bytes)?;
    let names = if names.is_empty() {
        signing_request.names().to_vec()
    } else {
        names
    };
    if names.is_empty() {
        bail!("the request names nothing; say what the certificate is for with --name");
    }
    say!("Request for: {}", names.join(", "));
    let mut request = profile.request(&names)?;
    if let Some(days) = days {
        request = request.valid_for(Duration::days(days.into()))?;
    }
    let mut store = store.map(Store::open).transpose()?;
    let role = signing_role(root, store.as_ref());
    let folder = folder_in(store.as_ref(), out, &names[0], group)?;

    let authority = open_ca(role, device, store.as_ref())?;
    let now = OffsetDateTime::now_utc();
    let issued = sign(&authority, |ca| {
        ca.sign_request(&request, &signing_request, now)
    })?;
    if let (Some(store), Some(folder)) = (&mut store, &folder) {
        store.record_in(folder, &issued, &request, role, None, now)?;
    }
    answer_with_certificate(&issued, &names, folder.as_ref().map(|folder| folder.path()))?;

    target(folder.as_ref(), out).write_all(&yca_core::export(
        files.into(),
        ExportSource {
            issued: &issued,
            private_key_der: None,
        },
        None,
    )?)?;
    say!();
    say!("The private key never left the device; install the certificate there.");
    say!("Valid until {}", issued.not_after().date());
    if let Some(store) = &store {
        say!(
            "Entered into {} as {}",
            store.dir().display(),
            short(&issued.serial()?)
        );
    }
    Ok(())
}

/// The beginning of a serial number, enough to tell certificates apart.
fn short(serial: &str) -> &str {
    &serial[..serial.len().min(12)]
}

fn status_name(status: Status) -> &'static str {
    match status {
        Status::Valid => "valid",
        Status::ExpiresSoon => "expires soon",
        Status::Expired => "expired",
        Status::Revoked => "revoked",
    }
}

fn profile_name(profile: LeafProfile) -> &'static str {
    match profile {
        LeafProfile::TlsServer => "tls-server",
        LeafProfile::TlsClient => "tls-client",
        LeafProfile::IpsecGateway => "ipsec-gateway",
        LeafProfile::IpsecClient => "ipsec-client",
    }
}

fn init_root(name: &str, serial: u32, key: CaKey, replace: bool, out: &Path) -> Result<()> {
    let found = device::list_devices()?;
    let device = target_for_new_ca(&found, serial, "a root CA", replace)?;
    let pin = pin_for_new_ca(device)?;
    say!("Generating the key inside the YubiKey...");
    announce_touch(found.usable.len(), serial);
    let created = Authority::create_root_on_yubikey(
        serial,
        &pin,
        &new_ca(name, key, replace),
        OffsetDateTime::now_utc(),
    );
    drop(pin);
    let (root, attestation) = created.map_err(|e| explain_setup_error(e, serial))?;

    say!();
    say!("Root CA \"{name}\" now lives on YubiKey {serial}.");
    say!("Valid until {}", root.not_after().date());
    write_new_ca(
        out,
        "root.pem",
        "install on devices as trusted CA",
        &root.certificate_pem(),
        attestation.as_ref(),
    )
}

/// The workspace a new issuing CA is entered into.
struct EnterInto<'a> {
    dir: &'a Path,
    /// Have the root CA revoke the issuing CA that is replaced.
    revoke_old: bool,
}

fn init_issuing(
    name: &str,
    serial: u32,
    root_serial: Option<u32>,
    key: CaKey,
    replace: bool,
    workspace: Option<EnterInto<'_>>,
    out: &Path,
) -> Result<()> {
    let revoke_old = workspace.as_ref().is_some_and(|w| w.revoke_old);
    let store = workspace.map(|w| w.dir);
    let found = device::list_devices()?;
    let root_device = found
        .select_ca(CaRole::Root, root_serial)
        .context("the root CA signs the issuing CA, so its YubiKey has to be connected too")?;
    if root_device.serial == serial {
        bail!("YubiKey {serial} holds the root CA; the issuing CA needs a YubiKey of its own");
    }
    let root_ca = root_device
        .ca
        .as_ref()
        .expect("select_ca returns a key with a CA");
    let mut store = store.map(Store::open).transpose()?;
    if let Some(store) = &store
        && store.ca_certificate_der(CaRole::Root)? != root_ca.certificate_der
    {
        bail!(
            "YubiKey {} holds a different root CA than the workspace folder {}",
            root_device.serial,
            store.dir().display()
        );
    }
    if revoke_old
        && !store
            .as_ref()
            .is_some_and(|s| s.ca(CaRole::Issuing).is_some())
    {
        bail!("--revoke-old is for replacing an issuing CA, and this workspace has none");
    }

    let device = target_for_new_ca(&found, serial, "an issuing CA", replace)?;
    say!(
        "It will be signed by the root CA \"{}\" on YubiKey {}.",
        root_ca.subject,
        root_device.serial
    );
    let pin = pin_for_new_ca(device)?;
    let root_pin = prompt_pin(root_device)?;
    let root = Authority::open_on_yubikey(root_device.serial, &root_pin)?;
    drop(root_pin);

    say!("Generating the key inside YubiKey {serial}...");
    say!(
        "Touch the ROOT YubiKey (serial {}) when it starts blinking; it signs the new CA.",
        root_device.serial
    );
    let now = OffsetDateTime::now_utc();
    let created =
        Authority::create_issuing_on_yubikey(&root, serial, &pin, &new_ca(name, key, replace), now);
    drop(pin);
    let (issuing, attestation) = created.map_err(|e| {
        // If it was the root that refused to sign, say why.
        match root.key().take_last_error() {
            Some(cause) => explain_setup_error(e, serial).context(cause),
            None => explain_setup_error(e, serial),
        }
    })?;

    let mut replaced = None;
    if let Some(store) = &mut store {
        let before = store.retired().len();
        store.set_issuing(issuing.certificate_der(), serial)?;
        if let Some(attestation) = &attestation {
            store.save_attestation(CaRole::Issuing, attestation)?;
        }
        replaced = store.retired().get(before).cloned();
        if let (true, Some(old)) = (revoke_old, &replaced) {
            store.revoke_retired(&old.serial, now)?;
        }
    }
    say!();
    say!("Issuing CA \"{name}\" now lives on YubiKey {serial}.");
    say!("Valid until {}", issuing.not_after().date());
    if let Some(store) = &store {
        say!("Entered into {} as its issuing CA.", store.dir().display());
    }
    if let Some(old) = &replaced {
        say!();
        say!("It replaces \"{}\".", old.subject);
        if revoke_old {
            say!(
                "The old issuing CA is marked as revoked. Devices only learn of it from the \
                 root CA's revocation list: run `yca crl --root` while the root YubiKey is \
                 connected. Then renew the certificates the old CA signed."
            );
        } else {
            say!(
                "The certificates it signed stay valid, but can no longer be revoked one by \
                 one. `yca reissue` renews them under the new issuing CA."
            );
        }
    }
    write_new_ca(
        out,
        "issuing.pem",
        "issuing CA certificate; travels with every certificate it signs",
        &issuing.certificate_pem(),
        attestation.as_ref(),
    )
}

/// The same as [`init_issuing`], except that the root is a key in memory
/// that is thrown away afterwards. Lets the creation of an issuing CA be
/// exercised with one YubiKey.
fn init_issuing_under_throwaway_root(
    name: &str,
    serial: u32,
    key: CaKey,
    replace: bool,
    out: &Path,
) -> Result<()> {
    let found = device::list_devices()?;
    let device = target_for_new_ca(&found, serial, "an issuing CA", replace)?;
    say!("It will be signed by a throwaway root that exists only in memory. For testing.");
    let pin = pin_for_new_ca(device)?;

    let now = OffsetDateTime::now_utc();
    let root_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)
        .context("could not generate the throwaway root key")?;
    let root = Authority::create_root("yca throwaway Root CA", root_key, now)?;
    say!("Generating the key inside YubiKey {serial}...");
    let created =
        Authority::create_issuing_on_yubikey(&root, serial, &pin, &new_ca(name, key, replace), now);
    drop(pin);
    let (issuing, attestation) = created.map_err(|e| explain_setup_error(e, serial))?;

    say!();
    say!("Issuing CA \"{name}\" now lives on YubiKey {serial}.");
    say!("Valid until {}", issuing.not_after().date());
    write_new_ca(
        out,
        "issuing.pem",
        "issuing CA certificate; travels with every certificate it signs",
        &issuing.certificate_pem(),
        attestation.as_ref(),
    )?;
    write_public(&out.join("root.pem"), &root.certificate_pem())?;
    say!(
        "  {:<28}  the throwaway root's certificate; its key is gone",
        "root.pem"
    );
    Ok(())
}

/// Finds the YubiKey a new CA goes on and makes sure nothing is destroyed
/// by accident: a key whose slot 9c is in use is refused unless --replace
/// was given and the serial number is typed in again.
fn target_for_new_ca<'a>(
    found: &'a device::Devices,
    serial: u32,
    what: &str,
    replace: bool,
) -> Result<&'a Device> {
    let device = found
        .usable
        .iter()
        .find(|device| device.serial == serial)
        .with_context(|| format!("YubiKey {serial} is not connected"))?;
    let (major, minor, patch) = device.firmware;
    say!("Setting up {what} on YubiKey {serial} (firmware {major}.{minor}.{patch}).");

    let occupant = match &device.ca {
        Some(ca) => Some(format!("the {} \"{}\"", ca.role, ca.subject)),
        None if device.signature_slot_in_use() => Some("a certificate in slot 9c".to_owned()),
        None => None,
    };
    match (&occupant, replace) {
        (Some(what), false) => bail!(
            "YubiKey {serial} already holds {what}. It is left untouched; \
             pass --replace to destroy it and start over."
        ),
        (_, true) => {
            let what = occupant.as_deref().unwrap_or("whatever key is in slot 9c");
            say!("This permanently destroys {what} on YubiKey {serial}.");
            confirm_serial(serial)?;
        }
        (None, false) => {}
    }
    Ok(device)
}

/// The PIN for a YubiKey that is about to get a CA. A key still in its
/// factory state gets a PIN and PUK of the user's own first.
fn pin_for_new_ca(device: &Device) -> Result<Zeroizing<String>> {
    if device.factory.pin == Some(true) {
        say!("This YubiKey still has its factory PIN. A CA needs one of your own first.");
        set_own_credentials(device.serial)
    } else {
        prompt_pin(device)
    }
}

fn new_ca(name: &str, key: CaKey, replace: bool) -> NewCa<'_> {
    NewCa {
        name,
        key_type: match key {
            CaKey::P384 => CaKeyType::EccP384,
            CaKey::P256 => CaKeyType::EccP256,
        },
        replace_existing: replace,
    }
}

fn explain_setup_error(error: Error, serial: u32) -> anyhow::Error {
    match error {
        Error::SlotInUse => anyhow::anyhow!(
            "slot 9c of YubiKey {serial} holds a key without a certificate, probably from an \
             interrupted setup. Pass --replace to start over."
        ),
        other => other.into(),
    }
}

/// Writes the certificate of a new CA and the YubiKey's attestation of
/// its key, and lists the files.
fn write_new_ca(
    out: &Path,
    file: &str,
    purpose: &str,
    certificate_pem: &str,
    attestation: Option<&yca_core::Attestation>,
) -> Result<()> {
    fs::create_dir_all(out).with_context(|| format!("could not create {}", out.display()))?;
    write_public(&out.join(file), certificate_pem)?;
    say!();
    say!("Wrote to {}:", out.display());
    say!("  {file:<28}  {purpose}");
    match attestation {
        Some(attestation) => {
            write_public(
                &out.join("attestation.pem"),
                &pem_certificate(&attestation.certificate_der),
            )?;
            write_public(
                &out.join("attestation-intermediate.pem"),
                &pem_certificate(&attestation.intermediate_der),
            )?;
            say!(
                "  {:<28}  the YubiKey's proof that the key was made inside it",
                "attestation.pem"
            );
            say!(
                "  {:<28}  this YubiKey's attestation certificate from Yubico",
                "attestation-intermediate.pem"
            );
        }
        None => {
            say!("  (this firmware cannot attest that the key was made inside the YubiKey)")
        }
    }
    Ok(())
}

fn protect(serial: u32) -> Result<()> {
    let found = device::list_devices()?;
    let device = found
        .usable
        .iter()
        .find(|device| device.serial == serial)
        .with_context(|| format!("YubiKey {serial} is not connected"))?;
    if device.factory.pin != Some(true) {
        bail!("the PIN of YubiKey {serial} is not the factory one; there is nothing to do");
    }
    say!("YubiKey {serial} still has its factory PIN.");
    set_own_credentials(serial)?;
    Ok(())
}

/// The slot of a YubiKey's own attestation certificate, as `yca devices`
/// names it.
const ATTESTATION_SLOT: &str = "f9";

fn connected(found: &device::Devices, serial: u32) -> Result<&Device> {
    found
        .usable
        .iter()
        .find(|device| device.serial == serial)
        .with_context(|| format!("YubiKey {serial} is not connected"))
}

fn change_pin(serial: u32) -> Result<()> {
    let found = device::list_devices()?;
    let device = connected(&found, serial)?;
    if device.factory.pin == Some(true) {
        bail!(
            "YubiKey {serial} still has its factory PIN; `yca protect` gives it a PIN, a PUK \
             and a management key of its own"
        );
    }
    let current = prompt_pin(device)?;
    let new = prompt_new("PIN")?;
    yca_core::change_pin(serial, &current, &new)?;
    say!("YubiKey {serial} now has the new PIN. Nothing else on it changed.");
    Ok(())
}

fn unblock(serial: u32) -> Result<()> {
    let found = device::list_devices()?;
    connected(&found, serial)?;
    say!("Setting a new PIN on YubiKey {serial} with its PUK.");
    say!("A wrong PUK costs one of its attempts, and nothing unblocks a PUK.");
    let puk = Zeroizing::new(
        rpassword::prompt_password("PUK: ").context("could not read the PUK from the terminal")?,
    );
    let new = prompt_new("PIN")?;
    yca_core::unblock_pin(serial, &puk, &new)?;
    say!("YubiKey {serial} now has the new PIN. Nothing else on it changed.");
    Ok(())
}

fn reset(serial: u32) -> Result<()> {
    let found = device::list_devices()?;
    let device = connected(&found, serial)?;
    let (major, minor, patch) = device.firmware;
    say!("YubiKey {serial} (firmware {major}.{minor}.{patch}) holds in its PIV application:");
    match &device.ca {
        Some(ca) => say!("  slot 9c: the {} \"{}\"", ca.role, ca.subject),
        None if device.signature_slot_in_use() => say!("  slot 9c: a certificate"),
        None => {}
    }
    // Slot f9 holds the YubiKey's own attestation certificate, which a
    // reset leaves in place.
    let others: Vec<_> = device
        .occupied_slots
        .iter()
        .filter(|slot| !slot.is_signature_slot && slot.slot != ATTESTATION_SLOT)
        .collect();
    for slot in &others {
        say!(
            "  slot {}: a certificate for \"{}\"",
            slot.slot,
            slot.subject
        );
    }
    if device.ca.is_none() && !device.signature_slot_in_use() && others.is_empty() {
        say!("  no certificates");
    }
    say!();
    say!("Resetting destroys all of it for good, with every PIV key on this YubiKey,");
    say!("and sets the PIN, the PUK and the management key back to the factory ones.");
    say!("The YubiKey's own attestation certificate stays, and FIDO2, OATH and OpenPGP");
    say!("on the same YubiKey are not touched.");
    confirm_serial(serial)?;
    yca_core::reset_piv(serial)?;
    say!();
    say!("YubiKey {serial} is as it left the factory: PIN 123456, PUK 12345678.");
    say!("Give it a PIN of its own before anything else: `yca protect --device {serial}`,");
    say!("or let the app do it when you create a CA on it.");
    Ok(())
}

/// Asks for a new PIN and PUK, puts them on a factory-state YubiKey and
/// returns the new PIN.
fn set_own_credentials(serial: u32) -> Result<Zeroizing<String>> {
    say!("  PIN: asked for at every signature.");
    say!("  PUK: unblocks the PIN after three wrong attempts. Write it down and keep it");
    say!("       away from the YubiKey; without it a blocked key has to be wiped.");
    let pin = prompt_new("PIN")?;
    let puk = prompt_new("PUK")?;
    let changed = yca_core::protect_yubikey(serial, &pin, &puk)?;

    say!("YubiKey {serial} now has your PIN.");
    say!(
        "  PUK:             {}",
        if changed.puk_changed {
            "set to yours"
        } else {
            "had been changed before; left as it was"
        }
    );
    say!(
        "  management key:  {}",
        if changed.management_key_protected {
            "random, kept on the YubiKey behind your PIN"
        } else {
            "had been changed before; left as it was"
        }
    );
    Ok(pin)
}

/// Reads a new secret twice from the terminal.
fn prompt_new(what: &str) -> Result<Zeroizing<String>> {
    let prompt = |text: String| -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(
            rpassword::prompt_password(text)
                .with_context(|| format!("could not read the {what} from the terminal"))?,
        ))
    };
    let first = prompt(format!("New {what} (6 to 8 characters): "))?;
    if *first != *prompt(format!("Repeat the new {what}: "))? {
        bail!("the two entries differ; nothing was changed");
    }
    Ok(first)
}

fn attest(serial: u32) -> Result<()> {
    match yca_core::attest_ca_on_yubikey(serial)? {
        Some(_) => say!(
            "YubiKey {serial} attests that the CA key in slot 9c was generated inside it, \
             and the attestation matches the CA certificate."
        ),
        None => say!("The firmware of YubiKey {serial} cannot attest its keys."),
    }
    Ok(())
}

/// Asks for the PIN on the terminal. A wrong PIN uses up an attempt, so
/// this refuses to gamble with the last one.
fn prompt_pin(device: &Device) -> Result<Zeroizing<String>> {
    match device.pin_attempts_left {
        0 => bail!("the PIN of this YubiKey is locked; unblock it with the PUK first"),
        1 => bail!(
            "only one PIN attempt is left on this YubiKey; a wrong PIN now would lock it. \
             Enter the correct PIN once in another tool to reset the counter, then retry."
        ),
        _ => {}
    }
    let pin = rpassword::prompt_password(format!(
        "PIN of YubiKey {} ({} attempts left): ",
        device.serial, device.pin_attempts_left
    ))
    .context("could not read the PIN from the terminal")?;
    Ok(Zeroizing::new(pin))
}

/// Makes the user type the serial number of the YubiKey about to be wiped.
fn confirm_serial(serial: u32) -> Result<()> {
    eprint!("Type the serial number of that YubiKey to confirm: ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if answer.trim() != serial.to_string() {
        bail!("the serial number does not match; nothing was changed");
    }
    Ok(())
}

fn announce_touch(connected: usize, serial: u32) {
    if connected > 1 {
        say!(
            "{connected} YubiKeys are connected. Touch only the one that blinks (serial {serial})."
        );
        say!("Touching another one signs nothing and may type a one-time code here.");
    } else {
        say!("Touch the YubiKey when it starts blinking...");
    }
}

fn pem_certificate(der: &[u8]) -> String {
    pem::encode_config(
        &pem::Pem::new("CERTIFICATE", der),
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    )
}

fn demo(hosts: &[String], export_args: &ExportArgs, algorithm: Algorithm) -> Result<()> {
    let now = OffsetDateTime::now_utc();
    let password = match export_args.files {
        Files::P12 => Some(p12_password()?),
        Files::Fullchain | Files::Separate => None,
    };

    let root = Authority::create_root("yca demo Root CA", algorithm.generate()?, now)?;
    let issuing = root.create_issuing("yca demo Issuing CA", algorithm.generate()?, now)?;

    let server_key = algorithm.generate()?;
    let server = issuing.issue(&LeafRequest::tls_server(hosts)?, &server_key, now)?;

    write_bundle(
        export_args,
        &target(None, export_args.out.as_deref()),
        &server,
        &server_key,
        &hosts[0],
        password.as_ref().map(|password| password.as_str()),
    )?;
    say!();
    say!("Certificate for {}", hosts.join(", "));
    say!("Root valid until    {}", root.not_after().date());
    say!("Server valid until  {}", server.not_after().date());
    say!();
    say!("This is a demo CA: its keys existed only in memory and are gone now.");
    Ok(())
}

/// Packs a freshly issued certificate for where it is going, writes the
/// files and lists them.
/// Where the files of a certificate go: its folder in the workspace, or,
/// with no workspace to keep them, a directory named on the command line.
enum Target<'a> {
    Folder(&'a CertificateFolder),
    Directory(&'a Path),
}

impl Target<'_> {
    fn path(&self) -> &Path {
        match self {
            Target::Folder(folder) => folder.path(),
            Target::Directory(path) => path,
        }
    }

    fn write(&self, file: &ExportFile) -> Result<()> {
        match self {
            Target::Folder(folder) => Ok(folder.write(file)?),
            Target::Directory(out) => {
                fs::create_dir_all(out)
                    .with_context(|| format!("could not create {}", out.display()))?;
                let path = out.join(&file.name);
                if file.holds_private_key {
                    write_private(&path, &file.contents)
                } else {
                    fs::write(&path, &file.contents)
                        .with_context(|| format!("could not write {}", path.display()))
                }
            }
        }
    }

    /// Writes the files and lists them.
    fn write_all(&self, files: &[ExportFile]) -> Result<()> {
        let width = files.iter().map(|file| file.name.len()).max().unwrap_or(0);
        say!();
        say!("Wrote to {}:", self.path().display());
        for file in files {
            self.write(file)?;
            say!("  {:<width$}  {}", file.name, file.purpose);
        }
        Ok(())
    }
}

/// The folder a certificate gets in the workspace, made before the YubiKey
/// signs. With a workspace the files always go there, so a directory named
/// on the command line as well would be a second home for them.
fn folder_in(
    store: Option<&Store>,
    out: Option<&Path>,
    first_name: &str,
    group: Option<&str>,
) -> Result<Option<CertificateFolder>> {
    match (store, out) {
        (Some(_), Some(_)) => bail!(
            "with --store the files go into the certificate's folder in the workspace; \
             leave --out away"
        ),
        (Some(store), None) => Ok(Some(store.new_certificate_folder(first_name, group)?)),
        (None, _) => Ok(None),
    }
}

/// Without a workspace: the directory named with --out, or `out`.
fn target<'a>(folder: Option<&'a CertificateFolder>, out: Option<&'a Path>) -> Target<'a> {
    match folder {
        Some(folder) => Target::Folder(folder),
        None => Target::Directory(out.unwrap_or(Path::new("out"))),
    }
}

fn write_bundle(
    args: &ExportArgs,
    to: &Target<'_>,
    issued: &IssuedCertificate,
    key: &KeyPair,
    label: &str,
    password: Option<&str>,
) -> Result<()> {
    let key_der = Zeroizing::new(key.serialize_der());
    let files = yca_core::export(
        args.files.into(),
        ExportSource {
            issued,
            private_key_der: Some(&key_der),
        },
        password.map(|password| P12Options {
            password,
            encryption: args.p12.into(),
            label,
        }),
    )?;

    to.write_all(&files)
}

/// Writes the files of a certificate again in another form.
fn repackage(dir: &Path, serial: &str, files: Files, p12: P12) -> Result<()> {
    let mut store = Store::open(dir)?;
    let record: Record = store.find(serial)?.clone();
    // The key of a certificate that is in one .p12 file is nowhere else.
    let opens = match store.form(&record) {
        Some(ExportForm::Pkcs12) => Some(p12_opens()?),
        _ => None,
    };
    let password = match files {
        Files::P12 => Some(p12_password()?),
        Files::Fullchain | Files::Separate => None,
    };
    let repacked = store.repackage(
        &record.serial,
        Repack {
            form: files.into(),
            opens: opens.as_ref().map(|password| password.as_str()),
            password: password.as_ref().map(|password| password.as_str()),
            encryption: p12.into(),
        },
    )?;
    answer(serde_json::json!({
        "serial": record.serial,
        "names": record.names,
        "folder": repacked.folder.to_string_lossy(),
        // What the folder holds now, as everything else calls it: where
        // the root CA signed, separate files and the full chain are one.
        "form": store.form(&record).map(ExportForm::name),
        "files": repacked.files.iter().map(|file| &file.name).collect::<Vec<_>>(),
    }));

    let width = repacked
        .files
        .iter()
        .map(|file| file.name.len())
        .max()
        .unwrap_or(0);
    say!("Certificate for {}", record.names.join(", "));
    say!();
    say!("{} now holds:", repacked.folder.display());
    for file in &repacked.files {
        say!("  {:<width$}  {}", file.name, file.purpose);
    }
    say!();
    say!("Nothing was issued: it is the same certificate and the same key.");
    Ok(())
}

/// The password of the .p12 file a certificate is in now, to get its
/// private key out. From the environment where there is no terminal to
/// ask on.
fn p12_opens() -> Result<Zeroizing<String>> {
    if let Ok(password) = std::env::var("YCA_P12_OPENS") {
        return Ok(Zeroizing::new(password));
    }
    Ok(Zeroizing::new(
        rpassword::prompt_password("Password of the .p12 file it is in now: ")
            .context("could not read the password from the terminal")?,
    ))
}

/// The password of a client bundle's .p12 file: typed twice on the
/// terminal, or taken from YCA_P12_PASSWORD for scripts and tests.
fn p12_password() -> Result<Zeroizing<String>> {
    if let Ok(password) = std::env::var("YCA_P12_PASSWORD") {
        return Ok(Zeroizing::new(password));
    }
    let prompt = |text: &str| -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(rpassword::prompt_password(text).context(
            "could not read the password from the terminal",
        )?))
    };
    let password = prompt("Password for the .p12 file: ")?;
    if password.is_empty() {
        bail!("the .p12 password must not be empty");
    }
    if *password != *prompt("Repeat the password: ")? {
        bail!("the two passwords differ");
    }
    Ok(password)
}

/// A file that anyone may read.
fn write_public(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("could not write {}", path.display()))
}

/// Writes a private key readable by the owner only.
fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("could not write {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("could not write {}", path.display()))
}
