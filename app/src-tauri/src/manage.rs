//! What the window does besides issuing a certificate with a new key:
//! issue one again for the same key, sign a device's own request, write a
//! certificate's files again in another form, revoke one, delete one from
//! the list, and sign the revocation list.

use std::fs;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use time::OffsetDateTime;
use yca_core::device::CaRole;
use yca_core::{
    ExportForm, ExportSource, LeafProfile, LeafRequest, P12Encryption, Record, Repack,
    SigningRequest, Store,
};
use zeroize::Zeroizing;

use crate::issue::{
    Failure, FileView, Issued, ask_for_touch, filled, limited, locate_ca, open_ca, other, sign,
};
use crate::{KeyLock, PkiView, pki_view, timestamp};

/// What the window asks for when a certificate is to be issued again.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReissueRequest {
    pki_path: String,
    /// Serial number of the certificate to replace.
    serial: String,
    /// The certificate as the window showed it.
    shown: Shown,
    /// The names the new certificate gets: for a renewal, the names the
    /// old one has.
    names: Vec<String>,
    /// Mark the replaced certificate as revoked.
    revoke_old: bool,
    /// Expire after this many days instead of as late as possible.
    #[serde(default)]
    days: Option<u32>,
    /// The password of the `.p12` file the old certificate is in, where
    /// it is in one: its private key is inside, and the new file gets the
    /// same password.
    #[serde(default)]
    opens: Option<String>,
    /// The SHA-256 fingerprint of the CA certificate the window showed as
    /// the one that signs. Nothing is signed if the workspace names
    /// another CA by now.
    ca: String,
    pin: String,
}

/// What the window showed of the certificate that is issued again. The
/// register is a file that other programs write to as well, and the one
/// who types the PIN agreed to what they were shown, not to what the
/// register says by the time the PIN arrives.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Shown {
    names: Vec<String>,
    profile: LeafProfile,
    issued_by: CaRole,
}

impl Shown {
    /// Whether the register still says of the certificate with this very
    /// serial number what the window showed of it.
    fn still_holds(&self, serial: &str, record: &Record) -> bool {
        record.serial == serial
            && record.names == self.names
            && record.profile == self.profile
            && record.issued_by == self.issued_by
    }
}

/// Issues a new certificate for the key of an existing one, to change its
/// names or to renew it. The private key stays on the device; only the new
/// certificate has to be installed there. Its folder holds the key all the
/// same, as the old one's did, so that it is complete on its own.
#[tauri::command]
pub async fn reissue_certificate(
    app: AppHandle,
    request: ReissueRequest,
) -> Result<Issued, Failure> {
    tauri::async_runtime::spawn_blocking(move || reissue(&app, request))
        .await
        .map_err(other)?
}

fn reissue(app: &AppHandle, request: ReissueRequest) -> Result<Issued, Failure> {
    let pin = Zeroizing::new(request.pin);
    let opens = request.opens.map(Zeroizing::new);
    let lock = app.state::<KeyLock>();
    let _signing = lock.wait();

    let mut store = Store::open(&request.pki_path)?;
    let old = store.find(&request.serial)?.clone();
    if !request.shown.still_holds(&request.serial, &old) {
        return Err(other(
            "the register no longer says of this certificate what was shown here: another \
             program changed the workspace. Close this and look at the certificate again",
        ));
    }
    let leaf_request = limited(
        LeafRequest::for_profile(old.profile, &request.names)?,
        request.days,
    )?;
    // The CA that signed the old certificate signs the new one. Its
    // YubiKey says, before its PIN is used, whether the register's copy of
    // the old certificate is that certificate: the key in it is the key
    // that gets certified again.
    let key = locate_ca(&store, old.issued_by, &request.ca)?;
    let previous = store.certificate_to_renew(&old, key.certificate_der())?;
    // The private key, and the password of its file, before the YubiKey
    // signs.
    let renewal = store.renewal(&old, opens.as_deref().map(String::as_str))?;
    // The new certificate stays in the group of the one it replaces.
    let folder = store.new_certificate_folder(&leaf_request.names()[0], old.group.as_deref())?;

    let serial = key.serial();
    let authority = key.open(pin)?;
    ask_for_touch(app, &authority, serial);
    let now = OffsetDateTime::now_utc();
    let issued = sign(&authority, |ca| ca.reissue(&leaf_request, &previous, now))?;
    // The files come in the form the old ones are in, with the same key.
    let files = renewal.files(&issued, &leaf_request.names()[0])?;
    store.record_with(
        &folder,
        &issued,
        &leaf_request,
        old.issued_by,
        Some(&old.serial),
        now,
        &files,
    )?;
    // Last, when the new certificate is there in full. A certificate that
    // can no longer be revoked, or that another program has revoked or
    // deleted in the meantime, is left as it is.
    if request.revoke_old {
        store.revoke_replaced(&old.serial, now)?;
    }
    filled(&folder, &issued, files)
}

/// What a device asks for in its request file.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestView {
    /// The names the device would like in its certificate, if it said any.
    names: Vec<String>,
}

/// Reads a device's certificate request (CSR), so the window can show
/// what it asks for before anything is signed. Refuses a file that is not
/// a request or whose signature does not hold.
#[tauri::command(async)]
pub fn read_request(path: String) -> Result<RequestView, String> {
    let bytes = fs::read(&path).map_err(|e| format!("{path}: {e}"))?;
    let request = SigningRequest::parse(&bytes).map_err(|e| e.to_string())?;
    Ok(RequestView {
        names: request.names().to_vec(),
    })
}

/// What the window asks for when a device's request is to be signed.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignRequest {
    pki_path: String,
    /// The request file the device made.
    csr_path: String,
    profile: LeafProfile,
    /// The names to certify; the request only suggests them.
    names: Vec<String>,
    /// What the upload form of the device asks for. There is no private
    /// key among the files, so not everything in one.
    #[serde(default)]
    files: ExportForm,
    /// For a device that cannot handle a certificate chain.
    sign_with_root: bool,
    /// Expire after this many days instead of as late as possible.
    #[serde(default)]
    days: Option<u32>,
    /// The group to sort the certificate into, if any.
    #[serde(default)]
    group: Option<String>,
    /// The SHA-256 fingerprint of the CA certificate the window showed as
    /// the one that signs. Nothing is signed if the workspace names
    /// another CA by now.
    ca: String,
    pin: String,
}

/// Issues a certificate for the key in a device's request. The device
/// made the key and keeps it; nothing but certificates is written out.
#[tauri::command]
pub async fn sign_request(app: AppHandle, request: SignRequest) -> Result<Issued, Failure> {
    tauri::async_runtime::spawn_blocking(move || sign_csr(&app, request))
        .await
        .map_err(other)?
}

fn sign_csr(app: &AppHandle, request: SignRequest) -> Result<Issued, Failure> {
    let pin = Zeroizing::new(request.pin);
    let lock = app.state::<KeyLock>();
    let _signing = lock.wait();

    // The device has its key and gives it to nobody.
    if request.files == ExportForm::Pkcs12 {
        return Err(other(
            "a .p12 file holds the private key, which stays in the device that made the request",
        ));
    }
    let bytes =
        fs::read(&request.csr_path).map_err(|e| other(format!("{}: {e}", request.csr_path)))?;
    let signing_request = SigningRequest::parse(&bytes)?;
    let mut store = Store::open(&request.pki_path)?;
    let role = if request.sign_with_root {
        CaRole::Root
    } else {
        store.everyday_ca()
    };
    // What goes into the certificate is what the person at the window
    // said, not what the device would like.
    let leaf_request = limited(
        LeafRequest::for_profile(request.profile, &request.names)?,
        request.days,
    )?;
    let folder =
        store.new_certificate_folder(&leaf_request.names()[0], request.group.as_deref())?;

    let authority = open_ca(app, &store, role, &request.ca, pin)?;
    let now = OffsetDateTime::now_utc();
    let issued = sign(&authority, |ca| {
        ca.sign_request(&leaf_request, &signing_request, now)
    })?;

    // No private key: the device made it and keeps it.
    let files = yca_core::export(
        request.files,
        ExportSource {
            issued: &issued,
            private_key_der: None,
        },
        None,
    )?;
    store.record_with(&folder, &issued, &leaf_request, role, None, now, &files)?;
    filled(&folder, &issued, files)
}

/// What the window asks for when a certificate's files are to be written
/// again in another form.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepackageRequest {
    path: String,
    serial: String,
    /// What the upload form of the device asks for.
    files: ExportForm,
    /// The password of the `.p12` file the folder holds now, where the
    /// private key is inside it and nowhere else.
    #[serde(default)]
    opens: Option<String>,
    /// The password for the `.p12` file to write.
    #[serde(default)]
    p12_password: Option<String>,
    /// Encrypt that file the way older systems need it.
    #[serde(default)]
    p12_compatible: bool,
}

/// What the window gets back: what the folder holds now, and the
/// workspace as it is.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Repackaged {
    folder: String,
    files: Vec<FileView>,
    pki: PkiView,
}

/// Writes the files of a certificate again in the form another kind of
/// upload form asks for. Nothing is issued and no YubiKey is needed: the
/// certificate and its key are in the workspace.
#[tauri::command(async)]
pub fn repackage_certificate(request: RepackageRequest) -> Result<Repackaged, String> {
    let opens = request.opens.map(Zeroizing::new);
    let password = request.p12_password.map(Zeroizing::new);
    let mut store = Store::open(&request.path).map_err(|e| e.to_string())?;
    let repacked = store
        .repackage(
            &request.serial,
            Repack {
                form: request.files,
                opens: opens.as_ref().map(|password| password.as_str()),
                password: password.as_ref().map(|password| password.as_str()),
                encryption: match request.p12_compatible {
                    true => P12Encryption::Compatible,
                    false => P12Encryption::Modern,
                },
            },
        )
        .map_err(|e| e.to_string())?;
    Ok(Repackaged {
        folder: repacked.folder.to_string_lossy().into_owned(),
        files: repacked.files.into_iter().map(FileView::of).collect(),
        pki: pki_view(&store)?,
    })
}

/// Marks a certificate as revoked in the register. Needs no YubiKey;
/// devices learn of it from the next revocation list.
#[tauri::command(async)]
pub fn revoke_certificate(path: String, serial: String) -> Result<PkiView, String> {
    let mut store = Store::open(&path).map_err(|e| e.to_string())?;
    store
        .revoke(&serial, OffsetDateTime::now_utc())
        .map_err(|e| e.to_string())?;
    pki_view(&store)
}

/// Deletes a certificate from the register, and its files from the
/// workspace, a private key among them. Needs no YubiKey. A certificate
/// that is installed somewhere is not affected; one that was revoked
/// stays on the revocation list until it would have expired.
#[tauri::command(async)]
pub fn delete_certificate(path: String, serial: String) -> Result<PkiView, String> {
    let mut store = Store::open(&path).map_err(|e| e.to_string())?;
    store
        .delete(&serial, OffsetDateTime::now_utc())
        .map_err(|e| e.to_string())?;
    pki_view(&store)
}

/// Sorts certificates into a group, or with no group named takes them out
/// of theirs. Needs no YubiKey. In the workspace, the folder of each
/// certificate moves into the folder of its group.
#[tauri::command(async)]
pub fn set_group(
    path: String,
    serials: Vec<String>,
    group: Option<String>,
) -> Result<PkiView, String> {
    let mut store = Store::open(&path).map_err(|e| e.to_string())?;
    // Every certificate is looked up before any is moved, so that one
    // that is gone does not leave the rest half sorted.
    let mut found = Vec::new();
    for serial in &serials {
        found.push(
            store
                .find(serial)
                .map_err(|e| e.to_string())?
                .serial
                .clone(),
        );
    }
    for serial in &found {
        store
            .set_group(serial, group.as_deref())
            .map_err(|e| e.to_string())?;
    }
    pki_view(&store)
}

/// Marks an issuing CA that was replaced as revoked: for when its YubiKey
/// turns out to be in someone else's hands. Needs no YubiKey; devices
/// learn of it from the next revocation list of the root CA.
#[tauri::command(async)]
pub fn revoke_replaced_ca(path: String, serial: String) -> Result<PkiView, String> {
    let mut store = Store::open(&path).map_err(|e| e.to_string())?;
    store
        .revoke_retired(&serial, OffsetDateTime::now_utc())
        .map_err(|e| e.to_string())?;
    pki_view(&store)
}

/// What the window asks for when a revocation list is to be signed.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListRequest {
    pki_path: String,
    /// Whose list: each CA lists the certificates it issued itself.
    role: CaRole,
    /// The SHA-256 fingerprint of the CA certificate the window showed as
    /// the one that signs. Nothing is signed if the workspace names
    /// another CA by now.
    ca: String,
    pin: String,
}

/// A freshly signed revocation list.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListSigned {
    number: u64,
    /// How many certificates the list names.
    count: usize,
    /// Until when devices treat the list as current.
    next_update: String,
    folder: String,
    files: Vec<FileView>,
}

/// Signs the revocation list of one CA: the file a device needs in order
/// to refuse a revoked certificate.
#[tauri::command]
pub async fn sign_revocation_list(
    app: AppHandle,
    request: ListRequest,
) -> Result<ListSigned, Failure> {
    tauri::async_runtime::spawn_blocking(move || sign_list(&app, request))
        .await
        .map_err(other)?
}

fn sign_list(app: &AppHandle, request: ListRequest) -> Result<ListSigned, Failure> {
    let pin = Zeroizing::new(request.pin);
    let lock = app.state::<KeyLock>();
    let _signing = lock.wait();

    let mut store = Store::open(&request.pki_path)?;
    let role = request.role;
    let now = OffsetDateTime::now_utc();
    let revoked = store.revoked(role, now);
    let number = store.next_crl_number(role)?;

    let authority = open_ca(app, &store, role, &request.ca, pin)?;
    let list = sign(&authority, |ca| ca.revocation_list(&revoked, number, now))?;
    // The workspace keeps the current list of each CA, in both forms.
    let (folder, [pem, der]) = store.save_crl(role, &list)?;
    Ok(ListSigned {
        number,
        count: revoked.len(),
        next_update: timestamp(list.next_update()),
        folder: folder.to_string_lossy().into_owned(),
        files: [pem, der]
            .into_iter()
            .map(|name| FileView {
                name,
                holds_private_key: false,
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_that_is_no_request_is_an_error_the_window_can_show() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notes.txt");
        fs::write(&path, "not a certificate request").unwrap();
        assert!(read_request(path.to_string_lossy().into_owned()).is_err());
        assert!(read_request("/nowhere/at/all.csr".to_owned()).is_err());
    }

    #[test]
    fn a_certificate_the_register_changed_is_not_the_one_that_was_shown() {
        let at = OffsetDateTime::now_utc();
        let root =
            yca_core::Authority::create_root("Test Root CA", crate::fixtures::key(), at).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut store =
            Store::create(dir.path().join("pki"), root.certificate_der(), 1001).unwrap();
        let request = LeafRequest::tls_server(["nas.home.example"]).unwrap();
        let issued = root.issue(&request, &crate::fixtures::key(), at).unwrap();
        let record = store
            .record(&issued, &request, CaRole::Root, None, at)
            .unwrap()
            .clone();
        let shown = |name: &str, profile, issued_by| Shown {
            names: vec![name.to_owned()],
            profile,
            issued_by,
        };
        let as_issued = shown("nas.home.example", LeafProfile::TlsServer, CaRole::Root);
        assert!(as_issued.still_holds(&record.serial, &record));
        // Only the certificate with the whole serial number is the one.
        assert!(!as_issued.still_holds(&record.serial[..8], &record));

        // The register says other names, another purpose or another CA than
        // the window showed: what was agreed to is not what would be signed.
        for changed in [
            shown("admin.home.example", LeafProfile::TlsServer, CaRole::Root),
            shown("nas.home.example", LeafProfile::TlsClient, CaRole::Root),
            shown("nas.home.example", LeafProfile::TlsServer, CaRole::Issuing),
        ] {
            assert!(!changed.still_holds(&record.serial, &record));
        }
    }

    #[test]
    fn a_request_made_by_openssl_tells_what_the_device_asks_for() {
        use std::process::Command;

        // Skipped where there is no openssl to play the device.
        if Command::new("openssl").arg("version").output().is_err() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let made = Command::new("openssl")
            .current_dir(dir.path())
            .args([
                "req",
                "-new",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-keyout",
                "key.pem",
                "-out",
                "switch.csr",
                "-subj",
                "/CN=switch.example",
                "-addext",
                "subjectAltName=DNS:switch.example,IP:192.0.2.7",
            ])
            .output()
            .unwrap();
        assert!(
            made.status.success(),
            "{}",
            String::from_utf8_lossy(&made.stderr)
        );

        let path = dir.path().join("switch.csr");
        let asked = read_request(path.to_string_lossy().into_owned()).unwrap();
        assert_eq!(asked.names, ["switch.example", "192.0.2.7"]);
    }
}
