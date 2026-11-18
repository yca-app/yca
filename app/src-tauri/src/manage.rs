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
    ExportForm, ExportSource, LeafProfile, LeafRequest, P12Encryption, Repack, SigningRequest,
    Store,
};
use zeroize::Zeroizing;

use crate::issue::{Failure, FileView, Issued, filled, limited, open_ca, other, sign};
use crate::{KeyLock, PkiView, pki_view, timestamp};

/// What the window asks for when a certificate is to be issued again.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReissueRequest {
    pki_path: String,
    /// Serial number of the certificate to replace.
    serial: String,
    /// The new names; empty keeps the names as they are.
    names: Vec<String>,
    /// Mark the replaced certificate as revoked.
    revoke_old: bool,
    /// Expire after this many days instead of as late as possible.
    #[serde(default)]
    days: Option<u32>,
    pin: String,
}

/// Issues a new certificate for the key of an existing one, to change its
/// names or to renew it. The private key stays on the device; only the new
/// certificate has to be installed there.
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
    let lock = app.state::<KeyLock>();
    let _signing = lock.wait();

    let mut store = Store::open(&request.pki_path)?;
    let old = store.find(&request.serial)?.clone();
    let previous = store.certificate_der(&old)?;
    let names = if request.names.is_empty() {
        old.names.clone()
    } else {
        request.names
    };
    let leaf_request = limited(LeafRequest::for_profile(old.profile, &names)?, request.days)?;
    // The new certificate stays in the group of the one it replaces.
    let folder = store.new_certificate_folder(&leaf_request.names()[0], old.group.as_deref())?;

    // The CA that signed the old certificate signs the new one.
    let authority = open_ca(app, &store, old.issued_by, pin)?;
    let now = OffsetDateTime::now_utc();
    let issued = sign(&authority, |ca| ca.reissue(&leaf_request, &previous, now))?;
    store.record_in(
        &folder,
        &issued,
        &leaf_request,
        old.issued_by,
        Some(&old.serial),
        now,
    )?;
    // A certificate that has expired is no longer anyone's to revoke, and
    // one of a replaced issuing CA cannot be revoked on its own.
    if request.revoke_old
        && old.revoked_at.is_none()
        && now < old.not_after
        && store.retired_issuer(&old).is_none()
    {
        store.revoke(&old.serial, now)?;
    }

    // No private key: it never left the device the certificate is for.
    // The files come in the form the old ones are in, as far as that can
    // be had without the key.
    let form = match store.form(&old) {
        Some(ExportForm::Separate) => ExportForm::Separate,
        Some(ExportForm::Fullchain | ExportForm::Pkcs12) | None => ExportForm::Fullchain,
    };
    let files = yca_core::export(
        form,
        ExportSource {
            issued: &issued,
            private_key_der: None,
        },
        None,
    )?;
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

    let authority = open_ca(app, &store, role, pin)?;
    let now = OffsetDateTime::now_utc();
    let issued = sign(&authority, |ca| {
        ca.sign_request(&leaf_request, &signing_request, now)
    })?;
    store.record_in(&folder, &issued, &leaf_request, role, None, now)?;

    // No private key: the device made it and keeps it.
    let files = yca_core::export(
        request.files,
        ExportSource {
            issued: &issued,
            private_key_der: None,
        },
        None,
    )?;
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

    let authority = open_ca(app, &store, role, pin)?;
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
