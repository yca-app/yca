//! Issuing a certificate from the window: PIN, touch, register, and the
//! files for the device, which go into the certificate's folder in the
//! workspace.

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};
use time::{Duration, OffsetDateTime};
use yca_core::device::{self, CaRole};
use yca_core::{
    Authority, CertificateFolder, Error, ExportFile, ExportForm, ExportSource, IssuedCertificate,
    KeyPair, LeafProfile, LeafRequest, P12Encryption, P12Options, PKCS_ECDSA_P256_SHA256,
    PKCS_RSA_SHA256, RsaKeySize, Store, YubiKeySigner,
};
use zeroize::Zeroizing;

use crate::{KeyLock, role_name, timestamp};

/// Sent to the window once the YubiKey has accepted the PIN and is
/// waiting to be touched. Carries the serial number of that YubiKey.
pub(crate) const TOUCH_EVENT: &str = "yca://touch";

/// What the window asks for.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueRequest {
    pki_path: String,
    profile: LeafProfile,
    names: Vec<String>,
    /// What the upload form of the device asks for, which decides the
    /// files that are written.
    files: ExportForm,
    /// Password for the `.p12` file, where everything goes into one.
    p12_password: Option<String>,
    /// For a device that cannot handle a certificate chain.
    sign_with_root: bool,
    /// Expire after this many days instead of as late as possible.
    #[serde(default)]
    days: Option<u32>,
    /// The kind of key the certificate gets.
    #[serde(default)]
    key: KeyKind,
    /// Encrypt the `.p12` file the way older systems need it.
    #[serde(default)]
    p12_compatible: bool,
    /// The group to sort the certificate into, if any.
    #[serde(default)]
    group: Option<String>,
    pin: String,
}

/// The kind of private key made for a new certificate.
#[derive(Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
enum KeyKind {
    /// RSA 2048: what every device can use.
    #[default]
    Rsa,
    /// ECC P-256.
    Ecdsa,
}

/// A request that expires after `days`, if a number of days was asked
/// for, and otherwise as late as its profile and its CA allow.
pub(crate) fn limited(request: LeafRequest, days: Option<u32>) -> Result<LeafRequest, Error> {
    match days {
        Some(days) => request.valid_for(Duration::days(days.into())),
        None => Ok(request),
    }
}

/// What the window gets back.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Issued {
    pub(crate) serial: String,
    pub(crate) not_after: String,
    /// The certificate's folder in the workspace, where its files are.
    pub(crate) folder: String,
    pub(crate) files: Vec<FileView>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FileView {
    pub(crate) name: String,
    pub(crate) holds_private_key: bool,
}

impl FileView {
    pub(crate) fn of(file: ExportFile) -> Self {
        FileView {
            name: file.name,
            holds_private_key: file.holds_private_key,
        }
    }
}

/// Why nothing was issued, in a form the window can explain and react to.
#[derive(Debug, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum Failure {
    /// The PIN was wrong; one attempt is used up. `serial` says which
    /// YubiKey refused, where more than one was asked for its PIN.
    WrongPin {
        attempts_left: u8,
        serial: Option<u32>,
    },
    /// Too many wrong PINs; the key needs its PUK.
    PinLocked { serial: Option<u32> },
    /// One attempt is left and the app will not gamble with it.
    LastAttempt { serial: Option<u32> },
    /// The PUK was wrong; one of its attempts is used up, and nothing
    /// unblocks a PUK.
    WrongPuk { attempts_left: u8 },
    /// Too many wrong PUKs: only resetting the YubiKey is left.
    PukLocked,
    /// The YubiKey was not touched in time.
    NotTouched,
    /// The YubiKey with the CA that has to sign is not connected.
    KeyMissing { role: &'static str },
    /// The password does not open the `.p12` file a private key is in.
    WrongPassword,
    /// A new CA key was generated, replacing what the slot held, but the
    /// CA was not finished. Trying again has to replace that key.
    /// `not_touched` says that what it lacked was the touch for its
    /// signature, so the window can name the YubiKey that waited for it.
    Interrupted { message: String, not_touched: bool },
    /// Anything else, in words.
    Other { message: String },
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        match error {
            Error::WrongPin { attempts_left } => Failure::WrongPin {
                attempts_left,
                serial: None,
            },
            Error::PinLocked => Failure::PinLocked { serial: None },
            Error::WrongPuk { attempts_left } => Failure::WrongPuk { attempts_left },
            Error::PukLocked => Failure::PukLocked,
            Error::NotTouched => Failure::NotTouched,
            Error::WrongP12Password => Failure::WrongPassword,
            Error::SetupInterrupted(cause) => Failure::Interrupted {
                message: cause.to_string(),
                not_touched: matches!(*cause, Error::NotTouched),
            },
            other => Failure::Other {
                message: other.to_string(),
            },
        }
    }
}

impl Failure {
    /// Names the YubiKey whose PIN this is about. For a step that asks
    /// for the PINs of two keys, where "wrong PIN" alone says too little.
    pub(crate) fn on_key(self, key: u32) -> Self {
        let serial = Some(key);
        match self {
            Failure::WrongPin { attempts_left, .. } => Failure::WrongPin {
                attempts_left,
                serial,
            },
            Failure::PinLocked { .. } => Failure::PinLocked { serial },
            Failure::LastAttempt { .. } => Failure::LastAttempt { serial },
            other => other,
        }
    }
}

pub(crate) fn other(message: impl ToString) -> Failure {
    Failure::Other {
        message: message.to_string(),
    }
}

/// Issues a certificate with the CA on a connected YubiKey, enters it
/// into the register and writes the files for where it is going.
#[tauri::command]
pub async fn issue_certificate(app: AppHandle, request: IssueRequest) -> Result<Issued, Failure> {
    // Signing waits for a touch, which must not freeze the window.
    tauri::async_runtime::spawn_blocking(move || issue(&app, request))
        .await
        .map_err(other)?
}

fn issue(app: &AppHandle, request: IssueRequest) -> Result<Issued, Failure> {
    let pin = Zeroizing::new(request.pin);
    let password = request.p12_password.map(Zeroizing::new);

    // Nothing else may talk to the YubiKey between the PIN and the
    // signature, or the key forgets that the PIN was given.
    let lock = app.state::<KeyLock>();
    let _signing = lock.wait();

    let mut store = Store::open(&request.pki_path)?;
    // A workspace kept on one YubiKey has no issuing CA: its root signs.
    let role = if request.sign_with_root {
        CaRole::Root
    } else {
        store.everyday_ca()
    };
    let leaf_request = limited(
        LeafRequest::for_profile(request.profile, &request.names)?,
        request.days,
    )?;
    let first_name = leaf_request.names()[0].clone();

    // Everything that can go wrong without the YubiKey is settled before
    // it signs, so a certificate is never issued and then lost.
    let password = match (request.files, &password) {
        (ExportForm::Pkcs12, Some(password)) if !password.is_empty() => Some(password.as_str()),
        (ExportForm::Pkcs12, _) => return Err(other("a .p12 file needs a password")),
        _ => None,
    };
    let folder = store.new_certificate_folder(&first_name, request.group.as_deref())?;

    let authority = open_ca(app, &store, role, pin)?;
    let key = match request.key {
        KeyKind::Rsa => KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048),
        KeyKind::Ecdsa => KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256),
    }
    .map_err(other)?;
    let now = OffsetDateTime::now_utc();
    let issued = sign(&authority, |ca| ca.issue(&leaf_request, &key, now))?;
    store.record_in(&folder, &issued, &leaf_request, role, None, now)?;

    let key_der = Zeroizing::new(key.serialize_der());
    let files = yca_core::export(
        request.files,
        ExportSource {
            issued: &issued,
            private_key_der: Some(&key_der),
        },
        password.map(|password| P12Options {
            password,
            encryption: match request.p12_compatible {
                true => P12Encryption::Compatible,
                false => P12Encryption::Modern,
            },
            label: &first_name,
        }),
    )?;
    filled(&folder, &issued, files)
}

/// Puts the files for the device into the certificate's folder and tells
/// the window what is there now: those files and nothing else.
pub(crate) fn filled(
    folder: &CertificateFolder,
    issued: &IssuedCertificate,
    files: Vec<ExportFile>,
) -> Result<Issued, Failure> {
    for file in &files {
        folder.write(file)?;
    }
    let views = files.into_iter().map(FileView::of).collect();
    Ok(Issued {
        serial: issued.serial()?,
        not_after: timestamp(issued.not_after()),
        folder: folder.path().to_string_lossy().into_owned(),
        files: views,
    })
}

/// Opens the CA of `role` on its YubiKey with the PIN, after making sure
/// that the key is the one this workspace knows and that a wrong PIN would
/// not lock it. Tells the window when the key is about to wait for a touch.
pub(crate) fn open_ca(
    app: &AppHandle,
    store: &Store,
    role: CaRole,
    pin: Zeroizing<String>,
) -> Result<Authority<YubiKeySigner>, Failure> {
    let (authority, serial) = open_ca_quietly(store, role, pin)?;
    if authority.key().touch_required() {
        // The window shows "touch your YubiKey" on this.
        let _ = app.emit(TOUCH_EVENT, serial);
    }
    Ok(authority)
}

/// The same without a word to the window, for a CA that signs only after
/// something else is done first: the touch is then asked for when its turn
/// comes. Returns the serial number of its YubiKey as well.
pub(crate) fn open_ca_quietly(
    store: &Store,
    role: CaRole,
    pin: Zeroizing<String>,
) -> Result<(Authority<YubiKeySigner>, u32), Failure> {
    let expected = store
        .ca(role)
        .ok_or_else(|| other(format!("this workspace has no {role} yet")))?
        .yubikey;
    let found = device::list_devices()?;
    let device = found
        .select_ca(role, Some(expected))
        .map_err(|_| Failure::KeyMissing {
            role: role_name(role),
        })?;
    let on_key = device
        .ca
        .as_ref()
        .expect("select_ca returns a key with a CA");
    if on_key.certificate_der != store.ca_certificate_der(role)? {
        return Err(other(format!(
            "YubiKey {} holds a different {role} than this workspace",
            device.serial
        )));
    }
    if on_key
        .key
        .as_ref()
        .is_some_and(|key| !key.matches_certificate)
    {
        return Err(other(
            "the key on this YubiKey does not belong to its CA certificate",
        ));
    }
    match device.pin_attempts_left {
        0 => return Err(Failure::PinLocked { serial: None }),
        1 => return Err(Failure::LastAttempt { serial: None }),
        _ => {}
    }

    let authority = Authority::open_on_yubikey(device.serial, &pin)?;
    Ok((authority, device.serial))
}

/// Has the YubiKey sign something and reports what the key itself said
/// went wrong, such as a touch that never came.
pub(crate) fn sign<T>(
    authority: &Authority<YubiKeySigner>,
    signing: impl FnOnce(&Authority<YubiKeySigner>) -> Result<T, Error>,
) -> Result<T, Failure> {
    signing(authority).map_err(|e| authority.key().take_last_error().unwrap_or(e).into())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::fixtures::key;

    fn asked(extra: serde_json::Value) -> IssueRequest {
        let mut request = json!({
            "pkiPath": "/nowhere",
            "profile": "ipsec-client",
            "names": ["alice@example.com"],
            "files": "p12",
            "p12Password": "secret",
            "signWithRoot": false,
            "pin": "123456",
        });
        for (name, value) in extra.as_object().unwrap() {
            request[name] = value.clone();
        }
        serde_json::from_value(request).unwrap()
    }

    #[test]
    fn options_the_window_leaves_alone_are_the_usual_ones() {
        let usual = asked(json!({}));
        assert_eq!(usual.days, None);
        assert!(usual.key == KeyKind::Rsa);
        assert!(!usual.p12_compatible);

        let chosen = asked(json!({ "days": 365, "key": "ecdsa", "p12Compatible": true }));
        assert_eq!(chosen.days, Some(365));
        assert!(chosen.key == KeyKind::Ecdsa);
        assert!(chosen.p12_compatible);
    }

    #[test]
    fn a_number_of_days_makes_the_certificate_expire_sooner() {
        let at = OffsetDateTime::now_utc();
        let root = Authority::create_root("Test Root CA", key(), at).unwrap();
        let request = || LeafRequest::ipsec_client("alice@example.com").unwrap();

        let longest = root
            .issue(&limited(request(), None).unwrap(), &key(), at)
            .unwrap();
        assert_eq!(longest.not_after(), root.not_after());

        let year = root
            .issue(&limited(request(), Some(365)).unwrap(), &key(), at)
            .unwrap();
        let length = year.not_after() - at;
        assert!(
            length > Duration::days(364) && length <= Duration::days(365),
            "{length}"
        );

        assert!(limited(request(), Some(0)).is_err());
    }
}
