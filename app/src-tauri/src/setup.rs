//! Creating a certificate authority from the window: a root CA on one
//! YubiKey and an issuing CA, signed by that root, on another. Or, for
//! someone with a single YubiKey, the root CA alone, which then signs
//! every certificate itself, until an issuing CA is added on a second
//! YubiKey after all.
//!
//! And what a YubiKey's own PIN may need: a PIN and PUK in place of the
//! factory ones, another PIN, a new PIN by way of the PUK, and, when all
//! is lost or to start over, a reset.
//!
//! These are the only commands of the app that write to a YubiKey. They
//! write what the core writes and nothing else: slot 9c, the PIN, PUK and
//! management key of a key that still has its factory ones, and a PIN on
//! request. The reset is the one that goes further: it wipes the whole
//! PIV application of the key, and nothing outside it.

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};
use time::OffsetDateTime;
use yca_core::device::{self, CaRole};
use yca_core::{
    Authority, CaKeyType, Error, NewCa, Store, YubiKeySigner, change_pin, protect_yubikey,
    reset_piv, unblock_pin,
};
use zeroize::Zeroizing;

use crate::adopt::keep_attestation;
use crate::issue::{Failure, TOUCH_EVENT, open_ca_quietly, other};
use crate::{KeyLock, PkiView, pki_view, timestamp};

/// One YubiKey and the CA it is to get.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeySetup {
    serial: u32,
    /// Name of the CA to create; becomes its common name.
    name: String,
    /// The PIN of the key. For a key that still has its factory PIN, the
    /// PIN it is to get instead.
    pin: String,
    /// The PUK a key with its factory PIN is to get.
    new_puk: Option<String>,
    /// Destroy what slot 9c holds now and put the new CA there.
    replace: bool,
}

/// A root CA that now exists on its YubiKey.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RootCreated {
    not_after: String,
}

/// Creates a root CA on a YubiKey: the key is generated inside it and
/// signs its own certificate, which waits for a touch.
#[tauri::command]
pub async fn create_root(app: AppHandle, key: KeySetup) -> Result<RootCreated, Failure> {
    tauri::async_runtime::spawn_blocking(move || root(&app, key))
        .await
        .map_err(other)?
}

fn root(app: &AppHandle, key: KeySetup) -> Result<RootCreated, Failure> {
    let lock = app.state::<KeyLock>();
    let _keys = lock.wait();

    let authority = make_root(app, &key)?;
    Ok(RootCreated {
        not_after: timestamp(authority.not_after()),
    })
}

fn make_root(app: &AppHandle, key: &KeySetup) -> Result<Authority<YubiKeySigner>, Failure> {
    let pin = ready_key(key)?;
    let (authority, _) = Authority::create_root_on_yubikey(
        key.serial,
        &pin,
        &new_ca(key),
        OffsetDateTime::now_utc(),
        // The new key signs its own certificate, and for that it wants a
        // touch: said when it starts to blink, not while it is being made.
        || {
            let _ = app.emit(TOUCH_EVENT, key.serial);
        },
    )?;
    Ok(authority)
}

/// What the window asks for when one YubiKey is to hold the whole
/// certificate authority.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootAloneSetup {
    key: KeySetup,
    /// Where the workspace folder of the new CA goes.
    workspace_path: String,
}

/// Creates a root CA on a YubiKey and starts a workspace folder with
/// nothing but that root, which signs every certificate itself. For
/// someone who has one YubiKey, or wants to use only one.
#[tauri::command]
pub async fn create_root_alone(
    app: AppHandle,
    request: RootAloneSetup,
) -> Result<PkiView, Failure> {
    tauri::async_runtime::spawn_blocking(move || root_alone(&app, request))
        .await
        .map_err(other)?
}

fn root_alone(app: &AppHandle, request: RootAloneSetup) -> Result<PkiView, Failure> {
    let lock = app.state::<KeyLock>();
    let _keys = lock.wait();

    // Settled before anything is written to the YubiKey.
    if Store::exists(&request.workspace_path) {
        return Err(other(
            "this folder already is a workspace; choose another place",
        ));
    }
    let root = make_root(app, &request.key)?;

    let store = Store::create(
        &request.workspace_path,
        root.certificate_der(),
        request.key.serial,
    )
    .map_err(folder_failed)?;
    keep_attestation(&store, CaRole::Root, request.key.serial);
    pki_view(&store).map_err(other)
}

/// What the window asks for when the issuing CA is to be created.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuingSetup {
    /// The YubiKey with the root CA, which signs the new issuing CA.
    root_serial: u32,
    root_pin: String,
    key: KeySetup,
    /// Where the workspace folder of the new CA goes.
    workspace_path: String,
}

/// Creates the issuing CA on a second YubiKey, signed by the root CA on
/// the first, and starts the workspace folder that keeps track of both.
#[tauri::command]
pub async fn create_issuing(app: AppHandle, request: IssuingSetup) -> Result<PkiView, Failure> {
    tauri::async_runtime::spawn_blocking(move || issuing(&app, request))
        .await
        .map_err(other)?
}

fn issuing(app: &AppHandle, request: IssuingSetup) -> Result<PkiView, Failure> {
    let lock = app.state::<KeyLock>();
    let _keys = lock.wait();

    // Everything that can be wrong without writing comes first.
    if request.root_serial == request.key.serial {
        return Err(other("the root CA and the issuing CA need a YubiKey each"));
    }
    if Store::exists(&request.workspace_path) {
        return Err(other(
            "this folder already is a workspace; choose another place",
        ));
    }
    let root_pin = Zeroizing::new(request.root_pin);
    let root = Authority::open_on_yubikey(request.root_serial, &root_pin)?;
    if !root.is_root() {
        return Err(other(format!(
            "YubiKey {} does not hold a root CA",
            request.root_serial
        )));
    }

    let issuing = make_issuing(app, &root, request.root_serial, &request.key)?;

    let mut store = Store::create(
        &request.workspace_path,
        root.certificate_der(),
        request.root_serial,
    )
    .map_err(folder_failed)?;
    store
        .set_issuing(issuing.certificate_der(), request.key.serial)
        .map_err(folder_failed)?;
    keep_attestation(&store, CaRole::Root, request.root_serial);
    keep_attestation(&store, CaRole::Issuing, request.key.serial);
    pki_view(&store).map_err(other)
}

/// Creates an issuing CA on its YubiKey and has the root CA, on the
/// other one, sign it.
fn make_issuing(
    app: &AppHandle,
    root: &Authority<YubiKeySigner>,
    root_serial: u32,
    key: &KeySetup,
) -> Result<Authority<YubiKeySigner>, Failure> {
    let pin = ready_key(key)?;
    let (issuing, _) = Authority::create_issuing_on_yubikey(
        root,
        key.serial,
        &pin,
        &new_ca(key),
        OffsetDateTime::now_utc(),
        // The root signs the new CA, so it is the root's key that blinks
        // and wants the touch. Said only once it does: while the new key
        // is being made, the other YubiKey flickers, and a window that
        // asked for a touch by then would have that one touched.
        || {
            if root.key().touch_required() {
                let _ = app.emit(TOUCH_EVENT, root_serial);
            }
        },
    )
    .map_err(|e| match (e, root.key().take_last_error()) {
        // The new key exists by now; say why the root did not sign.
        (yca_core::Error::SetupInterrupted(_), Some(cause)) => {
            yca_core::Error::SetupInterrupted(Box::new(cause))
        }
        (e, _) => e,
    })?;
    Ok(issuing)
}

/// What the window asks for when an open workspace is to get a new issuing
/// CA: its first, where the root CA has signed everything so far, or one
/// in place of the issuing CA it has.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuingAddition {
    workspace_path: String,
    /// PIN of the YubiKey with the workspace's root CA, which signs.
    root_pin: String,
    key: KeySetup,
    /// The workspace has an issuing CA, and this one is to take its place.
    /// Said outright, so that a window that is behind the folder cannot
    /// replace an issuing CA it does not know of.
    #[serde(default)]
    replacing: bool,
    /// Have the root CA revoke the replaced issuing CA: for a YubiKey that
    /// was stolen rather than lost or broken.
    #[serde(default)]
    revoke_replaced: bool,
}

/// Creates an issuing CA on another YubiKey, signed by the root CA of an
/// existing workspace, and enters it there: as the first issuing CA of a
/// workspace whose root signed everything so far, or in place of the one
/// it has. From then on the new issuing CA signs from day to day; what was
/// issued before stays valid.
#[tauri::command]
pub async fn add_issuing(app: AppHandle, request: IssuingAddition) -> Result<PkiView, Failure> {
    tauri::async_runtime::spawn_blocking(move || added_issuing(&app, request))
        .await
        .map_err(other)?
}

fn added_issuing(app: &AppHandle, request: IssuingAddition) -> Result<PkiView, Failure> {
    let lock = app.state::<KeyLock>();
    let _keys = lock.wait();

    // Everything that can be wrong without writing comes first.
    let mut store = Store::open(&request.workspace_path)?;
    match (store.ca(CaRole::Issuing).is_some(), request.replacing) {
        (true, false) => return Err(other("this workspace already has an issuing CA")),
        (false, true) => return Err(other("this workspace has no issuing CA to replace")),
        _ => {}
    }
    let root_serial = store
        .ca(CaRole::Root)
        .ok_or_else(|| other("the workspace folder has no root CA"))?
        .yubikey;
    let new_serial = request.key.serial;
    if root_serial == new_serial {
        return Err(other(
            "the issuing CA needs a YubiKey of its own, not the one with the root CA",
        ));
    }
    // Two PINs are asked for here, so a refused one names its YubiKey.
    // Opened without a word to the window: the root signs last, once the
    // new key is made, and only then wants its touch.
    let (root, _) = open_ca_quietly(&store, CaRole::Root, Zeroizing::new(request.root_pin))
        .map_err(|failure| failure.on_key(root_serial))?;

    let issuing = make_issuing(app, &root, root_serial, &request.key)
        .map_err(|failure| failure.on_key(new_serial))?;

    let retired_before = store.retired().len();
    store
        .set_issuing(issuing.certificate_der(), new_serial)
        .map_err(|e| {
            // The sidebar offers a connected issuing CA of this root.
            other(format!(
                "the issuing CA was created on its YubiKey, but could not be entered into the \
                 workspace: {e}. Cancel; the sidebar offers to use it as the issuing CA"
            ))
        })?;
    keep_attestation(&store, CaRole::Issuing, new_serial);
    if request.revoke_replaced
        && let Some(old) = store.retired().get(retired_before).cloned()
    {
        store
            .revoke_retired(&old.serial, OffsetDateTime::now_utc())
            .map_err(|e| {
                other(format!(
                    "the new issuing CA is in place, but the old one could not be marked as \
                     revoked: {e}"
                ))
            })?;
    }
    pki_view(&store).map_err(other)
}

/// What the window asks for when a YubiKey is to get a PIN of its own.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Protection {
    serial: u32,
    new_pin: String,
    new_puk: String,
}

/// Replaces the factory PIN and PUK of a YubiKey with the user's own, and
/// its factory management key with a random one kept on the key behind
/// the PIN. Keys and certificates are left alone: a CA that is there keeps
/// working, with the new PIN.
#[tauri::command]
pub async fn protect_key(app: AppHandle, request: Protection) -> Result<(), Failure> {
    tauri::async_runtime::spawn_blocking(move || {
        let lock = app.state::<KeyLock>();
        let _keys = lock.wait();
        let pin = Zeroizing::new(request.new_pin);
        let puk = Zeroizing::new(request.new_puk);
        protect_yubikey(request.serial, &pin, &puk)?;
        Ok(())
    })
    .await
    .map_err(other)?
}

/// What the window asks for when a YubiKey's PIN is to be changed.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PinChange {
    serial: u32,
    current_pin: String,
    new_pin: String,
}

/// Changes the PIN of a YubiKey; the CA on it keeps working, with the
/// new one. A wrong current PIN costs one of the key's attempts.
#[tauri::command]
pub async fn change_key_pin(app: AppHandle, request: PinChange) -> Result<(), Failure> {
    with_keys(app, move || {
        let current = Zeroizing::new(request.current_pin);
        let new = Zeroizing::new(request.new_pin);
        change_pin(request.serial, &current, &new)
    })
    .await
}

/// What the window asks for when a PIN is to be set anew with the PUK.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PinUnblock {
    serial: u32,
    puk: String,
    new_pin: String,
}

/// Sets a new PIN with the PUK, for a PIN that is forgotten or locked. A
/// wrong PUK costs one of the PUK's attempts.
#[tauri::command]
pub async fn unblock_key_pin(app: AppHandle, request: PinUnblock) -> Result<(), Failure> {
    with_keys(app, move || {
        let puk = Zeroizing::new(request.puk);
        let new = Zeroizing::new(request.new_pin);
        unblock_pin(request.serial, &puk, &new)
    })
    .await
}

/// Resets the PIV application of a YubiKey to its factory state: every
/// PIV key and certificate on it is destroyed, the CA included. Needs
/// neither PIN nor PUK; the window has its user type the serial number.
#[tauri::command]
pub async fn reset_key(app: AppHandle, serial: u32) -> Result<(), Failure> {
    with_keys(app, move || reset_piv(serial)).await
}

/// Runs something that talks to a YubiKey while nothing else does, and
/// off the thread the window lives on.
async fn with_keys(
    app: AppHandle,
    work: impl FnOnce() -> Result<(), Error> + Send + 'static,
) -> Result<(), Failure> {
    tauri::async_runtime::spawn_blocking(move || {
        let lock = app.state::<KeyLock>();
        let _keys = lock.wait();
        Ok(work()?)
    })
    .await
    .map_err(other)?
}

/// The CA is on its YubiKey by now and only the folder is missing. That
/// is not a setup to run again: the start screen makes a workspace from
/// the CAs the connected YubiKeys hold.
fn folder_failed(error: yca_core::Error) -> Failure {
    other(format!(
        "the CA was created on its YubiKey, but the workspace folder could not be made: {error}. \
         Cancel and start from the connected YubiKeys instead; they hold the new CA"
    ))
}

/// Makes sure the YubiKey is connected and fit to get a CA, gives a key
/// that still has its factory PIN the PIN and PUK chosen for it, and
/// returns the PIN to go on with.
fn ready_key(key: &KeySetup) -> Result<Zeroizing<String>, Failure> {
    let pin = Zeroizing::new(key.pin.clone());
    let found = device::list_devices()?;
    let device = found
        .usable
        .iter()
        .find(|device| device.serial == key.serial)
        .ok_or_else(|| other(format!("YubiKey {} is not connected", key.serial)))?;

    if device.factory.pin == Some(true) {
        // A CA behind the PIN every YubiKey ships with protects nothing.
        let puk = key
            .new_puk
            .as_deref()
            .ok_or_else(|| other("a new YubiKey needs a PUK as well as a PIN"))?;
        protect_yubikey(key.serial, &pin, puk)?;
    } else {
        match device.pin_attempts_left {
            0 => return Err(Failure::PinLocked { serial: None }),
            1 => return Err(Failure::LastAttempt { serial: None }),
            _ => {}
        }
    }
    Ok(pin)
}

fn new_ca(key: &KeySetup) -> NewCa<'_> {
    NewCa {
        name: key.name.trim(),
        key_type: CaKeyType::default(),
        replace_existing: key.replace,
    }
}
