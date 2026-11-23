//! Starting a PKI folder from CAs that already live on YubiKeys.
//!
//! Adoption only reads the YubiKeys and needs no PIN: it copies the CA
//! certificates into a new folder so the app has somewhere to keep track
//! of what those CAs issue.

use yca_core::Store;
use yca_core::device::{self, CaRole, Devices};

use crate::{KeyLock, PkiView, pki_view};

/// Starts a PKI folder at `path` from the root CA on a connected YubiKey,
/// and takes along the issuing CA if its YubiKey is connected too.
#[tauri::command(async)]
pub fn adopt_pki(lock: tauri::State<'_, KeyLock>, path: String) -> Result<PkiView, String> {
    let _keys = lock.wait();
    if Store::exists(&path) {
        return Err("this folder already is a workspace; open it instead".to_owned());
    }
    Store::can_start_in(&path).map_err(|e| e.to_string())?;
    let found = device::list_devices().map_err(|e| e.to_string())?;
    let device = found
        .select_ca(CaRole::Root, None)
        .map_err(|e| e.to_string())?;
    // A CA that could not be signed with is not worth a workspace.
    device.require_new_enough().map_err(|e| e.to_string())?;
    let ca = device
        .ca
        .as_ref()
        .expect("select_ca returns a key with a CA");

    let mut store =
        Store::create(&path, &ca.certificate_der, device.serial).map_err(|e| e.to_string())?;
    keep_attestation(&store, CaRole::Root, device.serial);
    add_connected_issuing(&mut store, &found);
    pki_view(&store)
}

/// Adds the issuing CA on the YubiKey with this serial number to a
/// workspace that has none. The window names the YubiKey it offered, so
/// what is taken is what the person saw, not whichever key happens to be
/// connected by now.
#[tauri::command(async)]
pub fn adopt_issuing(
    lock: tauri::State<'_, KeyLock>,
    path: String,
    serial: u32,
) -> Result<PkiView, String> {
    let _keys = lock.wait();
    let mut store = Store::open(&path).map_err(|e| e.to_string())?;
    if store.ca(CaRole::Issuing).is_some() {
        return Err(
            "this workspace has an issuing CA by now: another program gave it one. Look at \
             the workspace again"
                .to_owned(),
        );
    }
    let found = device::list_devices().map_err(|e| e.to_string())?;
    let device = found
        .select_ca(CaRole::Issuing, Some(serial))
        .map_err(|e| e.to_string())?;
    device.require_new_enough().map_err(|e| e.to_string())?;
    let ca = device
        .ca
        .as_ref()
        .expect("select_ca returns a key with a CA");
    // The store itself checks the signature against its root.
    store
        .set_issuing(&ca.certificate_der, device.serial)
        .map_err(|e| e.to_string())?;
    keep_attestation(&store, CaRole::Issuing, device.serial);
    pki_view(&store)
}

/// Takes the issuing CA from whichever connected YubiKey holds one that
/// this PKI's root signed. A YubiKey with the issuing CA of some other
/// PKI is passed over. Returns whether one was added.
fn add_connected_issuing(store: &mut Store, found: &Devices) -> bool {
    for device in &found.usable {
        let Some(ca) = &device.ca else { continue };
        if ca.role != CaRole::Issuing || !device.describes_its_keys {
            continue;
        }
        // The store itself checks the signature against its root.
        if store
            .set_issuing(&ca.certificate_der, device.serial)
            .is_ok()
        {
            keep_attestation(store, CaRole::Issuing, device.serial);
            return true;
        }
    }
    false
}

/// Keeps the YubiKey's proof that the CA key was generated inside it,
/// where there is one. A key that was imported, or firmware that cannot
/// attest, is no reason to refuse the CA.
pub(crate) fn keep_attestation(store: &Store, role: CaRole, serial: u32) {
    if let Ok(Some(attestation)) = yca_core::attest_ca_on_yubikey(serial) {
        let _ = store.save_attestation(role, &attestation);
    }
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;
    use yca_core::Authority;

    use super::*;
    use crate::fixtures::{key, yubikey};

    #[test]
    fn only_an_issuing_ca_of_this_pki_is_taken_along() {
        let at = OffsetDateTime::now_utc();
        let root = Authority::create_root("Root", key(), at).unwrap();
        let issuing = root.create_issuing("Issuing", key(), at).unwrap();
        let other_root = Authority::create_root("Other Root", key(), at).unwrap();
        let other_issuing = other_root
            .create_issuing("Other Issuing", key(), at)
            .unwrap();
        // Serial numbers no real YubiKey has, so nothing is ever asked of one.
        let (stranger, ours) = (4_000_000_001, 4_000_000_002);

        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::create(dir.path().join("pki"), root.certificate_der(), 1).unwrap();

        // Someone else's issuing CA, and a root, are passed over.
        let unrelated = Devices {
            usable: vec![
                yubikey(stranger, CaRole::Issuing, &other_issuing),
                yubikey(1, CaRole::Root, &root),
            ],
            unusable: Vec::new(),
        };
        assert!(!add_connected_issuing(&mut store, &unrelated));
        assert!(store.ca(CaRole::Issuing).is_none());

        // The one this root signed is found even behind the stranger.
        let both = Devices {
            usable: vec![
                yubikey(stranger, CaRole::Issuing, &other_issuing),
                yubikey(ours, CaRole::Issuing, &issuing),
            ],
            unusable: Vec::new(),
        };
        assert!(add_connected_issuing(&mut store, &both));
        assert_eq!(store.ca(CaRole::Issuing).unwrap().yubikey, ours);
        assert_eq!(
            store.ca_certificate_der(CaRole::Issuing).unwrap(),
            issuing.certificate_der()
        );
    }
}
