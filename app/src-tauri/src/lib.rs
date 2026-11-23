//! The desktop app: a window over `yca-core`.
//!
//! Everything the window can ask for is a command in this file. The
//! commands only translate between the core's types and plain data the
//! window understands; decisions stay in the core.

mod adopt;
#[cfg(unix)]
mod agent;
mod issue;
mod manage;
mod setup;
mod update;
mod window;

use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use tauri::Manager;
use yca_core::Store;
use yca_core::device;
use yca_core::view::{self, DevicesView};
pub(crate) use yca_core::view::{PkiView, role_name, timestamp};

/// Held by whichever command is talking to the YubiKeys.
///
/// A YubiKey forgets that the PIN was given as soon as anything else
/// talks to it, so nothing may look at the keys between the PIN and the
/// signature.
pub(crate) struct KeyLock(pub(crate) Mutex<()>);

impl KeyLock {
    /// Waits until no other command is talking to the YubiKeys and keeps
    /// them for the caller until the guard is dropped.
    ///
    /// The window looks at the keys every few seconds, and again whenever
    /// it comes back to the front, so a command that gave up instead of
    /// waiting would fail whenever it ran into such a look.
    pub(crate) fn wait(&self) -> MutexGuard<'_, ()> {
        // The lock guards no data; one left behind by a panic is as good
        // as any other.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The connected YubiKeys. Reads only and needs no PIN.
///
/// With a PKI folder open, `pki_path` names it, and each issuing CA is
/// checked against that PKI's root; otherwise against the root CA on a
/// connected YubiKey, if there is exactly one.
///
/// Fails with `busy` while another command has the keys, rather than
/// queue up behind a signature; the window then keeps showing what it
/// knew before.
#[tauri::command(async)]
fn devices(
    lock: tauri::State<'_, KeyLock>,
    pki_path: Option<String>,
) -> Result<DevicesView, String> {
    let Ok(_idle) = lock.0.try_lock() else {
        return Err("busy".to_owned());
    };
    let found = device::list_devices().map_err(|e| e.to_string())?;
    Ok(view::devices(found, pki_path.as_deref().map(Path::new)))
}

/// The contents of a PKI folder: its CAs and every certificate issued.
#[tauri::command(async)]
fn open_pki(path: String) -> Result<PkiView, String> {
    let store = Store::open(&path).map_err(|e| e.to_string())?;
    pki_view(&store)
}

/// Something that changes whenever anything writes the workspace: the
/// window itself, the command line, an agent. The window asks every second
/// and looks at the workspace again when the answer has changed, so what
/// another program does shows up without anyone reloading. `None` if the
/// folder is gone.
#[tauri::command(async)]
fn workspace_stamp(path: String) -> Option<String> {
    Store::stamp(path)
}

/// Where the root CA certificate is as a file to install on devices that
/// are to trust this CA; written first if the workspace has none yet.
#[tauri::command(async)]
fn root_for_devices(path: String) -> Result<String, String> {
    let store = Store::open(&path).map_err(|e| e.to_string())?;
    let file = store.root_for_devices().map_err(|e| e.to_string())?;
    Ok(file.to_string_lossy().into_owned())
}

/// A workspace as the window shows it, or why it cannot be shown.
pub(crate) fn pki_view(store: &Store) -> Result<PkiView, String> {
    view::workspace(store).map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(KeyLock(Mutex::new(())))
        .manage(agent::Desk::default())
        .setup(|app| {
            // Before the window is up, which asks at once whether the app
            // can update itself.
            update::setup(app)?;
            if let Some(main) = app.get_webview_window("main") {
                window::open(&main);
            }
            agent::listen(app.handle());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            devices,
            open_pki,
            workspace_stamp,
            agent::agent_ready,
            agent::answer_agent,
            root_for_devices,
            adopt::adopt_pki,
            adopt::adopt_issuing,
            issue::issue_certificate,
            manage::reissue_certificate,
            manage::read_request,
            manage::sign_request,
            manage::repackage_certificate,
            manage::revoke_certificate,
            manage::delete_certificate,
            manage::set_group,
            manage::revoke_replaced_ca,
            manage::sign_revocation_list,
            setup::create_root,
            setup::create_root_alone,
            setup::create_issuing,
            setup::add_issuing,
            setup::protect_key,
            setup::finish_protecting_key,
            setup::change_key_pin,
            setup::unblock_key_pin,
            setup::reset_key,
            update::update_status,
            update::check_for_update,
            update::install_update
        ])
        .run(tauri::generate_context!())
        .expect("error while running the app");
}

/// Stand-ins for YubiKeys, for tests.
#[cfg(test)]
pub(crate) mod fixtures {
    use yca_core::device::{CaRole, Device, FactoryCredentials, StoredCa};
    use yca_core::{Authority, KeyPair, PKCS_ECDSA_P256_SHA256};

    pub(crate) fn key() -> KeyPair {
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap()
    }

    /// A connected YubiKey holding the given CA.
    pub(crate) fn yubikey(serial: u32, role: CaRole, ca: &Authority<KeyPair>) -> Device {
        Device {
            serial,
            firmware: (5, 7, 4),
            reader: "test".to_owned(),
            pin_attempts_left: 3,
            factory: FactoryCredentials::default(),
            occupied_slots: Vec::new(),
            key_without_certificate: false,
            describes_its_keys: true,
            ca: Some(StoredCa {
                subject: "CN=Test".to_owned(),
                role,
                not_after: ca.not_after(),
                certificate_der: ca.certificate_der().to_vec(),
                key: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use time::{Duration, OffsetDateTime};
    use yca_core::device::{CaRole, Devices};
    use yca_core::view::{WorkspaceCas, devices_view};
    use yca_core::{Authority, LeafRequest};

    use super::fixtures::{key, yubikey};
    use super::manage::{delete_certificate, revoke_replaced_ca};
    use super::*;

    /// The `yca` command opens the app, and finds its socket, by the name
    /// the core knows. The bundle is given its name in another file.
    #[test]
    fn the_bundle_goes_by_the_name_the_core_knows() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(config["identifier"], yca_core::agent::APP_IDENTIFIER);
    }

    #[test]
    fn a_command_waits_for_the_keys_instead_of_giving_up() {
        let lock = KeyLock(Mutex::new(()));
        std::thread::scope(|scope| {
            // The window is in the middle of looking at the keys.
            let looking = lock.0.lock().unwrap();
            let waiting = scope.spawn(|| drop(lock.wait()));
            std::thread::sleep(std::time::Duration::from_millis(50));
            assert!(!waiting.is_finished());
            drop(looking);
            waiting.join().unwrap();
        });
    }

    #[test]
    fn the_window_is_told_which_issuing_ca_belongs_to_the_root() {
        let at = OffsetDateTime::now_utc();
        let root = Authority::create_root("Root", key(), at).unwrap();
        let issuing = root.create_issuing("Issuing", key(), at).unwrap();
        let other_root = Authority::create_root("Other Root", key(), at).unwrap();
        let stranger = other_root.create_issuing("Stranger", key(), at).unwrap();
        let connected = || Devices {
            usable: vec![
                yubikey(1, CaRole::Root, &root),
                yubikey(2, CaRole::Issuing, &issuing),
                yubikey(3, CaRole::Issuing, &stranger),
            ],
            unusable: Vec::new(),
        };
        let verdicts = |view: DevicesView| -> Vec<Option<bool>> {
            view.usable
                .iter()
                .map(|device| device.ca.as_ref().unwrap().signed_by_root)
                .collect()
        };

        // The root itself has no verdict; each issuing CA has one.
        let view = devices_view(connected(), Some(root.certificate_der()), None);
        assert_eq!(
            serde_json::to_value(&view).unwrap()["usable"][1]["ca"]["signedByRoot"],
            true
        );
        assert_eq!(verdicts(view), [None, Some(true), Some(false)]);

        // With no root to check against, nothing is claimed either way.
        assert_eq!(
            verdicts(devices_view(connected(), None, None)),
            [None, None, None]
        );
    }

    #[test]
    fn a_key_that_holds_another_ca_than_the_workspace_is_told_apart() {
        let at = OffsetDateTime::now_utc();
        let root = Authority::create_root("Root", key(), at).unwrap();
        let issuing = root.create_issuing("Issuing", key(), at).unwrap();
        // Same names, other keys: what an exchanged folder would hold.
        let forged_root = Authority::create_root("Root", key(), at).unwrap();
        let forged_issuing = forged_root.create_issuing("Issuing", key(), at).unwrap();
        let connected = || Devices {
            usable: vec![
                yubikey(1, CaRole::Root, &root),
                yubikey(2, CaRole::Issuing, &issuing),
            ],
            unusable: Vec::new(),
        };
        let same = |workspace: Option<&WorkspaceCas>| -> Vec<Option<bool>> {
            devices_view(connected(), None, workspace)
                .usable
                .iter()
                .map(|device| device.ca.as_ref().unwrap().matches_workspace)
                .collect()
        };

        // No workspace open: nothing to hold the keys against.
        assert_eq!(same(None), [None, None]);
        let real = WorkspaceCas {
            root: root.certificate_der().to_vec(),
            issuing: Some(issuing.certificate_der().to_vec()),
        };
        assert_eq!(same(Some(&real)), [Some(true), Some(true)]);
        let exchanged = WorkspaceCas {
            root: forged_root.certificate_der().to_vec(),
            issuing: Some(forged_issuing.certificate_der().to_vec()),
        };
        assert_eq!(same(Some(&exchanged)), [Some(false), Some(false)]);
        // A workspace kept on one YubiKey knows no issuing CA.
        let alone = WorkspaceCas {
            root: root.certificate_der().to_vec(),
            issuing: None,
        };
        assert_eq!(same(Some(&alone)), [Some(true), Some(false)]);
    }

    #[test]
    fn a_key_left_by_a_ca_that_was_not_finished_is_shown_for_what_it_is() {
        let at = OffsetDateTime::now_utc();
        let root = Authority::create_root("Root", key(), at).unwrap();
        // Given up between the key and its certificate.
        let mut unfinished = yubikey(2, CaRole::Root, &root);
        unfinished.ca = None;
        unfinished.key_without_certificate = true;
        let mut empty = yubikey(3, CaRole::Root, &root);
        empty.ca = None;
        let view = devices_view(
            Devices {
                usable: vec![yubikey(1, CaRole::Root, &root), unfinished, empty],
                unusable: Vec::new(),
            },
            None,
            None,
        );

        // A new CA would destroy the key as it would a CA, so the window
        // has to ask first; an empty slot is free.
        let shown: Vec<(bool, bool)> = view
            .usable
            .iter()
            .map(|device| (device.slot_in_use, device.key_without_certificate))
            .collect();
        assert_eq!(shown, [(true, false), (true, true), (false, false)]);
        assert_eq!(
            serde_json::to_value(&view).unwrap()["usable"][1]["keyWithoutCertificate"],
            true
        );
    }

    #[test]
    fn the_window_is_told_what_is_left_of_a_keys_factory_state_and_whether_it_can_be_used() {
        use yca_core::device::FactoryCredentials;

        let at = OffsetDateTime::now_utc();
        let root = Authority::create_root("Root", key(), at).unwrap();
        // A PIN of its owner's over the PUK every YubiKey ships with.
        let mut half = yubikey(1, CaRole::Root, &root);
        half.factory = FactoryCredentials {
            pin: Some(false),
            puk: Some(true),
            management_key: Some(false),
        };
        // Firmware that does not say what the key holds, nor any of this.
        let mut old = yubikey(2, CaRole::Root, &root);
        old.firmware = (5, 2, 7);
        old.describes_its_keys = false;
        let view = devices_view(
            Devices {
                usable: vec![half, old, yubikey(3, CaRole::Root, &root)],
                unusable: Vec::new(),
            },
            None,
            None,
        );
        let shown = serde_json::to_value(&view).unwrap();
        let of = |at: usize, what: &str| shown["usable"][at][what].clone();

        assert_eq!(of(0, "factoryPin"), false);
        assert_eq!(of(0, "factoryPuk"), true);
        assert_eq!(of(0, "factoryManagementKey"), false);
        assert_eq!(of(0, "factoryCredentials"), true);
        assert_eq!(of(0, "tooOld"), false);

        assert_eq!(of(1, "tooOld"), true);
        assert_eq!(of(1, "factoryCredentials"), false);

        assert_eq!(of(2, "tooOld"), false);
        assert_eq!(of(2, "factoryCredentials"), false);
        assert_eq!(of(2, "factoryPuk"), false);
    }

    #[test]
    fn a_pki_folder_is_shown_newest_first_with_its_cas_and_statuses() {
        let at = OffsetDateTime::now_utc();
        let root = Authority::create_root("Test Root CA", key(), at).unwrap();
        let issuing = root.create_issuing("Test Issuing CA", key(), at).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pki");
        let mut store = Store::create(&path, root.certificate_der(), 1001).unwrap();
        store.set_issuing(issuing.certificate_der(), 1002).unwrap();

        let old = LeafRequest::tls_server(["old.example"]).unwrap();
        let old_issued = issuing.issue(&old, &key(), at).unwrap();
        store
            .record(&old_issued, &old, CaRole::Issuing, None, at)
            .unwrap();
        store.revoke(&old_issued.serial().unwrap(), at).unwrap();
        let soon = LeafRequest::ipsec_client("alice@example.com")
            .unwrap()
            .valid_for(Duration::days(10))
            .unwrap();
        let soon_issued = root.issue(&soon, &key(), at).unwrap();
        store
            .record(&soon_issued, &soon, CaRole::Root, None, at)
            .unwrap();

        let view = open_pki(path.to_string_lossy().into_owned()).unwrap();
        assert_eq!(view.root.subject, "CN=Test Root CA");
        // What a device shows when it is asked to trust the root, and the
        // file it is given for that.
        assert_eq!(view.root.sha256.split(' ').count(), 32);
        assert_eq!(view.root.sha1.split(' ').count(), 20);
        assert_eq!(
            root_for_devices(path.to_string_lossy().into_owned()).unwrap(),
            path.join("Test Root CA.crt").to_string_lossy()
        );
        assert_eq!(view.root.yubikey, 1001);
        assert_eq!(view.issuing.as_ref().unwrap().yubikey, 1002);

        let [newest, oldest] = view.certificates.as_slice() else {
            panic!("expected two certificates");
        };
        assert_eq!(newest.names, ["alice@example.com"]);
        // Its files are in a folder of the workspace named after it.
        assert_eq!(
            newest.location.as_deref(),
            Some(
                path.join("certificates/alice@example.com")
                    .to_string_lossy()
                    .as_ref()
            )
        );
        assert_eq!(newest.profile, "ipsec-client");
        assert_eq!(newest.issued_by, "root");
        assert_eq!(newest.status, "expires-soon");
        assert_eq!(oldest.names, ["old.example"]);
        assert_eq!(oldest.status, "revoked");
        assert!(oldest.revoked_at.is_some());

        // The revocation waits for a list of the issuing CA; the root has
        // nothing to list.
        let issuing_list = &view.issuing.as_ref().unwrap().revocation;
        assert_eq!((issuing_list.number, issuing_list.unlisted), (None, 1));
        assert_eq!(view.root.revocation.unlisted, 0);

        // The window gets plain camelCase data.
        let json = serde_json::to_value(&view).unwrap();
        assert!(json["certificates"][0]["notAfter"].is_string());
        assert!(json["certificates"][0]["issuedBy"].is_string());
    }

    #[test]
    fn certificates_are_sorted_into_groups_several_at_once() {
        let at = OffsetDateTime::now_utc();
        let root = Authority::create_root("Test Root CA", key(), at).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pki");
        let mut store = Store::create(&path, root.certificate_der(), 1001).unwrap();
        let mut serials = Vec::new();
        for name in [
            "nas.acme.example",
            "switch.acme.example",
            "printer.home.example",
        ] {
            let request = LeafRequest::tls_server([name]).unwrap();
            let issued = root.issue(&request, &key(), at).unwrap();
            let record = store
                .record(&issued, &request, CaRole::Root, None, at)
                .unwrap();
            serials.push(record.serial.clone());
        }
        let folder = path.to_string_lossy().into_owned();
        let groups = |view: &PkiView| -> Vec<(String, Option<String>)> {
            let mut groups: Vec<_> = view
                .certificates
                .iter()
                .map(|certificate| (certificate.names[0].clone(), certificate.group.clone()))
                .collect();
            groups.sort();
            groups
        };

        let view = manage::set_group(
            folder.clone(),
            serials[..2].to_vec(),
            Some("Acme Ltd".to_owned()),
        )
        .unwrap();
        assert_eq!(
            groups(&view),
            [
                ("nas.acme.example".to_owned(), Some("Acme Ltd".to_owned())),
                ("printer.home.example".to_owned(), None),
                (
                    "switch.acme.example".to_owned(),
                    Some("Acme Ltd".to_owned())
                ),
            ]
        );
        // Finder is shown the folder where it is now.
        let nas = view
            .certificates
            .iter()
            .find(|certificate| certificate.names[0] == "nas.acme.example")
            .unwrap();
        assert_eq!(
            nas.location.as_deref(),
            Some(
                path.join("certificates/Acme Ltd/nas.acme.example")
                    .to_string_lossy()
                    .as_ref()
            )
        );

        // One that is gone moves none of the others.
        assert!(
            manage::set_group(
                folder.clone(),
                vec![serials[2].clone(), "ffffffff".to_owned()],
                Some("Home".to_owned()),
            )
            .is_err()
        );
        // No group named: out of the group they are in.
        let view = manage::set_group(folder, serials, None).unwrap();
        assert!(view.certificates.iter().all(|c| c.group.is_none()));
        assert!(!path.join("certificates/Acme Ltd").exists());
    }

    #[test]
    fn certificates_of_a_replaced_issuing_ca_are_told_apart() {
        let at = OffsetDateTime::now_utc();
        let root = Authority::create_root("Test Root CA", key(), at).unwrap();
        let lost = root.create_issuing("Lost Issuing CA", key(), at).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pki");
        let mut store = Store::create(&path, root.certificate_der(), 1001).unwrap();
        store.set_issuing(lost.certificate_der(), 1002).unwrap();
        let request = LeafRequest::tls_server(["nas.example"]).unwrap();
        let by_lost = lost.issue(&request, &key(), at).unwrap();
        store
            .record(&by_lost, &request, CaRole::Issuing, None, at)
            .unwrap();

        let second = root.create_issuing("Second Issuing CA", key(), at).unwrap();
        store.set_issuing(second.certificate_der(), 1003).unwrap();
        let by_second = second.issue(&request, &key(), at).unwrap();
        store
            .record(&by_second, &request, CaRole::Issuing, None, at)
            .unwrap();

        let open = || open_pki(path.to_string_lossy().into_owned()).unwrap();
        let view = open();
        assert_eq!(
            view.issuing.as_ref().unwrap().subject,
            "CN=Second Issuing CA"
        );
        let [retired] = view.retired.as_slice() else {
            panic!("expected one replaced issuing CA");
        };
        assert_eq!(retired.subject, "CN=Lost Issuing CA");
        assert!(retired.revoked_at.is_none());
        // Newest first: the new CA's certificate, then the lost CA's.
        let told: Vec<_> = view
            .certificates
            .iter()
            .map(|c| (c.issuer, c.status))
            .collect();
        assert_eq!(told, [("current", "valid"), ("replaced", "valid")]);

        // Lost turns out to be stolen: the root revokes the old CA, and
        // with it everything that CA signed.
        let after = revoke_replaced_ca(path.to_string_lossy().into_owned(), retired.serial.clone())
            .unwrap();
        assert!(after.retired[0].revoked_at.is_some());
        let told: Vec<_> = after
            .certificates
            .iter()
            .map(|c| (c.issuer, c.status, c.revoked_at.is_some()))
            .collect();
        assert_eq!(
            told,
            [("current", "valid", false), ("revoked", "revoked", false)]
        );
        assert_eq!(after.root.revocation.unlisted, 1);
        assert_eq!(after.issuing.as_ref().unwrap().revocation.unlisted, 0);

        // Deleting works for either, and the window gets camelCase data.
        let serial = after.certificates[1].serial.clone();
        let left = delete_certificate(path.to_string_lossy().into_owned(), serial).unwrap();
        assert_eq!(left.certificates.len(), 1);
        let json = serde_json::to_value(&left).unwrap();
        assert!(json["retired"][0]["revokedAt"].is_string());
        assert_eq!(json["certificates"][0]["issuer"], "current");
    }

    #[test]
    fn a_folder_without_a_pki_is_an_error_the_window_can_show() {
        let dir = tempfile::tempdir().unwrap();
        let error = open_pki(dir.path().to_string_lossy().into_owned())
            .err()
            .unwrap();
        assert!(error.contains("is not a workspace folder"), "{error}");
    }
}
