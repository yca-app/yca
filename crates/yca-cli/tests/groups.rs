//! The commands that sort certificates into groups, run as a user would
//! run them, against a workspace made with in-memory keys. None of them
//! needs a YubiKey.

use std::path::Path;
use std::process::Command;

use time::OffsetDateTime;
use yca_core::device::CaRole;
use yca_core::{Authority, KeyPair, LeafRequest, PKCS_ECDSA_P256_SHA256, Store};

fn key() -> KeyPair {
    KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap()
}

/// Runs `yca` and gives back what it printed, and whether it succeeded.
fn yca(arguments: &[&str]) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_yca"))
        .args(arguments)
        .output()
        .unwrap();
    let mut printed = String::from_utf8_lossy(&output.stdout).into_owned();
    printed.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), printed)
}

/// A workspace with three certificates, one of them in a group already.
/// Gives back their serial numbers.
fn workspace(dir: &Path) -> Vec<String> {
    let at = OffsetDateTime::now_utc();
    let root = Authority::create_root("Test Root CA", key(), at).unwrap();
    let issuing = root.create_issuing("Test Issuing CA", key(), at).unwrap();
    let mut store = Store::create(dir, root.certificate_der(), 1001).unwrap();
    store.set_issuing(issuing.certificate_der(), 1002).unwrap();
    [
        ("nas.acme.example", Some("Acme Ltd")),
        ("switch.acme.example", None),
        ("printer.home.example", None),
    ]
    .into_iter()
    .map(|(name, group)| {
        let request = LeafRequest::tls_server([name]).unwrap();
        let issued = issuing.issue(&request, &key(), at).unwrap();
        let folder = store.new_certificate_folder(name, group).unwrap();
        store
            .record_in(&folder, &issued, &request, CaRole::Issuing, None, at)
            .unwrap()
            .serial
            .clone()
    })
    .collect()
}

#[test]
fn certificates_are_sorted_into_groups_from_the_command_line() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("workspace");
    let serials = workspace(&path);
    let store = path.to_str().unwrap();

    // The list has a column for the group once there is one.
    let (ok, listed) = yca(&["list", "--store", store]);
    assert!(ok, "{listed}");
    assert!(listed.contains("GROUP"), "{listed}");
    assert!(listed.contains("Acme Ltd  nas.acme.example"), "{listed}");

    // Into the group, spelled the way it was typed this time.
    let (ok, moved) = yca(&[
        "group",
        "--store",
        store,
        "--serial",
        &serials[1],
        "--name",
        "acme ltd",
    ]);
    assert!(ok, "{moved}");
    assert!(moved.contains("group \"Acme Ltd\""), "{moved}");
    assert!(
        path.join("certificates/Acme Ltd/switch.acme.example")
            .is_dir()
    );

    // One group alone.
    let (ok, listed) = yca(&["list", "--store", store, "--group", "ACME LTD"]);
    assert!(ok, "{listed}");
    assert!(listed.contains("nas.acme.example"), "{listed}");
    assert!(listed.contains("switch.acme.example"), "{listed}");
    assert!(!listed.contains("printer.home.example"), "{listed}");
    let (ok, listed) = yca(&["list", "--store", store, "--group", "nobody"]);
    assert!(ok, "{listed}");
    assert!(listed.contains("No certificates in a group"), "{listed}");

    // Out of the group again, both at once; the group is gone with them.
    let (ok, moved) = yca(&[
        "group",
        "--store",
        store,
        "--serial",
        &serials[0],
        "--serial",
        &serials[1],
        "--none",
    ]);
    assert!(ok, "{moved}");
    assert!(!path.join("certificates/Acme Ltd").exists());
    assert!(path.join("certificates/nas.acme.example").is_dir());
    let (_, listed) = yca(&["list", "--store", store]);
    assert!(!listed.contains("GROUP"), "{listed}");
}

#[test]
fn a_mistyped_serial_number_moves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("workspace");
    let serials = workspace(&path);
    let store = path.to_str().unwrap();

    let (ok, said) = yca(&[
        "group",
        "--store",
        store,
        "--serial",
        &serials[2],
        "--serial",
        "ffffffffffff",
        "--name",
        "Home",
    ]);
    assert!(!ok, "{said}");
    assert!(path.join("certificates/printer.home.example").is_dir());
    assert!(!path.join("certificates/Home").exists());

    // Neither a name nor --none is not a request.
    let (ok, _) = yca(&["group", "--store", store, "--serial", &serials[2]]);
    assert!(!ok);
    let (ok, said) = yca(&[
        "group",
        "--store",
        store,
        "--serial",
        &serials[2],
        "--name",
        "  ",
    ]);
    assert!(!ok, "{said}");
    assert!(said.contains("--none"), "{said}");
}
