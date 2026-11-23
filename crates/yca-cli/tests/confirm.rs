//! What cannot be undone takes a person at the terminal. A program that
//! runs the command gets nowhere with it, whatever it feeds it.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use time::OffsetDateTime;
use yca_core::device::CaRole;
use yca_core::{
    Authority, ExportForm, ExportSource, KeyPair, LeafRequest, PKCS_ECDSA_P256_SHA256, Store,
    export,
};

fn key() -> KeyPair {
    KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap()
}

/// A workspace with one certificate whose private key is in its folder.
/// Gives back the certificate's serial number.
fn workspace(dir: &Path) -> String {
    let at = OffsetDateTime::now_utc();
    let root = Authority::create_root("Test Root CA", key(), at).unwrap();
    let issuing = root.create_issuing("Test Issuing CA", key(), at).unwrap();
    let mut store = Store::create(dir, root.certificate_der(), 1001).unwrap();
    store.set_issuing(issuing.certificate_der(), 1002).unwrap();

    let request = LeafRequest::tls_server(["nas.home.example"]).unwrap();
    let device_key = key();
    let issued = issuing.issue(&request, &device_key, at).unwrap();
    let key_der = device_key.serialize_der();
    let files = export(
        ExportForm::Fullchain,
        ExportSource {
            issued: &issued,
            private_key_der: Some(&key_der),
        },
        None,
    )
    .unwrap();
    let folder = store
        .new_certificate_folder("nas.home.example", None)
        .unwrap();
    store
        .record_with(
            &folder,
            &issued,
            &request,
            CaRole::Issuing,
            None,
            at,
            &files,
        )
        .unwrap()
        .serial
        .clone()
}

#[test]
fn a_program_cannot_confirm_a_deletion() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("workspace");
    let serial = workspace(&path);
    let key_file = path.join("certificates/nas.home.example/private-key.key");
    assert!(key_file.is_file());

    // Asked for a JSON document, there is nobody to ask, and a "yes" on
    // standard input is not a person agreeing.
    let mut child = Command::new(env!("CARGO_BIN_EXE_yca"))
        .args(["--json", "delete", "--store"])
        .arg(&path)
        .args(["--serial", &serial])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    let answer: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        answer["error"]
            .as_str()
            .is_some_and(|error| error.contains("a person at a terminal")),
        "{answer}"
    );

    // The certificate, its files and its key are where they were.
    assert!(Store::open(&path).unwrap().find(&serial).is_ok());
    assert!(key_file.is_file());
}
