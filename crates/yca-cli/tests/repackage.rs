//! Writing a certificate's files again in another form, run as a user
//! would run it, against a workspace made with in-memory keys. It needs
//! no YubiKey: nothing is issued.

use std::fs;
use std::path::Path;
use std::process::Command;

use time::OffsetDateTime;
use yca_core::device::CaRole;
use yca_core::{
    Authority, ExportForm, ExportSource, KeyPair, LeafRequest, PKCS_ECDSA_P256_SHA256, Store,
    export,
};

fn key() -> KeyPair {
    KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap()
}

/// Runs `yca` with some of its environment set and gives back what it
/// printed, and whether it succeeded.
fn yca(arguments: &[&str], environment: &[(&str, &str)]) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_yca"))
        .args(arguments)
        .envs(environment.iter().copied())
        .output()
        .unwrap();
    let mut printed = String::from_utf8_lossy(&output.stdout).into_owned();
    printed.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), printed)
}

/// A workspace with one certificate, its files written for a form with
/// two fields. Gives back its serial number and its private key.
fn workspace(dir: &Path) -> (String, String) {
    let at = OffsetDateTime::now_utc();
    let root = Authority::create_root("Test Root CA", key(), at).unwrap();
    let issuing = root.create_issuing("Test Issuing CA", key(), at).unwrap();
    let mut store = Store::create(dir, root.certificate_der(), 1001).unwrap();
    store.set_issuing(issuing.certificate_der(), 1002).unwrap();

    let request = LeafRequest::tls_server(["nas.home.example"]).unwrap();
    let device_key = key();
    let issued = issuing.issue(&request, &device_key, at).unwrap();
    let folder = store
        .new_certificate_folder("nas.home.example", None)
        .unwrap();
    let serial = store
        .record_in(&folder, &issued, &request, CaRole::Issuing, None, at)
        .unwrap()
        .serial
        .clone();
    let key_der = device_key.serialize_der();
    for file in export(
        ExportForm::Fullchain,
        ExportSource {
            issued: &issued,
            private_key_der: Some(&key_der),
        },
        None,
    )
    .unwrap()
    {
        folder.write(&file).unwrap();
    }
    (serial, device_key.serialize_pem())
}

fn files_in(folder: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(folder)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn the_files_of_a_certificate_are_written_again_from_the_command_line() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("workspace");
    let (serial, private_key) = workspace(&path);
    let store = path.to_str().unwrap();
    let folder = path.join("certificates/nas.home.example");
    let repackage = |files: &str, environment: &[(&str, &str)]| {
        yca(
            &[
                "repackage",
                "--store",
                store,
                "--serial",
                &serial[..10],
                "--files",
                files,
            ],
            environment,
        )
    };
    assert_eq!(files_in(&folder), ["fullchain.crt", "private-key.key"]);

    // Three fields instead of two.
    let (ok, said) = repackage("separate", &[]);
    assert!(ok, "{said}");
    assert!(said.contains("Nothing was issued"), "{said}");
    assert!(said.contains("intermediate-ca.crt"), "{said}");
    assert_eq!(
        files_in(&folder),
        ["certificate.crt", "intermediate-ca.crt", "private-key.key"]
    );

    // One file with a password, and the list says so.
    let (ok, said) = repackage("p12", &[("YCA_P12_PASSWORD", "correct horse")]);
    assert!(ok, "{said}");
    assert_eq!(files_in(&folder), ["certificate.p12"]);
    let (ok, listed) = yca(&["--json", "list", "--store", store], &[]);
    assert!(ok, "{listed}");
    let listed: serde_json::Value =
        serde_json::from_str(listed.lines().find(|line| line.starts_with('{')).unwrap()).unwrap();
    assert_eq!(listed["certificates"][0]["form"], "p12");
    assert_eq!(listed["certificates"][0]["hasKey"], true);

    // Out of it again takes its password; a wrong one changes nothing.
    let (ok, said) = repackage("fullchain", &[("YCA_P12_OPENS", "wrong")]);
    assert!(!ok && said.contains("does not open"), "{said}");
    assert_eq!(files_in(&folder), ["certificate.p12"]);
    let (ok, said) = repackage("fullchain", &[("YCA_P12_OPENS", "correct horse")]);
    assert!(ok, "{said}");
    assert_eq!(files_in(&folder), ["fullchain.crt", "private-key.key"]);
    // The same key as before it went into the file and came out again.
    assert_eq!(
        fs::read_to_string(folder.join("private-key.key")).unwrap(),
        private_key
    );

    // With --json the answer says what the folder holds now.
    let (ok, answered) = yca(
        &[
            "--json",
            "repackage",
            "--store",
            store,
            "--serial",
            &serial,
            "--files",
            "separate",
        ],
        &[],
    );
    assert!(ok, "{answered}");
    let answered: serde_json::Value =
        serde_json::from_str(answered.lines().find(|line| line.starts_with('{')).unwrap()).unwrap();
    assert_eq!(answered["form"], "separate");
    assert_eq!(
        answered["files"],
        serde_json::json!(["certificate.crt", "intermediate-ca.crt", "private-key.key"])
    );
}

#[test]
fn a_device_s_own_request_is_never_answered_with_one_file_that_holds_a_key() {
    // Said before the request file is even read, and long before a YubiKey
    // is asked for anything.
    let (ok, said) = yca(
        &[
            "sign-csr",
            "--csr",
            "no-such-file.csr",
            "--profile",
            "tls-server",
            "--files",
            "p12",
        ],
        &[],
    );
    assert!(!ok, "{said}");
    assert!(said.contains("--files fullchain"), "{said}");
}

#[test]
fn the_answer_calls_the_folder_what_the_list_calls_it() {
    // Signed by the root CA there is no intermediate CA: separate files
    // and the full chain are the same files, and go by one name.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("workspace");
    let at = OffsetDateTime::now_utc();
    let root = Authority::create_root("Test Root CA", key(), at).unwrap();
    let mut store = Store::create(&path, root.certificate_der(), 1001).unwrap();
    let request = LeafRequest::tls_server(["printer.home.example"]).unwrap();
    let device_key = key();
    let issued = root.issue(&request, &device_key, at).unwrap();
    let folder = store
        .new_certificate_folder("printer.home.example", None)
        .unwrap();
    let serial = store
        .record_in(&folder, &issued, &request, CaRole::Root, None, at)
        .unwrap()
        .serial
        .clone();
    drop(folder);
    let store = path.to_str().unwrap();
    let json = |printed: String| -> serde_json::Value {
        serde_json::from_str(printed.lines().find(|line| line.starts_with('{')).unwrap()).unwrap()
    };

    let (ok, answered) = yca(
        &[
            "--json",
            "repackage",
            "--store",
            store,
            "--serial",
            &serial,
            "--files",
            "separate",
        ],
        &[],
    );
    assert!(ok, "{answered}");
    let answered = json(answered);
    assert_eq!(answered["files"], serde_json::json!(["certificate.crt"]));
    let (ok, listed) = yca(&["--json", "list", "--store", store], &[]);
    assert!(ok, "{listed}");
    assert_eq!(answered["form"], "fullchain");
    assert_eq!(json(listed)["certificates"][0]["form"], "fullchain");
}
