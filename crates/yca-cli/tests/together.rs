//! Several programs at one workspace at the same moment: a window, a
//! terminal and an agent or two, each a process of its own. Run here as
//! many `yca` commands started together, against a workspace made with
//! in-memory keys. None of them needs a YubiKey.

use std::path::Path;
use std::process::{Command, Stdio};

use time::OffsetDateTime;
use yca_core::device::CaRole;
use yca_core::{Authority, KeyPair, LeafRequest, PKCS_ECDSA_P256_SHA256, Store};

fn key() -> KeyPair {
    KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap()
}

/// A workspace with as many certificates as asked for. Gives back their
/// serial numbers.
fn workspace(dir: &Path, certificates: usize) -> Vec<String> {
    let at = OffsetDateTime::now_utc();
    let root = Authority::create_root("Test Root CA", key(), at).unwrap();
    let issuing = root.create_issuing("Test Issuing CA", key(), at).unwrap();
    let mut store = Store::create(dir, root.certificate_der(), 1001).unwrap();
    store.set_issuing(issuing.certificate_der(), 1002).unwrap();
    (0..certificates)
        .map(|n| {
            let name = format!("device-{n}.home.example");
            let request = LeafRequest::tls_server([name.as_str()]).unwrap();
            let issued = issuing.issue(&request, &key(), at).unwrap();
            let folder = store.new_certificate_folder(&name, None).unwrap();
            store
                .record_in(&folder, &issued, &request, CaRole::Issuing, None, at)
                .unwrap()
                .serial
                .clone()
        })
        .collect()
}

#[test]
fn programs_changing_one_workspace_at_once_lose_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("workspace");
    let serials = workspace(&path, 16);
    let store = path.to_str().unwrap();

    // Each certificate is changed by a program of its own, all started
    // together: every other one is revoked, the rest are sorted into one
    // of two groups. Every one of them reads the register, changes one
    // entry and writes the whole register back.
    let programs: Vec<_> = serials
        .iter()
        .enumerate()
        .map(|(n, serial)| {
            let mut command = Command::new(env!("CARGO_BIN_EXE_yca"));
            if n % 2 == 0 {
                command.args(["revoke", "--store", store, "--serial", serial]);
            } else {
                let group = if n % 4 == 1 { "Acme Ltd" } else { "Home" };
                command.args(["group", "--store", store, "--serial", serial]);
                command.args(["--name", group]);
            }
            command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    for program in programs {
        let output = program.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // What each of them did is there, and nothing of what another did
    // was written over.
    let after = Store::open(&path).unwrap();
    assert_eq!(after.records().len(), serials.len());
    for (n, serial) in serials.iter().enumerate() {
        let record = after.find(serial).unwrap();
        if n % 2 == 0 {
            assert!(record.revoked_at.is_some(), "certificate {n} is revoked");
            assert_eq!(record.group, None);
        } else {
            let group = if n % 4 == 1 { "Acme Ltd" } else { "Home" };
            assert!(record.revoked_at.is_none());
            assert_eq!(record.group.as_deref(), Some(group), "certificate {n}");
            // Its folder went where its group is.
            let folder = path.join("certificates").join(&record.folder);
            assert!(record.folder.starts_with(group), "{}", record.folder);
            assert!(folder.is_dir(), "{}", folder.display());
        }
    }
    // Nothing a program wrote through is left lying about.
    let left: Vec<String> = std::fs::read_dir(&path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".tmp"))
        .collect();
    assert!(left.is_empty(), "{left:?}");
}
