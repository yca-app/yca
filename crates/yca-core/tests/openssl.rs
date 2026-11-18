//! Cross-checks issued chains with the `openssl` command-line tool, which
//! is an independent implementation of X.509 path validation.
//!
//! The tests are skipped when `openssl` is not installed.

use std::path::Path;
use std::process::Command;

use time::OffsetDateTime;
use yca_core::{
    Authority, KeyPair, LeafRequest, PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256, RsaKeySize,
};

fn openssl_available() -> bool {
    let found = Command::new("openssl").arg("version").output().is_ok();
    if !found {
        eprintln!("openssl not found, skipping");
    }
    found
}

/// Runs `openssl verify` and returns whether it accepted the certificate.
fn verify(dir: &Path, args: &[&str]) -> bool {
    let output = Command::new("openssl")
        .arg("verify")
        .arg("-x509_strict")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    output.status.success()
}

fn check(new_key: fn() -> KeyPair) {
    if !openssl_available() {
        return;
    }
    let now = OffsetDateTime::now_utc();
    let root = Authority::create_root("Test Root CA", new_key(), now).unwrap();
    let issuing = root
        .create_issuing("Test Issuing CA", new_key(), now)
        .unwrap();
    let server = issuing
        .issue(
            &LeafRequest::tls_server(["foo.example"]).unwrap(),
            &new_key(),
            now,
        )
        .unwrap();
    let client = issuing
        .issue(
            &LeafRequest::ipsec_client("alice@example.com").unwrap(),
            &new_key(),
            now,
        )
        .unwrap();
    let direct = root
        .issue(
            &LeafRequest::tls_server(["switch.example"]).unwrap(),
            &new_key(),
            now,
        )
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, pem: String| std::fs::write(dir.path().join(name), pem).unwrap();
    write("root.pem", root.certificate_pem());
    write("issuing.pem", issuing.certificate_pem());
    write("server.pem", server.pem());
    write("client.pem", client.pem());
    write("direct.pem", direct.pem());
    let dir = dir.path();

    // The device trusts only the root; the intermediate travels with the leaf.
    let with_chain = ["-CAfile", "root.pem", "-untrusted", "issuing.pem"];
    assert!(verify(dir, &[&with_chain[..], &["issuing.pem"]].concat()));
    assert!(verify(
        dir,
        &[
            &with_chain[..],
            &[
                "-purpose",
                "sslserver",
                "-verify_hostname",
                "foo.example",
                "server.pem"
            ]
        ]
        .concat()
    ));
    assert!(verify(
        dir,
        &[&with_chain[..], &["-purpose", "sslclient", "client.pem"]].concat()
    ));

    // A server certificate is not accepted as a client, nor for another host.
    assert!(!verify(
        dir,
        &[&with_chain[..], &["-purpose", "sslclient", "server.pem"]].concat()
    ));
    assert!(!verify(
        dir,
        &[
            &with_chain[..],
            &["-verify_hostname", "bar.example", "server.pem"]
        ]
        .concat()
    ));

    // Without the intermediate the chain cannot be built.
    assert!(!verify(dir, &["-CAfile", "root.pem", "server.pem"]));

    // A certificate issued directly by the root needs no intermediate.
    assert!(verify(
        dir,
        &["-CAfile", "root.pem", "-purpose", "sslserver", "direct.pem"]
    ));
}

#[test]
fn openssl_accepts_ecdsa_chain() {
    check(|| KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap());
}

#[test]
fn openssl_accepts_rsa_chain() {
    check(|| KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap());
}
