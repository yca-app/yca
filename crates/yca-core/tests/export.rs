//! The files of a certificate, checked by reading them back and with
//! `openssl`.

use std::process::Command;

use p12_keystore::{KeyStore, KeyStoreEntry, Pkcs12ImportPolicy};
use time::OffsetDateTime;
use yca_core::{
    Authority, Error, ExportFile, ExportForm, ExportSource, IssuedCertificate, KeyPair,
    LeafRequest, P12Encryption, P12Options, PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256, RsaKeySize,
    export, key_from_p12,
};

const PASSWORD: &str = "correct horse";

struct Fixture {
    root: Authority<KeyPair>,
    issuing: Authority<KeyPair>,
    key: KeyPair,
    via_issuing: IssuedCertificate,
    via_root: IssuedCertificate,
}

fn fixture(new_key: fn() -> KeyPair) -> Fixture {
    let at = OffsetDateTime::now_utc();
    let root = Authority::create_root("Test Root CA", new_key(), at).unwrap();
    let issuing = root
        .create_issuing("Test Issuing CA", new_key(), at)
        .unwrap();
    let key = new_key();
    let request = LeafRequest::ipsec_client("alice@example.com").unwrap();
    let via_issuing = issuing.issue(&request, &key, at).unwrap();
    let via_root = root.issue(&request, &key, at).unwrap();
    Fixture {
        root,
        issuing,
        key,
        via_issuing,
        via_root,
    }
}

fn ec() -> KeyPair {
    KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap()
}

fn rsa() -> KeyPair {
    KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap()
}

fn names(files: &[ExportFile]) -> Vec<&str> {
    files.iter().map(|file| file.name.as_str()).collect()
}

fn text<'a>(files: &'a [ExportFile], name: &str) -> &'a str {
    let file = files.iter().find(|file| file.name == name).unwrap();
    std::str::from_utf8(&file.contents).unwrap()
}

fn p12(encryption: P12Encryption) -> Option<P12Options<'static>> {
    Some(P12Options {
        password: PASSWORD,
        encryption,
        label: "alice",
    })
}

#[test]
fn a_form_with_two_fields_gets_the_full_chain_and_the_key() {
    let f = fixture(ec);
    let key_der = f.key.serialize_der();
    let files = export(
        ExportForm::Fullchain,
        ExportSource {
            issued: &f.via_issuing,
            private_key_der: Some(&key_der),
        },
        None,
    )
    .unwrap();

    assert_eq!(names(&files), ["fullchain.crt", "private-key.key"]);
    // The device's certificate first, the intermediate CA below it, no
    // root.
    let chain = text(&files, "fullchain.crt");
    assert_eq!(chain, f.via_issuing.fullchain_pem());
    assert!(chain.starts_with(&f.via_issuing.pem()));
    assert!(chain.ends_with(&f.issuing.certificate_pem()));
    assert!(!chain.contains(&f.root.certificate_pem()));

    assert_eq!(text(&files, "private-key.key"), f.key.serialize_pem());
    let secret: Vec<_> = files.iter().filter(|file| file.holds_private_key).collect();
    assert_eq!(secret.len(), 1);
    assert_eq!(secret[0].name, "private-key.key");
}

#[test]
fn a_form_with_three_fields_gets_each_in_a_file_of_its_own() {
    let f = fixture(ec);
    let key_der = f.key.serialize_der();
    let files = export(
        ExportForm::Separate,
        ExportSource {
            issued: &f.via_issuing,
            private_key_der: Some(&key_der),
        },
        None,
    )
    .unwrap();
    assert_eq!(
        names(&files),
        ["certificate.crt", "intermediate-ca.crt", "private-key.key"]
    );
    assert_eq!(text(&files, "certificate.crt"), f.via_issuing.pem());
    assert_eq!(
        text(&files, "intermediate-ca.crt"),
        f.issuing.certificate_pem()
    );
    // The root CA is never among the files: a device does not send it.
    assert!(
        files
            .iter()
            .all(|file| !text(&files, &file.name).contains(&f.root.certificate_pem()))
    );
}

#[test]
fn signed_by_the_root_both_forms_come_to_the_same_two_files() {
    // There is no intermediate CA to put anywhere.
    let f = fixture(ec);
    let key_der = f.key.serialize_der();
    let source = ExportSource {
        issued: &f.via_root,
        private_key_der: Some(&key_der),
    };
    let fullchain = export(ExportForm::Fullchain, source, None).unwrap();
    let separate = export(ExportForm::Separate, source, None).unwrap();
    assert_eq!(names(&fullchain), ["certificate.crt", "private-key.key"]);
    assert_eq!(fullchain, separate);
    assert_eq!(text(&fullchain, "certificate.crt"), f.via_root.pem());
}

#[test]
fn without_a_key_only_certificates_are_exported() {
    // A certificate issued for a device's own request, or reissued for
    // the key the device already has.
    let f = fixture(ec);
    let source = ExportSource {
        issued: &f.via_issuing,
        private_key_der: None,
    };
    let fullchain = export(ExportForm::Fullchain, source, None).unwrap();
    assert_eq!(names(&fullchain), ["fullchain.crt"]);
    let separate = export(ExportForm::Separate, source, None).unwrap();
    assert_eq!(names(&separate), ["certificate.crt", "intermediate-ca.crt"]);
    assert!(
        fullchain
            .iter()
            .chain(&separate)
            .all(|file| !file.holds_private_key)
    );

    // One file with everything is nothing without the key.
    assert!(matches!(
        export(ExportForm::Pkcs12, source, p12(P12Encryption::Modern)),
        Err(Error::InvalidRequest(_))
    ));
}

fn check_one_file(new_key: fn() -> KeyPair, encryption: P12Encryption) {
    let f = fixture(new_key);
    let key_der = f.key.serialize_der();
    let files = export(
        ExportForm::Pkcs12,
        ExportSource {
            issued: &f.via_issuing,
            private_key_der: Some(&key_der),
        },
        p12(encryption),
    )
    .unwrap();
    // The one file and nothing beside it.
    assert_eq!(names(&files), ["certificate.p12"]);
    let archive = &files[0];
    assert!(archive.holds_private_key);

    // Read it back: the key, then the certificate and the intermediate CA.
    let keystore =
        KeyStore::from_pkcs12(&archive.contents, PASSWORD, Pkcs12ImportPolicy::Strict).unwrap();
    assert_eq!(keystore.entries_len(), 1);
    let Some(KeyStoreEntry::PrivateKeyChain(chain)) = keystore.entry("alice") else {
        panic!("the .p12 holds no key under its label");
    };
    assert_eq!(chain.key().as_der(), key_der.as_slice());
    let certificates: Vec<_> = chain.certs().iter().map(|cert| cert.as_der()).collect();
    assert_eq!(
        certificates,
        [f.via_issuing.der(), f.issuing.certificate_der()]
    );

    // The key comes out again with the password, for packing it anew, and
    // with no other.
    assert_eq!(
        key_from_p12(&archive.contents, PASSWORD)
            .unwrap()
            .as_slice(),
        key_der.as_slice()
    );
    assert!(matches!(
        key_from_p12(&archive.contents, "wrong"),
        Err(Error::InvalidRequest(_))
    ));
    assert!(KeyStore::from_pkcs12(&archive.contents, "wrong", Pkcs12ImportPolicy::Strict).is_err());
}

#[test]
fn one_file_reads_back_with_modern_encryption() {
    check_one_file(ec, P12Encryption::Modern);
    check_one_file(rsa, P12Encryption::Modern);
}

#[test]
fn one_file_reads_back_with_compatible_encryption() {
    check_one_file(ec, P12Encryption::Compatible);
    check_one_file(rsa, P12Encryption::Compatible);
}

#[test]
fn one_file_for_a_certificate_signed_by_the_root_carries_no_intermediate() {
    let f = fixture(ec);
    let key_der = f.key.serialize_der();
    let files = export(
        ExportForm::Pkcs12,
        ExportSource {
            issued: &f.via_root,
            private_key_der: Some(&key_der),
        },
        p12(P12Encryption::Modern),
    )
    .unwrap();
    let keystore =
        KeyStore::from_pkcs12(&files[0].contents, PASSWORD, Pkcs12ImportPolicy::Strict).unwrap();
    let (_, chain) = keystore.private_key_chain().unwrap();
    assert_eq!(chain.certs().len(), 1);
}

#[test]
fn one_file_needs_a_real_password() {
    let f = fixture(ec);
    let key_der = f.key.serialize_der();
    let source = ExportSource {
        issued: &f.via_issuing,
        private_key_der: Some(&key_der),
    };
    assert!(matches!(
        export(ExportForm::Pkcs12, source, None),
        Err(Error::InvalidRequest(_))
    ));
    let empty = P12Options {
        password: "",
        encryption: P12Encryption::Modern,
        label: "alice",
    };
    assert!(matches!(
        export(ExportForm::Pkcs12, source, Some(empty)),
        Err(Error::InvalidRequest(_))
    ));
}

#[test]
fn the_forms_go_by_their_names_outside_the_program() {
    for (form, name) in [
        (ExportForm::Fullchain, "fullchain"),
        (ExportForm::Separate, "separate"),
        (ExportForm::Pkcs12, "p12"),
    ] {
        assert_eq!(form.name(), name);
        assert_eq!(serde_json::to_value(form).unwrap(), name);
        assert_eq!(
            serde_json::from_value::<ExportForm>(name.into()).unwrap(),
            form
        );
    }
}

#[test]
fn openssl_opens_the_one_file() {
    if Command::new("openssl").arg("version").output().is_err() {
        eprintln!("openssl not found, skipping");
        return;
    }
    let f = fixture(rsa);
    let key_der = f.key.serialize_der();
    let files = export(
        ExportForm::Pkcs12,
        ExportSource {
            issued: &f.via_issuing,
            private_key_der: Some(&key_der),
        },
        p12(P12Encryption::Modern),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    for file in &files {
        std::fs::write(dir.path().join(&file.name), &file.contents).unwrap();
    }
    // The root is not among the files; whoever checks has it already.
    std::fs::write(dir.path().join("ca-root.pem"), f.root.certificate_pem()).unwrap();
    let run = |args: &[&str]| {
        let output = Command::new("openssl")
            .args(args)
            .current_dir(dir.path())
            .output()
            .unwrap();
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };
    let password = format!("pass:{PASSWORD}");

    let (ok, certificates, errors) = run(&[
        "pkcs12",
        "-in",
        "certificate.p12",
        "-passin",
        &password,
        "-nokeys",
    ]);
    assert!(ok, "{errors}");
    assert_eq!(certificates.matches("BEGIN CERTIFICATE").count(), 2);
    assert!(certificates.contains("alice"));

    let (ok, key, errors) = run(&[
        "pkcs12",
        "-in",
        "certificate.p12",
        "-passin",
        &password,
        "-nocerts",
        "-noenc",
    ]);
    assert!(ok, "{errors}");
    assert!(key.contains("PRIVATE KEY"));

    let (ok, _, _) = run(&[
        "pkcs12",
        "-in",
        "certificate.p12",
        "-passin",
        "pass:wrong",
        "-nokeys",
    ]);
    assert!(!ok);

    // The certificate inside chains to the root that ships beside it.
    std::fs::write(dir.path().join("inside.pem"), certificates).unwrap();
    let (ok, _, errors) = run(&[
        "verify",
        "-x509_strict",
        "-CAfile",
        "ca-root.pem",
        "-untrusted",
        "inside.pem",
        "-purpose",
        "sslclient",
        "inside.pem",
    ]);
    assert!(ok, "{errors}");
}
