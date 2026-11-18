//! Revocation lists and signing requests, checked with in-memory keys and,
//! where available, with the `openssl` command-line tool.

use std::path::Path;
use std::process::Command;

use time::{Duration, OffsetDateTime};
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::revocation_list::CertificateRevocationList;
use yca_core::device::CaRole;
use yca_core::{
    Authority, Error, KeyPair, LeafRequest, PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256, Revoked,
    RsaKeySize, SigningRequest, Store,
};

fn key() -> KeyPair {
    KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap()
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn two_tier(at: OffsetDateTime) -> (Authority<KeyPair>, Authority<KeyPair>) {
    let root = Authority::create_root("Test Root CA", key(), at).unwrap();
    let issuing = root.create_issuing("Test Issuing CA", key(), at).unwrap();
    (root, issuing)
}

fn subject_key_identifier(certificate_der: &[u8]) -> Vec<u8> {
    let (_, certificate) = X509Certificate::from_der(certificate_der).unwrap();
    certificate
        .iter_extensions()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(identifier) => Some(identifier.0.to_vec()),
            _ => None,
        })
        .unwrap()
}

fn authority_key_identifier(list: &CertificateRevocationList<'_>) -> Vec<u8> {
    list.tbs_cert_list
        .iter_extensions()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(identifier) => {
                identifier.key_identifier.as_ref().map(|id| id.0.to_vec())
            }
            _ => None,
        })
        .unwrap()
}

fn openssl_available() -> bool {
    let found = Command::new("openssl").arg("version").output().is_ok();
    if !found {
        eprintln!("openssl not found, skipping");
    }
    found
}

fn openssl(dir: &Path, args: &[&str]) -> (bool, String) {
    let output = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), text)
}

#[test]
fn a_revocation_list_names_exactly_the_revoked_certificates() {
    let at = now();
    let (_, issuing) = two_tier(at);
    let request = LeafRequest::tls_client("laptop").unwrap();
    let stolen = issuing.issue(&request, &key(), at).unwrap();
    let kept = issuing.issue(&request, &key(), at).unwrap();

    let list = issuing
        .revocation_list(
            &[Revoked {
                serial: stolen.serial().unwrap(),
                revoked_at: at,
            }],
            1,
            at,
        )
        .unwrap();
    assert_eq!(list.number(), 1);
    assert_eq!(list.len(), 1);
    assert!(list.pem().starts_with("-----BEGIN X509 CRL-----"));

    let (rest, parsed) = CertificateRevocationList::from_der(list.der()).unwrap();
    assert!(rest.is_empty());
    let (_, ca) = X509Certificate::from_der(issuing.certificate_der()).unwrap();
    parsed.verify_signature(ca.public_key()).unwrap();
    assert_eq!(parsed.issuer().as_raw(), ca.subject().as_raw());

    let (_, stolen_cert) = X509Certificate::from_der(stolen.der()).unwrap();
    let (_, kept_cert) = X509Certificate::from_der(kept.der()).unwrap();
    let serials: Vec<_> = parsed
        .iter_revoked_certificates()
        .map(|entry| entry.raw_serial().to_vec())
        .collect();
    assert_eq!(serials, vec![stolen_cert.raw_serial().to_vec()]);
    assert!(!serials.contains(&kept_cert.raw_serial().to_vec()));

    // Current for a year, and never dated ahead of itself.
    let this_update = parsed.last_update().to_datetime();
    assert_eq!(list.next_update(), this_update + Duration::days(365));
    assert_eq!(
        parsed.next_update().unwrap().to_datetime(),
        list.next_update()
    );
    let revoked_at = parsed
        .iter_revoked_certificates()
        .next()
        .unwrap()
        .revocation_date
        .to_datetime();
    assert!(revoked_at <= this_update);
}

#[test]
fn an_empty_list_is_valid_and_says_nothing_is_revoked() {
    let at = now();
    let (_, issuing) = two_tier(at);
    let list = issuing.revocation_list(&[], 7, at).unwrap();
    assert!(list.is_empty());
    let (_, parsed) = CertificateRevocationList::from_der(list.der()).unwrap();
    assert_eq!(parsed.iter_revoked_certificates().count(), 0);
    assert_eq!(parsed.crl_number().unwrap().to_string(), "7");
}

#[test]
fn a_list_never_outlives_its_ca() {
    // A root with about 100 days left.
    let at = now();
    let created = at - Duration::days(20 * 365 + 5 - 100);
    let root = Authority::create_root("Old Root", key(), created).unwrap();
    let list = root.revocation_list(&[], 1, at).unwrap();
    assert_eq!(list.next_update(), root.not_after());

    let after_the_end = root.not_after() + Duration::seconds(1);
    assert!(matches!(
        root.revocation_list(&[], 2, after_the_end),
        Err(Error::CaExpired)
    ));
}

#[test]
fn the_list_points_at_its_ca_by_the_identifier_in_the_ca_certificate() {
    // A CA made by another tool may identify its key differently from
    // how rcgen would. Build such a CA certificate by hand.
    let at = now();
    let ca_key = key();
    let custom_identifier = vec![0xAB; 20];
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Adopted Root");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(1));
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params.not_before = at - Duration::days(1);
    params.not_after = at + Duration::days(3650);
    params.key_identifier_method = rcgen::KeyIdMethod::PreSpecified(custom_identifier.clone());
    let certificate = params.self_signed(&ca_key).unwrap();
    assert_eq!(subject_key_identifier(certificate.der()), custom_identifier);

    let adopted = Authority::load(certificate.der(), ca_key).unwrap();
    let list = adopted.revocation_list(&[], 1, at).unwrap();
    let (_, parsed) = CertificateRevocationList::from_der(list.der()).unwrap();
    assert_eq!(authority_key_identifier(&parsed), custom_identifier);

    // And the certificates it issues point at it the same way.
    let leaf = adopted
        .issue(&LeafRequest::tls_client("laptop").unwrap(), &key(), at)
        .unwrap();
    let (_, leaf) = X509Certificate::from_der(leaf.der()).unwrap();
    let leaf_points_at = leaf
        .iter_extensions()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(identifier) => {
                identifier.key_identifier.as_ref().map(|id| id.0.to_vec())
            }
            _ => None,
        })
        .unwrap();
    assert_eq!(leaf_points_at, custom_identifier);
}

#[test]
fn nonsense_serial_numbers_are_refused() {
    let at = now();
    let (_, issuing) = two_tier(at);
    for serial in ["", "xyz", "abc"] {
        let revoked = [Revoked {
            serial: serial.to_owned(),
            revoked_at: at,
        }];
        assert!(
            matches!(
                issuing.revocation_list(&revoked, 1, at),
                Err(Error::InvalidRequest(_))
            ),
            "{serial:?}"
        );
    }
}

#[test]
fn the_folder_decides_what_goes_on_each_list_and_counts_them() {
    let at = now();
    let (root, issuing) = two_tier(at);
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(dir.path().join("pki"), root.certificate_der(), 1).unwrap();
    store.set_issuing(issuing.certificate_der(), 2).unwrap();

    let client = LeafRequest::tls_client("laptop").unwrap();
    let short = LeafRequest::tls_client("guest")
        .unwrap()
        .valid_for(Duration::days(1))
        .unwrap();
    let mut record = |authority: &Authority<KeyPair>, request: &LeafRequest, role| {
        let issued = authority.issue(request, &key(), at).unwrap();
        store.record(&issued, request, role, None, at).unwrap();
        issued.serial().unwrap()
    };
    let stolen = record(&issuing, &client, CaRole::Issuing);
    let _kept = record(&issuing, &client, CaRole::Issuing);
    let expired_soon = record(&issuing, &short, CaRole::Issuing);
    let by_root = record(&root, &client, CaRole::Root);

    assert!(store.revoked(CaRole::Issuing, at).is_empty());
    store.revoke(&stolen, at).unwrap();
    store.revoke(&expired_soon, at).unwrap();
    store.revoke(&by_root, at).unwrap();

    // Each CA lists only what it issued itself.
    let on_issuing: Vec<_> = store
        .revoked(CaRole::Issuing, at)
        .into_iter()
        .map(|entry| entry.serial)
        .collect();
    assert_eq!(on_issuing, vec![stolen.clone(), expired_soon.clone()]);
    let on_root: Vec<_> = store
        .revoked(CaRole::Root, at)
        .into_iter()
        .map(|entry| entry.serial)
        .collect();
    assert_eq!(on_root, vec![by_root]);

    // A revoked certificate drops off the list once it has expired.
    let later = at + Duration::days(2);
    let on_issuing_later: Vec<_> = store
        .revoked(CaRole::Issuing, later)
        .into_iter()
        .map(|entry| entry.serial)
        .collect();
    assert_eq!(on_issuing_later, vec![stolen]);

    // Lists are numbered 1, 2, ... per CA, and the count survives reopening.
    assert_eq!(store.next_crl_number(CaRole::Issuing).unwrap(), 1);
    let first = issuing
        .revocation_list(&store.revoked(CaRole::Issuing, at), 1, at)
        .unwrap();
    // Kept in the workspace in both forms a device may ask for.
    let (folder, [pem, der]) = store.save_crl(CaRole::Issuing, &first).unwrap();
    assert_eq!(folder, store.dir().join("crl"));
    assert_eq!(
        (pem.as_str(), der.as_str()),
        ("issuing.crl.pem", "issuing.crl")
    );
    assert_eq!(
        std::fs::read_to_string(folder.join(&pem)).unwrap(),
        first.pem()
    );
    assert_eq!(std::fs::read(folder.join(&der)).unwrap(), first.der());
    assert_eq!(store.next_crl_number(CaRole::Issuing).unwrap(), 2);
    assert_eq!(store.next_crl_number(CaRole::Root).unwrap(), 1);

    // The same number cannot be used twice.
    assert!(matches!(
        store.save_crl(CaRole::Issuing, &first),
        Err(Error::Store(_))
    ));

    let reopened = Store::open(store.dir()).unwrap();
    assert_eq!(reopened.next_crl_number(CaRole::Issuing).unwrap(), 2);
    assert_eq!(reopened.ca(CaRole::Issuing).unwrap().crl_number, 1);
}

#[test]
fn the_folder_knows_which_revocations_no_list_names_yet() {
    let at = now();
    let (root, issuing) = two_tier(at);
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(dir.path().join("pki"), root.certificate_der(), 1).unwrap();
    store.set_issuing(issuing.certificate_der(), 2).unwrap();
    let client = LeafRequest::tls_client("laptop").unwrap();
    let mut serials = Vec::new();
    for _ in 0..2 {
        let issued = issuing.issue(&client, &key(), at).unwrap();
        store
            .record(&issued, &client, CaRole::Issuing, None, at)
            .unwrap();
        serials.push(issued.serial().unwrap());
    }

    // Nothing signed and nothing revoked.
    let status = store.crl_status(CaRole::Issuing, at).unwrap();
    assert_eq!(
        (status.number, status.next_update, status.unlisted),
        (None, None, 0)
    );

    // A revocation waits for a list.
    store.revoke(&serials[0], at).unwrap();
    assert_eq!(store.crl_status(CaRole::Issuing, at).unwrap().unlisted, 1);

    // Once signed, the list covers it...
    let list = issuing
        .revocation_list(&store.revoked(CaRole::Issuing, at), 1, at)
        .unwrap();
    store.save_crl(CaRole::Issuing, &list).unwrap();
    let status = store.crl_status(CaRole::Issuing, at).unwrap();
    assert_eq!(status.number, Some(1));
    assert_eq!(status.next_update, Some(list.next_update()));
    assert_eq!(status.unlisted, 0);

    // ...until something else is revoked.
    store.revoke(&serials[1], at).unwrap();
    assert_eq!(store.crl_status(CaRole::Issuing, at).unwrap().unlisted, 1);
    // The root keeps a list of its own.
    assert_eq!(store.crl_status(CaRole::Root, at).unwrap().unlisted, 0);
}

#[test]
fn openssl_refuses_a_revoked_certificate_once_it_has_the_list() {
    if !openssl_available() {
        return;
    }
    let at = now();
    let (root, issuing) = two_tier(at);
    let request = LeafRequest::tls_client("laptop").unwrap();
    let stolen = issuing.issue(&request, &key(), at).unwrap();
    let kept = issuing.issue(&request, &key(), at).unwrap();
    let list = issuing
        .revocation_list(
            &[Revoked {
                serial: stolen.serial().unwrap(),
                revoked_at: at,
            }],
            1,
            at,
        )
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, text: String| std::fs::write(dir.path().join(name), text).unwrap();
    write("root.pem", root.certificate_pem());
    write("issuing.pem", issuing.certificate_pem());
    write("stolen.pem", stolen.pem());
    write("kept.pem", kept.pem());
    write("crl.pem", list.pem());
    let dir = dir.path();

    // openssl accepts the list itself as signed by the issuing CA.
    let (ok, text) = openssl(
        dir,
        &["crl", "-in", "crl.pem", "-noout", "-CAfile", "issuing.pem"],
    );
    assert!(ok && text.contains("verify OK"), "{text}");

    let base = [
        "verify",
        "-x509_strict",
        "-CAfile",
        "root.pem",
        "-untrusted",
        "issuing.pem",
    ];
    let with_list = [&base[..], &["-crl_check", "-CRLfile", "crl.pem"]].concat();

    // Without the list nobody knows; with it, only the revoked one fails.
    assert!(openssl(dir, &[&base[..], &["stolen.pem"]].concat()).0);
    let (ok, text) = openssl(dir, &[&with_list[..], &["stolen.pem"]].concat());
    assert!(!ok && text.contains("certificate revoked"), "{text}");
    let (ok, text) = openssl(dir, &[&with_list[..], &["kept.pem"]].concat());
    assert!(ok, "{text}");
}

#[test]
fn openssl_refuses_the_certificates_of_a_revoked_issuing_ca() {
    if !openssl_available() {
        return;
    }
    let at = now();
    let (root, stolen_ca) = two_tier(at);
    let request = LeafRequest::tls_client("laptop").unwrap();
    let by_stolen = stolen_ca.issue(&request, &key(), at).unwrap();
    // What the stolen CA said last about its own certificates: nothing.
    let last_list = stolen_ca.revocation_list(&[], 1, at).unwrap();

    // The folder replaces the issuing CA and has the root revoke the old.
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::create(dir.path().join("pki"), root.certificate_der(), 1).unwrap();
    store.set_issuing(stolen_ca.certificate_der(), 2).unwrap();
    let replacement = root.create_issuing("Second Issuing CA", key(), at).unwrap();
    store.set_issuing(replacement.certificate_der(), 3).unwrap();
    let retired = store.retired()[0].serial.clone();
    store.revoke_retired(&retired, at).unwrap();
    let number = store.next_crl_number(CaRole::Root).unwrap();
    let root_list = root
        .revocation_list(&store.revoked(CaRole::Root, at), number, at)
        .unwrap();
    store.save_crl(CaRole::Root, &root_list).unwrap();
    assert_eq!(store.crl_status(CaRole::Root, at).unwrap().unlisted, 0);
    let by_new = replacement.issue(&request, &key(), at).unwrap();
    let new_list = replacement.revocation_list(&[], 1, at).unwrap();

    let write = |name: &str, text: String| std::fs::write(dir.path().join(name), text).unwrap();
    write("root.pem", root.certificate_pem());
    write("stolen-ca.pem", stolen_ca.certificate_pem());
    write("new-ca.pem", replacement.certificate_pem());
    write("by-stolen.pem", by_stolen.pem());
    write("by-new.pem", by_new.pem());
    write(
        "lists.pem",
        format!("{}{}{}", root_list.pem(), last_list.pem(), new_list.pem()),
    );
    let dir = dir.path();

    // A device that checks every link of the chain against the lists.
    let verify = |ca: &str, certificate: &str| {
        openssl(
            dir,
            &[
                "verify",
                "-x509_strict",
                "-CAfile",
                "root.pem",
                "-untrusted",
                ca,
                "-crl_check_all",
                "-CRLfile",
                "lists.pem",
                certificate,
            ],
        )
    };
    let (ok, text) = verify("stolen-ca.pem", "by-stolen.pem");
    assert!(!ok && text.contains("certificate revoked"), "{text}");
    let (ok, text) = verify("new-ca.pem", "by-new.pem");
    assert!(ok, "{text}");
}

#[test]
fn a_device_request_yields_a_certificate_for_the_devices_own_key() {
    let at = now();
    let (_, issuing) = two_tier(at);

    // The device makes a key and a request; only the request leaves it.
    let device_key = key();
    let mut wanted =
        rcgen::CertificateParams::new(vec!["switch.example".to_owned(), "192.0.2.7".to_owned()])
            .unwrap();
    // A device may ask for anything; none of this is honoured.
    wanted.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    wanted.not_after = at + Duration::days(36500);
    let request_pem = wanted
        .serialize_request(&device_key)
        .unwrap()
        .pem()
        .unwrap();

    let request = SigningRequest::parse(request_pem.as_bytes()).unwrap();
    assert_eq!(request.names(), ["switch.example", "192.0.2.7"]);

    let profile = LeafRequest::tls_server(request.names()).unwrap();
    let issued = issuing.sign_request(&profile, &request, at).unwrap();
    let (_, certificate) = X509Certificate::from_der(issued.der()).unwrap();

    use yca_core::PublicKeyData;
    assert_eq!(
        certificate.public_key().raw,
        device_key.subject_public_key_info().as_slice()
    );
    // The profile decided, not the request.
    assert!(!certificate.basic_constraints().unwrap().unwrap().value.ca);
    let lifetime = issued.not_after() - certificate.validity().not_before.to_datetime();
    assert!(lifetime <= Duration::days(825));
    assert!(
        certificate
            .extended_key_usage()
            .unwrap()
            .unwrap()
            .value
            .server_auth
    );

    // DER works as well as PEM.
    let der = wanted
        .serialize_request(&device_key)
        .unwrap()
        .der()
        .to_vec();
    assert_eq!(
        SigningRequest::parse(&der).unwrap().names(),
        request.names()
    );
}

#[test]
fn a_request_without_alternative_names_falls_back_to_its_common_name() {
    let mut wanted = rcgen::CertificateParams::default();
    wanted.distinguished_name = rcgen::DistinguishedName::new();
    wanted
        .distinguished_name
        .push(rcgen::DnType::CommonName, "router.example");
    let pem = wanted.serialize_request(&key()).unwrap().pem().unwrap();
    assert_eq!(
        SigningRequest::parse(pem.as_bytes()).unwrap().names(),
        ["router.example"]
    );
}

#[test]
fn a_damaged_or_foreign_request_is_refused() {
    let wanted = rcgen::CertificateParams::new(vec!["switch.example".to_owned()]).unwrap();
    let mut der = wanted.serialize_request(&key()).unwrap().der().to_vec();

    // Flip one bit of the signature at the very end.
    *der.last_mut().unwrap() ^= 0x01;
    assert!(matches!(
        SigningRequest::parse(&der),
        Err(Error::InvalidRequest(_))
    ));

    assert!(matches!(
        SigningRequest::parse(b"not a request at all"),
        Err(Error::InvalidRequest(_))
    ));
    let (root, _) = two_tier(now());
    assert!(matches!(
        SigningRequest::parse(root.certificate_pem().as_bytes()),
        Err(Error::InvalidRequest(_))
    ));
}

#[test]
fn an_rsa_request_keeps_the_rsa_key() {
    let at = now();
    let (_, issuing) = two_tier(at);
    let device_key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
    let wanted = rcgen::CertificateParams::new(vec!["vpn.example".to_owned()]).unwrap();
    let pem = wanted
        .serialize_request(&device_key)
        .unwrap()
        .pem()
        .unwrap();

    let request = SigningRequest::parse(pem.as_bytes()).unwrap();
    let issued = issuing
        .sign_request(
            &LeafRequest::ipsec_gateway(request.names()).unwrap(),
            &request,
            at,
        )
        .unwrap();
    let (_, certificate) = X509Certificate::from_der(issued.der()).unwrap();
    let usage = certificate.key_usage().unwrap().unwrap().value;
    assert!(usage.digital_signature() && usage.key_encipherment());
}

#[test]
fn a_request_made_by_openssl_is_understood() {
    if !openssl_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let (ok, text) = openssl(
        dir.path(),
        &[
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "device.key",
            "-out",
            "device.csr",
            "-subj",
            "/CN=fw.example/O=Example",
            "-addext",
            "subjectAltName=DNS:fw.example,IP:192.0.2.9,email:admin@example.com",
        ],
    );
    assert!(ok, "{text}");
    let request =
        SigningRequest::parse(&std::fs::read(dir.path().join("device.csr")).unwrap()).unwrap();
    assert_eq!(
        request.names(),
        ["fw.example", "192.0.2.9", "admin@example.com"]
    );

    // A weak RSA key is refused. Newer openssl may decline to make one,
    // in which case there is nothing to test.
    let (made, _) = openssl(
        dir.path(),
        &[
            "req",
            "-new",
            "-newkey",
            "rsa:1024",
            "-nodes",
            "-keyout",
            "weak.key",
            "-out",
            "weak.csr",
            "-subj",
            "/CN=old.example",
        ],
    );
    if made {
        let weak = std::fs::read(dir.path().join("weak.csr")).unwrap();
        assert!(matches!(
            SigningRequest::parse(&weak),
            Err(Error::InvalidRequest(_))
        ));
    }
}
