//! Builds complete chains with in-memory keys and checks that every
//! certificate has the shape its profile promises.

use time::{Duration, OffsetDateTime};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};
use yca_core::{
    Authority, Error, KeyPair, LeafRequest, PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256, RsaKeySize,
};

const IPSEC_IKE_OID: &str = "1.3.6.1.5.5.7.3.17";

fn ec_key() -> KeyPair {
    KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap()
}

fn rsa_key() -> KeyPair {
    KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap()
}

fn parse(der: &[u8]) -> X509Certificate<'_> {
    let (rest, cert) = X509Certificate::from_der(der).unwrap();
    assert!(rest.is_empty());
    cert
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// A root and an issuing CA below it.
fn two_tier(
    new_key: fn() -> KeyPair,
    at: OffsetDateTime,
) -> (Authority<KeyPair>, Authority<KeyPair>) {
    let root = Authority::create_root("Test Root CA", new_key(), at).unwrap();
    let issuing = root
        .create_issuing("Test Issuing CA", new_key(), at)
        .unwrap();
    (root, issuing)
}

fn check_full_chain(new_key: fn() -> KeyPair) {
    let at = now();
    let (root, issuing) = two_tier(new_key, at);
    let leaf_key = new_key();
    let leaf = issuing
        .issue(
            &LeafRequest::tls_server(["foo.example", "192.0.2.10"]).unwrap(),
            &leaf_key,
            at,
        )
        .unwrap();

    let root_cert = parse(root.certificate_der());
    let issuing_cert = parse(issuing.certificate_der());
    let leaf_cert = parse(leaf.der());

    // Signatures chain leaf -> issuing -> root -> root.
    root_cert
        .verify_signature(Some(root_cert.public_key()))
        .unwrap();
    issuing_cert
        .verify_signature(Some(root_cert.public_key()))
        .unwrap();
    leaf_cert
        .verify_signature(Some(issuing_cert.public_key()))
        .unwrap();
    assert!(
        leaf_cert
            .verify_signature(Some(root_cert.public_key()))
            .is_err()
    );

    // Root: CA with one level below it, valid for 20 years.
    assert!(root.is_root());
    let bc = root_cert.basic_constraints().unwrap().unwrap().value;
    assert!(bc.ca);
    assert_eq!(bc.path_len_constraint, Some(1));
    let ku = root_cert.key_usage().unwrap().unwrap().value;
    assert!(ku.key_cert_sign() && ku.crl_sign() && !ku.digital_signature());
    let root_lifetime = root.not_after() - root_cert.validity().not_before.to_datetime();
    assert_eq!(root_lifetime, Duration::days(20 * 365 + 5));

    // Issuing CA: no CAs below it, lives exactly as long as the root.
    assert!(!issuing.is_root());
    let bc = issuing_cert.basic_constraints().unwrap().unwrap().value;
    assert!(bc.ca);
    assert_eq!(bc.path_len_constraint, Some(0));
    assert_eq!(issuing.not_after(), root.not_after());
    assert_eq!(issuing_cert.issuer().as_raw(), root_cert.subject().as_raw());

    // Leaf: not a CA, server auth, both names in SAN, at most 825 days.
    let bc = leaf_cert.basic_constraints().unwrap().unwrap().value;
    assert!(!bc.ca);
    let eku = leaf_cert.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.server_auth && !eku.client_auth);
    let san = leaf_cert.subject_alternative_name().unwrap().unwrap().value;
    assert!(
        san.general_names
            .contains(&GeneralName::DNSName("foo.example"))
    );
    assert!(
        san.general_names
            .contains(&GeneralName::IPAddress(&[192, 0, 2, 10]))
    );
    let validity = leaf_cert.validity();
    let lifetime = validity.not_after.to_datetime() - validity.not_before.to_datetime();
    assert_eq!(lifetime, Duration::days(825) - Duration::seconds(1));
    assert_eq!(leaf.not_after(), validity.not_after.to_datetime());
    assert_eq!(leaf_cert.issuer().as_raw(), issuing_cert.subject().as_raw());
}

#[test]
fn full_chain_with_ecdsa_keys() {
    check_full_chain(ec_key);
}

#[test]
fn full_chain_with_rsa_keys() {
    check_full_chain(rsa_key);
    // RSA servers additionally get keyEncipherment.
    let at = now();
    let (_, issuing) = two_tier(rsa_key, at);
    let leaf = issuing
        .issue(
            &LeafRequest::tls_server(["foo.example"]).unwrap(),
            &rsa_key(),
            at,
        )
        .unwrap();
    let cert = parse(leaf.der());
    let ku = cert.key_usage().unwrap().unwrap().value;
    assert!(ku.digital_signature() && ku.key_encipherment());
}

#[test]
fn ecdsa_server_has_no_key_encipherment() {
    let at = now();
    let (_, issuing) = two_tier(ec_key, at);
    let leaf = issuing
        .issue(
            &LeafRequest::tls_server(["foo.example"]).unwrap(),
            &ec_key(),
            at,
        )
        .unwrap();
    let cert = parse(leaf.der());
    let ku = cert.key_usage().unwrap().unwrap().value;
    assert!(ku.digital_signature() && !ku.key_encipherment());
}

#[test]
fn tls_server_never_outlives_its_ca() {
    // A root created almost 20 years ago has about 100 days left.
    let at = now();
    let created = at - Duration::days(20 * 365 + 5 - 100);
    let root = Authority::create_root("Old Root", ec_key(), created).unwrap();
    let issuing = root.create_issuing("Issuing", ec_key(), at).unwrap();
    let leaf = issuing
        .issue(
            &LeafRequest::tls_server(["foo.example"]).unwrap(),
            &ec_key(),
            at,
        )
        .unwrap();
    assert_eq!(leaf.not_after(), root.not_after());
    assert!(leaf.not_after() - at < Duration::days(101));
}

#[test]
fn profiles_without_platform_limit_live_as_long_as_the_ca() {
    let at = now();
    let (_, issuing) = two_tier(ec_key, at);
    for request in [
        LeafRequest::tls_client("laptop").unwrap(),
        LeafRequest::ipsec_gateway(["vpn.example"]).unwrap(),
        LeafRequest::ipsec_client("alice@example.com").unwrap(),
    ] {
        let leaf = issuing.issue(&request, &ec_key(), at).unwrap();
        assert_eq!(leaf.not_after(), issuing.not_after(), "{request:?}");
    }
}

#[test]
fn ipsec_gateway_profile() {
    let at = now();
    let (_, issuing) = two_tier(ec_key, at);
    let leaf = issuing
        .issue(
            &LeafRequest::ipsec_gateway(["vpn.example", "2001:db8::1"]).unwrap(),
            &ec_key(),
            at,
        )
        .unwrap();
    let cert = parse(leaf.der());
    let eku = cert.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.server_auth);
    assert!(
        eku.other
            .iter()
            .any(|oid| oid.to_id_string() == IPSEC_IKE_OID)
    );
    let san = cert.subject_alternative_name().unwrap().unwrap().value;
    assert_eq!(san.general_names.len(), 2);
    assert!(
        san.general_names
            .contains(&GeneralName::DNSName("vpn.example"))
    );
}

#[test]
fn client_profiles() {
    let at = now();
    let (_, issuing) = two_tier(ec_key, at);

    let with_email = issuing
        .issue(
            &LeafRequest::ipsec_client("alice@example.com").unwrap(),
            &ec_key(),
            at,
        )
        .unwrap();
    let cert = parse(with_email.der());
    let eku = cert.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.client_auth && !eku.server_auth);
    let san = cert.subject_alternative_name().unwrap().unwrap().value;
    assert_eq!(
        san.general_names,
        vec![GeneralName::RFC822Name("alice@example.com")]
    );

    let with_name = issuing
        .issue(&LeafRequest::tls_client("laptop").unwrap(), &ec_key(), at)
        .unwrap();
    let cert = parse(with_name.der());
    assert!(cert.subject_alternative_name().unwrap().is_none());
    let cn = cert.subject().iter_common_name().next().unwrap();
    assert_eq!(cn.as_str().unwrap(), "laptop");
}

#[test]
fn fullchain_carries_the_intermediate_but_never_the_root() {
    let at = now();
    let (root, issuing) = two_tier(ec_key, at);
    let request = LeafRequest::tls_server(["foo.example"]).unwrap();

    let via_issuing = issuing.issue(&request, &ec_key(), at).unwrap();
    let chain = via_issuing.fullchain_pem();
    assert_eq!(chain.matches("BEGIN CERTIFICATE").count(), 2);
    assert!(chain.starts_with(&via_issuing.pem()));
    assert!(chain.ends_with(&issuing.certificate_pem()));

    // For a device that cannot handle a chain the root signs directly.
    let via_root = root.issue(&request, &ec_key(), at).unwrap();
    assert_eq!(via_root.fullchain_pem(), via_root.pem());
}

#[test]
fn serial_numbers_do_not_repeat_for_the_same_key() {
    let at = now();
    let (_, issuing) = two_tier(ec_key, at);
    let request = LeafRequest::tls_server(["foo.example"]).unwrap();
    let key = ec_key();
    let first = issuing.issue(&request, &key, at).unwrap();
    let second = issuing.issue(&request, &key, at).unwrap();
    assert_ne!(parse(first.der()).serial, parse(second.der()).serial);
}

#[test]
fn load_rejects_a_key_that_does_not_belong_to_the_certificate() {
    let root = Authority::create_root("Root", ec_key(), now()).unwrap();
    let result = Authority::load(root.certificate_der(), ec_key());
    assert!(matches!(result, Err(Error::KeyMismatch)));
}

#[test]
fn load_rejects_a_certificate_that_is_not_a_ca() {
    let at = now();
    let (_, issuing) = two_tier(ec_key, at);
    let leaf_key = ec_key();
    let leaf = issuing
        .issue(
            &LeafRequest::tls_server(["foo.example"]).unwrap(),
            &leaf_key,
            at,
        )
        .unwrap();
    assert!(matches!(
        Authority::load(leaf.der(), leaf_key),
        Err(Error::NotCa)
    ));
}

#[test]
fn load_reopens_a_stored_ca() {
    let at = now();
    let key = ec_key();
    let key_copy = KeyPair::try_from(key.serialize_der()).unwrap();
    let root = Authority::create_root("Root", key, at).unwrap();

    let reopened = Authority::load(root.certificate_der(), key_copy).unwrap();
    assert!(reopened.is_root());
    assert_eq!(reopened.not_after(), root.not_after());
    let leaf = reopened
        .issue(&LeafRequest::tls_client("laptop").unwrap(), &ec_key(), at)
        .unwrap();
    parse(leaf.der())
        .verify_signature(Some(parse(root.certificate_der()).public_key()))
        .unwrap();
}

#[test]
fn an_expired_ca_issues_nothing() {
    let at = now();
    let (root, issuing) = two_tier(ec_key, at);
    let later = root.not_after() + Duration::seconds(1);
    let request = LeafRequest::tls_client("laptop").unwrap();
    assert!(matches!(
        issuing.issue(&request, &ec_key(), later),
        Err(Error::CaExpired)
    ));
    assert!(matches!(
        root.create_issuing("Late", ec_key(), later),
        Err(Error::CaExpired)
    ));
}

#[test]
fn requests_need_a_name() {
    assert!(matches!(
        LeafRequest::tls_server(Vec::<String>::new()),
        Err(Error::InvalidRequest(_))
    ));
    assert!(matches!(
        LeafRequest::tls_client("  "),
        Err(Error::InvalidRequest(_))
    ));
    assert!(matches!(
        Authority::create_root(" ", ec_key(), now()),
        Err(Error::InvalidRequest(_))
    ));
}

/// A signer that claims one public key but signs with another, like a CA
/// certificate paired with the wrong YubiKey slot.
struct MismatchedKey {
    claimed: KeyPair,
    actual: KeyPair,
}

impl yca_core::PublicKeyData for MismatchedKey {
    fn der_bytes(&self) -> &[u8] {
        self.claimed.der_bytes()
    }

    fn algorithm(&self) -> &'static yca_core::SignatureAlgorithm {
        self.claimed.algorithm()
    }
}

impl yca_core::SigningKey for MismatchedKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.actual.sign(msg)
    }
}

#[test]
fn a_signature_from_the_wrong_private_key_never_leaves_the_library() {
    use yca_core::PublicKeyData;

    let at = now();
    let mismatched = || MismatchedKey {
        claimed: ec_key(),
        actual: ec_key(),
    };

    // A root whose own signature does not verify is refused.
    assert!(matches!(
        Authority::create_root("Root", mismatched(), at),
        Err(Error::KeyMismatch)
    ));

    // So is everything signed by a CA opened with such a key. `load` alone
    // cannot tell, because the public keys do match.
    let honest = ec_key();
    let root = Authority::create_root("Root", &honest, at).unwrap();
    let claimed = KeyPair::try_from(honest.serialize_der()).unwrap();
    assert_eq!(claimed.der_bytes(), honest.der_bytes());
    let impostor = Authority::load(
        root.certificate_der(),
        MismatchedKey {
            claimed,
            actual: ec_key(),
        },
    )
    .unwrap();
    assert!(matches!(
        impostor.issue(&LeafRequest::tls_client("laptop").unwrap(), &ec_key(), at),
        Err(Error::KeyMismatch)
    ));
    assert!(matches!(
        impostor.create_issuing("Issuing", ec_key(), at),
        Err(Error::KeyMismatch)
    ));
}

#[test]
fn full_chain_with_p384_keys() {
    // The curve of the CA keys already in use on the YubiKeys.
    check_full_chain(|| KeyPair::generate_for(&yca_core::PKCS_ECDSA_P384_SHA384).unwrap());
}

#[test]
fn a_requested_validity_shortens_but_never_extends() {
    let at = now();
    let (_, issuing) = two_tier(ec_key, at);
    let lifetime = |request: LeafRequest| {
        let leaf = issuing.issue(&request, &ec_key(), at).unwrap();
        let cert = parse(leaf.der());
        let validity = cert.validity();
        validity.not_after.to_datetime() - validity.not_before.to_datetime()
    };
    let one_second = Duration::seconds(1);

    let short = LeafRequest::tls_client("laptop")
        .unwrap()
        .valid_for(Duration::days(1))
        .unwrap();
    assert_eq!(lifetime(short), Duration::days(1) - one_second);

    // Asking for more than the platform accepts still gives 825 days.
    let long = LeafRequest::tls_server(["foo.example"])
        .unwrap()
        .valid_for(Duration::days(5000))
        .unwrap();
    assert_eq!(lifetime(long), Duration::days(825) - one_second);

    // Asking for more than the CA has left gives what the CA has left.
    let beyond_ca = LeafRequest::tls_client("laptop")
        .unwrap()
        .valid_for(Duration::days(365 * 100))
        .unwrap();
    let leaf = issuing.issue(&beyond_ca, &ec_key(), at).unwrap();
    assert_eq!(leaf.not_after(), issuing.not_after());

    assert!(matches!(
        LeafRequest::tls_client("laptop")
            .unwrap()
            .valid_for(Duration::ZERO),
        Err(Error::InvalidRequest(_))
    ));
}
