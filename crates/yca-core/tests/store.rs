//! The workspace folder and its register, exercised with in-memory keys.

use std::fs;

use time::{Duration, OffsetDateTime};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};
use yca_core::device::CaRole;
use yca_core::{
    Attestation, Authority, Error, ExportFile, ExportForm, ExportSource, KeyPair, LeafProfile,
    LeafRequest, P12Encryption, PKCS_ECDSA_P256_SHA256, Repack, Status, Store, export,
};

const ROOT_KEY: u32 = 1001;
const ISSUING_KEY: u32 = 1002;

fn key() -> KeyPair {
    KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap()
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn parse(der: &[u8]) -> X509Certificate<'_> {
    X509Certificate::from_der(der).unwrap().1
}

struct Pki {
    root: Authority<KeyPair>,
    issuing: Authority<KeyPair>,
    store: Store,
    _dir: tempfile::TempDir,
}

/// A root, an issuing CA and a folder that knows both.
fn pki() -> Pki {
    let at = now();
    let root = Authority::create_root("Test Root CA", key(), at).unwrap();
    let issuing = root.create_issuing("Test Issuing CA", key(), at).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut store =
        Store::create(dir.path().join("pki"), root.certificate_der(), ROOT_KEY).unwrap();
    store
        .set_issuing(issuing.certificate_der(), ISSUING_KEY)
        .unwrap();
    Pki {
        root,
        issuing,
        store,
        _dir: dir,
    }
}

#[test]
fn a_new_folder_knows_its_cas() {
    let pki = pki();
    let root = pki.store.ca(CaRole::Root).unwrap();
    assert_eq!(root.subject, "CN=Test Root CA");
    assert_eq!(root.yubikey, ROOT_KEY);
    assert_eq!(root.not_after, pki.root.not_after());
    let issuing = pki.store.ca(CaRole::Issuing).unwrap();
    assert_eq!(issuing.subject, "CN=Test Issuing CA");
    assert_eq!(issuing.yubikey, ISSUING_KEY);

    assert_eq!(
        pki.store.ca_certificate_der(CaRole::Root).unwrap(),
        pki.root.certificate_der()
    );
    assert_eq!(
        pki.store.ca_certificate_der(CaRole::Issuing).unwrap(),
        pki.issuing.certificate_der()
    );
    assert!(pki.store.records().is_empty());
}

#[test]
fn a_folder_with_the_root_alone_signs_with_it() {
    // The whole authority on one YubiKey: no issuing CA, so the root is
    // what signs from day to day.
    let at = now();
    let root = Authority::create_root("Lone Root CA", key(), at).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut store =
        Store::create(dir.path().join("pki"), root.certificate_der(), ROOT_KEY).unwrap();
    assert_eq!(store.everyday_ca(), CaRole::Root);

    let request = LeafRequest::tls_server(["nas.example"]).unwrap();
    let issued = root.issue(&request, &key(), at).unwrap();
    store
        .record(&issued, &request, store.everyday_ca(), None, at)
        .unwrap();
    let reopened = Store::open(store.dir()).unwrap();
    assert_eq!(reopened.everyday_ca(), CaRole::Root);
    assert_eq!(reopened.records()[0].issued_by, CaRole::Root);

    // An issuing CA added later, on a second YubiKey, takes over.
    let issuing = root.create_issuing("Later Issuing CA", key(), at).unwrap();
    store
        .set_issuing(issuing.certificate_der(), ISSUING_KEY)
        .unwrap();
    assert_eq!(store.everyday_ca(), CaRole::Issuing);
}

#[test]
fn issued_certificates_survive_closing_and_reopening() {
    let mut pki = pki();
    let at = now();
    let request = LeafRequest::tls_server(["foo.example", "192.0.2.10"]).unwrap();
    let issued = pki.issuing.issue(&request, &key(), at).unwrap();
    let serial = issued.serial().unwrap();
    pki.store
        .record(&issued, &request, CaRole::Issuing, None, at)
        .unwrap();

    let reopened = Store::open(pki.store.dir()).unwrap();
    assert_eq!(reopened.records(), pki.store.records());
    let record = &reopened.records()[0];
    assert_eq!(record.serial, serial);
    assert_eq!(record.profile, LeafProfile::TlsServer);
    assert_eq!(record.names, ["foo.example", "192.0.2.10"]);
    assert_eq!(record.issued_by, CaRole::Issuing);
    assert_eq!(record.not_after, issued.not_after());
    assert_eq!(record.revoked_at, None);
    assert_eq!(reopened.certificate_der(record).unwrap(), issued.der());
    assert_eq!(reopened.ca(CaRole::Issuing), pki.store.ca(CaRole::Issuing));
}

#[test]
fn the_folder_is_plain_files_other_tools_can_read() {
    let mut pki = pki();
    let at = now();
    let request = LeafRequest::ipsec_client("alice@example.com").unwrap();
    let issued = pki.issuing.issue(&request, &key(), at).unwrap();
    pki.store
        .record(&issued, &request, CaRole::Issuing, None, at)
        .unwrap();
    let dir = pki.store.dir();

    let meta = fs::read_to_string(dir.join("ca.toml")).unwrap();
    assert!(meta.contains("[root]") && meta.contains("[issuing]"));
    assert!(meta.contains(&format!("yubikey = {ROOT_KEY}")));

    let index = fs::read_to_string(dir.join("index.toml")).unwrap();
    assert!(index.contains("[[certificate]]"));
    assert!(index.contains("profile = \"ipsec-client\""));
    assert!(index.contains("issued_by = \"issuing\""));
    assert!(index.contains("alice@example.com"));

    // The certificate has a folder named after it, for the files that go
    // onto the device, and the register keeps a copy of its own.
    assert!(dir.join("certificates/alice@example.com").is_dir());
    let stored = dir.join(format!("register/{}.pem", issued.serial().unwrap()));
    assert_eq!(fs::read_to_string(stored).unwrap(), issued.pem());
    assert!(
        fs::read_to_string(dir.join("root.pem"))
            .unwrap()
            .starts_with("-----BEGIN CERTIFICATE-----")
    );

    // The register writes no private key of its own accord: one only
    // gets here with the files of a certificate that was issued with it.
    for entry in walk(dir) {
        // Not every file is text: the root CA for devices is binary.
        let contents = fs::read(&entry).unwrap();
        let text = String::from_utf8_lossy(&contents);
        assert!(!text.contains("PRIVATE KEY"), "{}", entry.display());
        assert!(!entry.to_string_lossy().ends_with(".tmp"));
    }

    // The folder tells whoever comes across it what it is, and accounts
    // for everything that lies next to the explanation.
    let readme = fs::read_to_string(dir.join("README.txt")).unwrap();
    assert!(readme.contains("What about private keys"));
    for entry in fs::read_dir(dir).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        // The root CA for devices carries the CA's own name.
        let named_after_ca = name == "Test Root CA.crt" && readme.contains("The .crt file");
        assert!(
            name == "README.txt" || named_after_ca || readme.contains(&name),
            "README.txt does not mention {name}"
        );
    }
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(walk(&path));
        } else {
            files.push(path);
        }
    }
    files
}

#[test]
fn status_follows_the_calendar_and_revocation() {
    let mut pki = pki();
    let at = now();
    let request = LeafRequest::tls_server(["foo.example"])
        .unwrap()
        .valid_for(Duration::days(90))
        .unwrap();
    let issued = pki.issuing.issue(&request, &key(), at).unwrap();
    let serial = issued.serial().unwrap();
    pki.store
        .record(&issued, &request, CaRole::Issuing, None, at)
        .unwrap();
    let record = pki.store.records()[0].clone();

    assert_eq!(record.status(at), Status::Valid);
    assert_eq!(record.status(at + Duration::days(59)), Status::Valid);
    assert_eq!(record.status(at + Duration::days(61)), Status::ExpiresSoon);
    assert_eq!(record.status(at + Duration::days(91)), Status::Expired);

    let revoked = pki.store.revoke(&serial, at).unwrap().clone();
    assert!(revoked.revoked_at.is_some());
    assert_eq!(revoked.status(at), Status::Revoked);
    // Revoked stays revoked, even after it would have expired.
    assert_eq!(revoked.status(at + Duration::days(365)), Status::Revoked);
    assert!(matches!(
        pki.store.revoke(&serial, at),
        Err(Error::Store(_))
    ));

    let reopened = Store::open(pki.store.dir()).unwrap();
    assert_eq!(reopened.records()[0], revoked);
}

#[test]
fn a_certificate_is_found_by_the_start_of_its_serial() {
    let mut pki = pki();
    let at = now();
    let request = LeafRequest::tls_client("laptop").unwrap();
    let mut serials = Vec::new();
    for _ in 0..3 {
        let issued = pki.issuing.issue(&request, &key(), at).unwrap();
        serials.push(issued.serial().unwrap());
        pki.store
            .record(&issued, &request, CaRole::Issuing, None, at)
            .unwrap();
    }

    let full = &serials[1];
    assert_eq!(&pki.store.find(full).unwrap().serial, full);
    assert_eq!(&pki.store.find(&full[..12]).unwrap().serial, full);
    assert_eq!(&pki.store.find(&full.to_uppercase()).unwrap().serial, full);
    assert!(matches!(pki.store.find("zz"), Err(Error::Store(_))));
    assert!(matches!(pki.store.find(""), Err(Error::Store(_))));
}

#[test]
fn reissuing_changes_the_name_and_keeps_the_key() {
    let mut pki = pki();
    let at = now();
    let device_key = key();
    let old_request = LeafRequest::tls_server(["switch-old.example"]).unwrap();
    let old = pki.issuing.issue(&old_request, &device_key, at).unwrap();
    let old_serial = old.serial().unwrap();
    pki.store
        .record(&old, &old_request, CaRole::Issuing, None, at)
        .unwrap();

    // Later: only the register and the YubiKey are at hand, not the
    // device's private key.
    let record = pki.store.find(&old_serial).unwrap().clone();
    let previous = pki.store.certificate_der(&record).unwrap();
    let new_request = LeafRequest::for_profile(record.profile, ["switch-new.example"]).unwrap();
    let new = pki.issuing.reissue(&new_request, &previous, at).unwrap();
    pki.store
        .record(&new, &new_request, record.issued_by, Some(&old_serial), at)
        .unwrap();

    let old_cert = parse(old.der());
    let new_cert = parse(new.der());
    assert_eq!(new_cert.public_key().raw, old_cert.public_key().raw);
    assert_ne!(new_cert.serial, old_cert.serial);
    new_cert
        .verify_signature(Some(parse(pki.issuing.certificate_der()).public_key()))
        .unwrap();
    let san = new_cert.subject_alternative_name().unwrap().unwrap().value;
    assert_eq!(
        san.general_names,
        vec![GeneralName::DNSName("switch-new.example")]
    );

    let replacement = pki.store.records().last().unwrap();
    assert_eq!(replacement.replaces.as_deref(), Some(old_serial.as_str()));
    assert_eq!(replacement.names, ["switch-new.example"]);
    // The old certificate is untouched until someone revokes it.
    assert_eq!(
        pki.store.find(&old_serial).unwrap().status(at),
        Status::Valid
    );
}

#[test]
fn a_certificate_issued_by_the_root_is_recorded_as_such() {
    let mut pki = pki();
    let at = now();
    let request = LeafRequest::tls_server(["old-switch.example"]).unwrap();
    let issued = pki.root.issue(&request, &key(), at).unwrap();
    let record = pki
        .store
        .record(&issued, &request, CaRole::Root, None, at)
        .unwrap();
    assert_eq!(record.issued_by, CaRole::Root);
}

#[test]
fn the_register_refuses_what_does_not_belong() {
    let mut pki = pki();
    let at = now();
    let request = LeafRequest::tls_client("laptop").unwrap();

    // Signed by the issuing CA but claimed for the root, and the reverse.
    let by_issuing = pki.issuing.issue(&request, &key(), at).unwrap();
    assert!(matches!(
        pki.store
            .record(&by_issuing, &request, CaRole::Root, None, at),
        Err(Error::Store(_))
    ));

    // Signed by a CA of some other PKI.
    let stranger = Authority::create_root("Other Root", key(), at).unwrap();
    let foreign = stranger.issue(&request, &key(), at).unwrap();
    assert!(matches!(
        pki.store
            .record(&foreign, &request, CaRole::Issuing, None, at),
        Err(Error::Store(_))
    ));
    assert!(pki.store.records().is_empty());

    // The same certificate twice.
    pki.store
        .record(&by_issuing, &request, CaRole::Issuing, None, at)
        .unwrap();
    assert!(matches!(
        pki.store
            .record(&by_issuing, &request, CaRole::Issuing, None, at),
        Err(Error::Store(_))
    ));
    assert_eq!(pki.store.records().len(), 1);
}

#[test]
fn a_folder_holds_exactly_one_pki() {
    let pki = pki();
    let other_root = Authority::create_root("Other Root", key(), now()).unwrap();
    assert!(matches!(
        Store::create(pki.store.dir(), other_root.certificate_der(), 7),
        Err(Error::Store(_))
    ));

    let empty = tempfile::tempdir().unwrap();
    assert!(matches!(Store::open(empty.path()), Err(Error::Store(_))));
}

#[test]
fn only_real_cas_are_accepted() {
    let at = now();
    let root = Authority::create_root("Root", key(), at).unwrap();
    let issuing = root.create_issuing("Issuing", key(), at).unwrap();
    let leaf = issuing
        .issue(&LeafRequest::tls_client("laptop").unwrap(), &key(), at)
        .unwrap();
    let dir = tempfile::tempdir().unwrap();

    // The root must be a self-signed CA.
    assert!(matches!(
        Store::create(dir.path().join("a"), issuing.certificate_der(), 1),
        Err(Error::Store(_))
    ));
    assert!(matches!(
        Store::create(dir.path().join("b"), leaf.der(), 1),
        Err(Error::NotCa)
    ));

    // The issuing CA must be signed by this root.
    let mut store = Store::create(dir.path().join("c"), root.certificate_der(), 1).unwrap();
    let other_root = Authority::create_root("Other Root", key(), at).unwrap();
    let other_issuing = other_root
        .create_issuing("Other Issuing", key(), at)
        .unwrap();
    assert!(matches!(
        store.set_issuing(other_issuing.certificate_der(), 2),
        Err(Error::Store(_))
    ));
    assert!(matches!(
        store.set_issuing(root.certificate_der(), 2),
        Err(Error::Store(_))
    ));
    assert!(store.ca(CaRole::Issuing).is_none());
    assert!(matches!(
        store.ca_certificate_der(CaRole::Issuing),
        Err(Error::Store(_))
    ));
}

#[test]
fn client_profiles_take_exactly_one_name() {
    assert!(LeafRequest::for_profile(LeafProfile::TlsClient, ["a", "b"]).is_err());
    assert!(LeafRequest::for_profile(LeafProfile::IpsecClient, ["a"]).is_ok());
    assert!(LeafRequest::for_profile(LeafProfile::TlsServer, ["a", "b"]).is_ok());
    assert!(LeafRequest::for_profile(LeafProfile::IpsecGateway, Vec::<String>::new()).is_err());
}

#[test]
fn a_replaced_issuing_ca_is_kept_and_its_certificates_are_not_the_new_ones() {
    let mut pki = pki();
    let at = now();
    let request = LeafRequest::tls_client("laptop").unwrap();
    let by_old = pki.issuing.issue(&request, &key(), at).unwrap();
    let old_serial = by_old.serial().unwrap();
    pki.store
        .record(&by_old, &request, CaRole::Issuing, None, at)
        .unwrap();
    let old_certificate = pki.issuing.certificate_der().to_vec();

    // The issuing YubiKey is lost: the root signs a new issuing CA.
    let replacement = pki
        .root
        .create_issuing("Second Issuing CA", key(), at)
        .unwrap();
    pki.store
        .set_issuing(replacement.certificate_der(), 2002)
        .unwrap();
    assert_eq!(pki.store.ca(CaRole::Issuing).unwrap().yubikey, 2002);
    assert_eq!(
        pki.store.ca_certificate_der(CaRole::Issuing).unwrap(),
        replacement.certificate_der()
    );

    // The old certificate is still on file, for the chains that need it.
    let retired: Vec<_> = fs::read_dir(pki.store.dir().join("retired"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(retired.len(), 1);
    let kept = pem::parse(fs::read_to_string(&retired[0]).unwrap()).unwrap();
    assert_eq!(kept.contents(), old_certificate.as_slice());

    // The new CA issues and revokes its own certificates only.
    let by_new = replacement.issue(&request, &key(), at).unwrap();
    let new_serial = by_new.serial().unwrap();
    pki.store
        .record(&by_new, &request, CaRole::Issuing, None, at)
        .unwrap();
    let old_record = pki.store.find(&old_serial).unwrap();
    let new_record = pki.store.find(&new_serial).unwrap();
    assert!(old_record.issuer_key_id.is_some());
    assert_ne!(old_record.issuer_key_id, new_record.issuer_key_id);

    // With the old CA's key gone no list can name its certificates, so
    // the register does not pretend to revoke one.
    assert_eq!(
        pki.store
            .retired_issuer(pki.store.find(&old_serial).unwrap())
            .map(|ca| ca.subject.as_str()),
        Some("CN=Test Issuing CA")
    );
    assert!(
        pki.store
            .retired_issuer(pki.store.find(&new_serial).unwrap())
            .is_none()
    );
    assert!(matches!(
        pki.store.revoke(&old_serial, at),
        Err(Error::Store(_))
    ));
    pki.store.revoke(&new_serial, at).unwrap();
    let on_list: Vec<_> = pki
        .store
        .revoked(CaRole::Issuing, at)
        .into_iter()
        .map(|entry| entry.serial)
        .collect();
    assert_eq!(on_list, vec![new_serial]);

    // A certificate of the old CA is refused as one of the new CA.
    let late = pki.issuing.issue(&request, &key(), at).unwrap();
    assert!(matches!(
        pki.store.record(&late, &request, CaRole::Issuing, None, at),
        Err(Error::Store(_))
    ));

    // Setting the same issuing CA again retires nothing.
    pki.store
        .set_issuing(replacement.certificate_der(), 2002)
        .unwrap();
    assert_eq!(
        fs::read_dir(pki.store.dir().join("retired"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn deleting_takes_a_certificate_out_of_the_register_and_the_folder() {
    let mut pki = pki();
    let at = now();
    let request = LeafRequest::tls_server(["nas.example"]).unwrap();
    let kept = pki.issuing.issue(&request, &key(), at).unwrap();
    let gone = pki.issuing.issue(&request, &key(), at).unwrap();
    for issued in [&kept, &gone] {
        pki.store
            .record(issued, &request, CaRole::Issuing, None, at)
            .unwrap();
    }
    let gone_serial = gone.serial().unwrap();
    // The second certificate of the same name got a folder with a number.
    let copy = pki.store.dir().join(format!("register/{gone_serial}.pem"));
    assert!(copy.exists());
    assert!(pki.store.dir().join("certificates/nas.example 2").is_dir());
    assert_eq!(
        pki.store
            .certificate_location(pki.store.find(&gone_serial).unwrap()),
        Some(pki.store.dir().join("certificates/nas.example 2"))
    );

    let deleted = pki.store.delete(&gone_serial[..8], at).unwrap();
    assert_eq!(deleted.record.serial, gone_serial);
    // It was never revoked, so nothing of it has to stay.
    assert!(!deleted.revocation_kept);
    assert!(!copy.exists());
    // Its folder went with it; the other certificate's is untouched.
    assert!(!pki.store.dir().join("certificates/nas.example 2").exists());
    assert!(pki.store.dir().join("certificates/nas.example").is_dir());
    assert!(
        pki.store
            .dir()
            .join(format!("register/{}.pem", kept.serial().unwrap()))
            .exists()
    );
    assert!(pki.store.revoked(CaRole::Issuing, at).is_empty());

    let reopened = Store::open(pki.store.dir()).unwrap();
    let left: Vec<_> = reopened.records().iter().map(|r| &r.serial).collect();
    assert_eq!(left, [&kept.serial().unwrap()]);
    assert!(matches!(
        pki.store.delete(&gone_serial, at),
        Err(Error::Store(_))
    ));
}

#[test]
fn a_deleted_certificate_stays_revoked_until_it_would_have_expired() {
    let mut pki = pki();
    let at = now();
    let request = LeafRequest::tls_client("laptop")
        .unwrap()
        .valid_for(Duration::days(30))
        .unwrap();
    let issued = pki.issuing.issue(&request, &key(), at).unwrap();
    let serial = issued.serial().unwrap();
    pki.store
        .record(&issued, &request, CaRole::Issuing, None, at)
        .unwrap();
    pki.store.revoke(&serial, at).unwrap();

    let deleted = pki.store.delete(&serial, at).unwrap();
    assert!(deleted.revocation_kept);
    assert!(pki.store.records().is_empty());

    // Gone from the register, but the revocation list goes on naming it,
    // also after the folder was closed and opened again.
    let mut reopened = Store::open(pki.store.dir()).unwrap();
    let listed = reopened.revoked(CaRole::Issuing, at);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].serial, serial);
    assert_eq!(
        reopened.crl_status(CaRole::Issuing, at).unwrap().unlisted,
        1
    );
    assert!(reopened.revoked(CaRole::Root, at).is_empty());

    // Once it would have expired nobody accepts it anyway: the list drops
    // it, and the next deletion clears what was kept of it.
    let later = at + Duration::days(31);
    assert!(reopened.revoked(CaRole::Issuing, later).is_empty());
    let other = pki.issuing.issue(&request, &key(), at).unwrap();
    reopened
        .record(&other, &request, CaRole::Issuing, None, at)
        .unwrap();
    reopened.delete(&other.serial().unwrap(), later).unwrap();
    let index = fs::read_to_string(reopened.dir().join("index.toml")).unwrap();
    assert!(!index.contains(&serial), "{index}");
}

#[test]
fn a_revoked_certificate_that_expired_leaves_nothing_behind() {
    let mut pki = pki();
    let at = now();
    let request = LeafRequest::tls_client("laptop")
        .unwrap()
        .valid_for(Duration::days(30))
        .unwrap();
    let issued = pki.issuing.issue(&request, &key(), at).unwrap();
    let serial = issued.serial().unwrap();
    pki.store
        .record(&issued, &request, CaRole::Issuing, None, at)
        .unwrap();
    pki.store.revoke(&serial, at).unwrap();

    let deleted = pki.store.delete(&serial, at + Duration::days(31)).unwrap();
    assert!(!deleted.revocation_kept);
    let index = fs::read_to_string(pki.store.dir().join("index.toml")).unwrap();
    assert!(!index.contains(&serial), "{index}");
}

#[test]
fn a_certificate_revoked_before_its_ca_was_replaced_drops_off_the_list() {
    let mut pki = pki();
    let at = now();
    let request = LeafRequest::tls_client("laptop").unwrap();
    let issued = pki.issuing.issue(&request, &key(), at).unwrap();
    let serial = issued.serial().unwrap();
    pki.store
        .record(&issued, &request, CaRole::Issuing, None, at)
        .unwrap();
    pki.store.revoke(&serial, at).unwrap();
    assert_eq!(pki.store.revoked(CaRole::Issuing, at).len(), 1);

    let replacement = pki
        .root
        .create_issuing("Second Issuing CA", key(), at)
        .unwrap();
    pki.store
        .set_issuing(replacement.certificate_der(), 2002)
        .unwrap();
    // The new issuing CA cannot speak for the certificates of the old.
    assert!(pki.store.revoked(CaRole::Issuing, at).is_empty());
}

#[test]
fn the_root_revokes_a_replaced_issuing_ca_as_a_whole() {
    let mut pki = pki();
    let at = now();
    let old_serial: String = parse(pki.issuing.certificate_der())
        .raw_serial()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert!(pki.store.retired().is_empty());
    // An issuing CA that is still in use is not the root's to revoke here.
    assert!(matches!(
        pki.store.revoke_retired(&old_serial, at),
        Err(Error::Store(_))
    ));

    let replacement = pki
        .root
        .create_issuing("Second Issuing CA", key(), at)
        .unwrap();
    pki.store
        .set_issuing(replacement.certificate_der(), 2002)
        .unwrap();
    let [retired] = pki.store.retired() else {
        panic!("expected one replaced issuing CA");
    };
    assert_eq!(retired.subject, "CN=Test Issuing CA");
    assert_eq!(retired.serial, old_serial);
    assert_eq!(retired.not_after, pki.issuing.not_after());
    assert_eq!(retired.revoked_at, None);
    // Lost is not stolen: nothing is revoked unless asked for.
    assert!(pki.store.revoked(CaRole::Root, at).is_empty());

    // The YubiKey may be in someone else's hands after all.
    pki.store.revoke_retired(&old_serial, at).unwrap();
    assert!(matches!(
        pki.store.revoke_retired(&old_serial, at),
        Err(Error::Store(_))
    ));
    let reopened = Store::open(pki.store.dir()).unwrap();
    let listed = reopened.revoked(CaRole::Root, at);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].serial, old_serial);
    assert!(reopened.revoked(CaRole::Issuing, at).is_empty());
    assert_eq!(reopened.crl_status(CaRole::Root, at).unwrap().unlisted, 1);

    // The root signs a list that names it, which other tools accept.
    let number = reopened.next_crl_number(CaRole::Root).unwrap();
    let list = pki.root.revocation_list(&listed, number, at).unwrap();
    assert_eq!(list.len(), 1);

    // Past its own end the retired CA is refused anyway.
    let much_later = pki.issuing.not_after() + Duration::days(1);
    assert!(reopened.revoked(CaRole::Root, much_later).is_empty());
}

#[test]
fn a_folder_whose_ca_certificate_was_exchanged_does_not_open() {
    let pki = pki();
    let at = now();
    let dir = pki.store.dir().to_path_buf();
    let root_file = dir.join("root.pem");
    let issuing_file = dir.join("issuing.pem");
    let real_root = fs::read_to_string(&root_file).unwrap();
    let real_issuing = fs::read_to_string(&issuing_file).unwrap();
    let other_root = Authority::create_root("Test Root CA", key(), at).unwrap();
    let other_issuing = other_root
        .create_issuing("Test Issuing CA", key(), at)
        .unwrap();

    // Another root under the same name: the issuing CA is not its.
    fs::write(&root_file, other_root.certificate_pem()).unwrap();
    let Err(Error::Store(why)) = Store::open(&dir) else {
        panic!("a folder with a foreign root opened");
    };
    assert!(why.contains("not signed by the root CA"), "{why}");

    // Another issuing CA under the real root.
    fs::write(&root_file, &real_root).unwrap();
    fs::write(&issuing_file, other_issuing.certificate_pem()).unwrap();
    assert!(matches!(Store::open(&dir), Err(Error::Store(_))));

    // Something that is no root at all where the root belongs.
    fs::write(&issuing_file, &real_issuing).unwrap();
    fs::write(&root_file, &real_issuing).unwrap();
    assert!(matches!(Store::open(&dir), Err(Error::Store(_))));

    // Put back as it was, it opens.
    fs::write(&root_file, &real_root).unwrap();
    Store::open(&dir).unwrap();
}

#[test]
fn a_kept_attestation_counts_only_for_the_ca_it_is_about() {
    let pki = pki();
    let at = now();
    assert!(pki.store.attestation(CaRole::Root).is_none());

    // A stand-in for a YubiKey's attestation key and for what it states:
    // a certificate over the attested key.
    let device = Authority::create_root("YubiKey PIV Attestation", key(), at).unwrap();
    let statement = LeafRequest::tls_client("YubiKey PIV Attestation 9c").unwrap();
    let stated_about = |attested: &KeyPair, by: &Authority<KeyPair>| Attestation {
        certificate_der: by.issue(&statement, attested, at).unwrap().der().to_vec(),
        intermediate_der: device.certificate_der().to_vec(),
    };

    let about_root = stated_about(pki.root.key(), &device);
    pki.store
        .save_attestation(CaRole::Root, &about_root)
        .unwrap();
    assert_eq!(
        pki.store.attestation(CaRole::Root),
        Some(about_root.clone())
    );

    // The same statement filed under the issuing CA says nothing about it.
    pki.store
        .save_attestation(CaRole::Issuing, &about_root)
        .unwrap();
    assert!(pki.store.attestation(CaRole::Issuing).is_none());

    // Nor does one that the attestation key it comes with did not sign.
    let somebody = Authority::create_root("Somebody", key(), at).unwrap();
    pki.store
        .save_attestation(CaRole::Issuing, &stated_about(pki.issuing.key(), &somebody))
        .unwrap();
    assert!(pki.store.attestation(CaRole::Issuing).is_none());

    pki.store
        .save_attestation(CaRole::Issuing, &stated_about(pki.issuing.key(), &device))
        .unwrap();
    assert!(pki.store.attestation(CaRole::Issuing).is_some());
}

#[test]
fn a_certificate_folder_is_named_for_its_owner_and_holds_its_files() {
    let mut pki = pki();
    let at = now();

    // Names a file system could take amiss still make a folder, and none
    // of them leads out of the workspace.
    for (name, folder) in [
        ("nas.home.example", "nas.home.example"),
        ("*.home.example", "_.home.example"),
        ("fd00::1", "fd00__1"),
        ("alice@example.com", "alice@example.com"),
        ("../../elsewhere", "_.._elsewhere"),
        ("..", "certificate"),
    ] {
        let made = pki.store.new_certificate_folder(name, None).unwrap();
        assert_eq!(made.name(), folder, "{name}");
        assert_eq!(
            made.path(),
            pki.store.dir().join("certificates").join(folder)
        );
    }
    // Still empty when let go of, as after a wrong PIN: gone again.
    assert!(
        !pki.store
            .dir()
            .join("certificates/nas.home.example")
            .exists()
    );

    // Made before the YubiKey signs, filled once it has.
    let request = LeafRequest::tls_server(["nas.home.example", "192.168.1.20"]).unwrap();
    let device_key = key();
    let issued = pki.issuing.issue(&request, &device_key, at).unwrap();
    let folder = pki
        .store
        .new_certificate_folder("nas.home.example", None)
        .unwrap();
    let record = pki
        .store
        .record_in(&folder, &issued, &request, CaRole::Issuing, None, at)
        .unwrap()
        .clone();
    assert_eq!(record.folder, "nas.home.example");
    let private = ExportFile {
        name: "private-key.key".to_owned(),
        contents: device_key.serialize_pem().into_bytes(),
        holds_private_key: true,
        purpose: "the private key",
    };
    let public = ExportFile {
        name: "fullchain.crt".to_owned(),
        contents: issued.fullchain_pem().into_bytes(),
        holds_private_key: false,
        purpose: "the certificate and its chain",
    };
    folder.write(&private).unwrap();
    folder.write(&public).unwrap();
    let path = folder.path().to_path_buf();
    drop(folder);

    // The folder stays, with the key readable by its owner only.
    let mut names: Vec<_> = fs::read_dir(&path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    // Nothing but what was put there: the register reads its own copy.
    assert_eq!(names, ["fullchain.crt", "private-key.key"]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |name: &str| fs::metadata(path.join(name)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode("private-key.key"), 0o600);
        assert_ne!(mode("fullchain.crt") & 0o044, 0);
    }
    assert_eq!(pki.store.certificate_der(&record).unwrap(), issued.der());

    // Deleting the certificate takes its files, the key included, and
    // leaves alone what somebody else put next to them. What Finder left
    // there after a look is nobody's to keep.
    fs::write(path.join("notes.txt"), "installed on the NAS in March").unwrap();
    fs::write(path.join(".DS_Store"), [0u8; 4]).unwrap();
    pki.store.delete(&record.serial, at).unwrap();
    let left: Vec<_> = fs::read_dir(&path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, ["notes.txt"]);
}

#[test]
fn the_root_ca_is_there_as_a_file_devices_install() {
    let pki = pki();
    let dir = pki.store.dir();

    // Made with the workspace: binary, named after the CA, ending in .crt.
    let file = dir.join("Test Root CA.crt");
    assert_eq!(fs::read(&file).unwrap(), pki.root.certificate_der());
    assert_eq!(pki.store.root_for_devices().unwrap(), file);

    // A workspace from before has none, and gets it when asked.
    fs::remove_file(&file).unwrap();
    let reopened = Store::open(dir).unwrap();
    assert!(!file.exists());
    assert_eq!(reopened.root_for_devices().unwrap(), file);
    assert_eq!(fs::read(&file).unwrap(), pki.root.certificate_der());

    // One that was damaged is put right.
    fs::write(&file, b"not a certificate").unwrap();
    reopened.root_for_devices().unwrap();
    assert_eq!(fs::read(&file).unwrap(), pki.root.certificate_der());

    // What a device shows next to it: SHA-256 and SHA-1, as pairs.
    let prints = pki.store.ca_fingerprints(CaRole::Root).unwrap();
    assert_eq!(prints.sha256.split(' ').count(), 32);
    assert_eq!(prints.sha1.split(' ').count(), 20);
    assert!(
        prints
            .sha256
            .chars()
            .all(|c| c == ' ' || c.is_ascii_digit() || c.is_ascii_uppercase())
    );
    assert_ne!(prints, pki.store.ca_fingerprints(CaRole::Issuing).unwrap());
}

/// Issues a web server certificate for one name and enters it into the
/// register, in a group or in none.
fn issue_into(pki: &mut Pki, name: &str, group: Option<&str>) -> String {
    let at = now();
    let request = LeafRequest::tls_server([name]).unwrap();
    let issued = pki.issuing.issue(&request, &key(), at).unwrap();
    let folder = pki.store.new_certificate_folder(name, group).unwrap();
    pki.store
        .record_in(&folder, &issued, &request, CaRole::Issuing, None, at)
        .unwrap()
        .serial
        .clone()
}

#[test]
fn a_certificate_in_a_group_lives_in_the_folder_of_the_group() {
    let mut pki = pki();
    let certificates = pki.store.dir().join("certificates");

    // Stray spaces are not part of the name.
    let nas = issue_into(&mut pki, "nas.acme.example", Some("  Acme   Ltd "));
    let record = pki.store.find(&nas).unwrap().clone();
    assert_eq!(record.group.as_deref(), Some("Acme Ltd"));
    assert_eq!(record.folder, "Acme Ltd/nas.acme.example");
    assert!(certificates.join("Acme Ltd/nas.acme.example").is_dir());
    assert_eq!(
        pki.store.certificate_location(&record),
        Some(certificates.join("Acme Ltd/nas.acme.example"))
    );

    // The same group spelled another way is still the same group.
    let switch = issue_into(&mut pki, "switch.acme.example", Some("acme ltd"));
    let record = pki.store.find(&switch).unwrap();
    assert_eq!(record.group.as_deref(), Some("Acme Ltd"));
    assert_eq!(record.folder, "Acme Ltd/switch.acme.example");

    // A certificate in no group is where it always was.
    let printer = issue_into(&mut pki, "printer.home.example", None);
    let record = pki.store.find(&printer).unwrap();
    assert_eq!(record.group, None);
    assert_eq!(record.folder, "printer.home.example");

    issue_into(&mut pki, "nas.zeta.example", Some("zeta"));
    assert_eq!(pki.store.groups(), ["Acme Ltd", "zeta"]);

    // The register remembers.
    let reopened = Store::open(pki.store.dir()).unwrap();
    assert_eq!(
        reopened.find(&nas).unwrap().group.as_deref(),
        Some("Acme Ltd")
    );
    assert_eq!(reopened.groups(), ["Acme Ltd", "zeta"]);
}

#[test]
fn moving_a_certificate_to_another_group_moves_its_folder() {
    let mut pki = pki();
    let certificates = pki.store.dir().join("certificates");
    let nas = issue_into(&mut pki, "nas.home.example", None);

    let record = pki.store.set_group(&nas, Some("Office")).unwrap();
    assert_eq!(record.group.as_deref(), Some("Office"));
    assert_eq!(record.folder, "Office/nas.home.example");
    assert!(!certificates.join("nas.home.example").exists());
    assert!(certificates.join("Office/nas.home.example").is_dir());
    // Its certificate is still found where the register says.
    let record = record.clone();
    assert!(pki.store.certificate_der(&record).is_ok());

    // On to another group: the folder of the one it leaves empty goes.
    pki.store.set_group(&nas, Some("Site B")).unwrap();
    assert!(!certificates.join("Office").exists());
    assert!(certificates.join("Site B/nas.home.example").is_dir());

    // And out of any group, even after Finder has looked into the folder.
    fs::write(certificates.join("Site B/.DS_Store"), b"finder").unwrap();
    let record = pki.store.set_group(&nas, None).unwrap();
    assert_eq!(record.group, None);
    assert_eq!(record.folder, "nas.home.example");
    assert!(!certificates.join("Site B").exists());
    assert!(pki.store.groups().is_empty());

    // Asked for the group it is in, nothing moves.
    let record = pki.store.set_group(&nas, Some("  ")).unwrap();
    assert_eq!(record.folder, "nas.home.example");

    // Where its name is taken, it gets a number like any other.
    let twin = issue_into(&mut pki, "nas.home.example", Some("Office"));
    let record = pki.store.set_group(&twin, None).unwrap();
    assert_eq!(record.folder, "nas.home.example 2");
    assert!(certificates.join("nas.home.example 2").is_dir());

    let reopened = Store::open(pki.store.dir()).unwrap();
    assert_eq!(reopened.find(&twin).unwrap().folder, "nas.home.example 2");
}

#[test]
fn a_renewed_certificate_stays_in_its_group() {
    let mut pki = pki();
    let at = now();
    let old = issue_into(&mut pki, "nas.acme.example", Some("Acme"));

    let request = LeafRequest::tls_server(["nas.acme.example"]).unwrap();
    let renewed = pki.issuing.issue(&request, &key(), at).unwrap();
    let record = pki
        .store
        .record(&renewed, &request, CaRole::Issuing, Some(&old), at)
        .unwrap();
    assert_eq!(record.group.as_deref(), Some("Acme"));
    assert_eq!(record.folder, "Acme/nas.acme.example 2");
}

#[test]
fn the_folder_of_a_group_goes_with_its_last_certificate() {
    let mut pki = pki();
    let at = now();
    let certificates = pki.store.dir().join("certificates");
    let first = issue_into(&mut pki, "nas.acme.example", Some("Acme"));
    let second = issue_into(&mut pki, "switch.acme.example", Some("Acme"));

    pki.store.delete(&first, at).unwrap();
    assert!(certificates.join("Acme/switch.acme.example").is_dir());
    pki.store.delete(&second, at).unwrap();
    assert!(!certificates.join("Acme").exists());
    assert!(pki.store.groups().is_empty());

    // A folder made for a signature that never came leaves nothing of a
    // new group behind either.
    let unused = pki
        .store
        .new_certificate_folder("nas.other.example", Some("Other"))
        .unwrap();
    assert!(certificates.join("Other/nas.other.example").is_dir());
    drop(unused);
    assert!(!certificates.join("Other").exists());
}

#[test]
fn a_group_and_a_certificate_never_share_a_folder() {
    let mut pki = pki();
    // A certificate and a group that would make the same folder, on a disk
    // that does not tell upper case from lower.
    let plain = issue_into(&mut pki, "acme.example", None);
    let grouped = issue_into(&mut pki, "nas.acme.example", Some("ACME.example"));
    assert_eq!(pki.store.find(&plain).unwrap().folder, "acme.example");
    assert_eq!(
        pki.store.find(&grouped).unwrap().folder,
        "ACME.example 2/nas.acme.example"
    );
    // The group keeps the folder it got.
    let second = issue_into(&mut pki, "switch.acme.example", Some("ACME.example"));
    assert_eq!(
        pki.store.find(&second).unwrap().folder,
        "ACME.example 2/switch.acme.example"
    );
}

#[test]
fn the_name_of_a_group_cannot_lead_out_of_the_workspace() {
    let mut pki = pki();
    assert_eq!(pki.store.group_name("   ").unwrap(), None);
    assert!(pki.store.group_name(&"x".repeat(61)).is_err());
    assert!(pki.store.group_name("two\u{0}lines").is_err());
    assert!(
        pki.store
            .new_certificate_folder("nas.home.example", Some(&"x".repeat(61)))
            .is_err()
    );

    // The name is the owner's to choose; the folder is made safe.
    let serial = issue_into(&mut pki, "nas.home.example", Some("../../elsewhere"));
    let record = pki.store.find(&serial).unwrap();
    assert_eq!(record.group.as_deref(), Some("../../elsewhere"));
    assert_eq!(record.folder, "_.._elsewhere/nas.home.example");
}

#[test]
fn a_register_that_points_out_of_the_workspace_is_refused() {
    let mut pki = pki();
    issue_into(&mut pki, "nas.home.example", None);
    let index = pki.store.dir().join("index.toml");
    let text = fs::read_to_string(&index).unwrap();
    assert!(text.contains("folder = \"nas.home.example\""));
    for elsewhere in ["../../elsewhere", "/etc", "a/b/c", "a//b", "./a"] {
        fs::write(
            &index,
            text.replace(
                "folder = \"nas.home.example\"",
                &format!("folder = \"{elsewhere}\""),
            ),
        )
        .unwrap();
        assert!(
            matches!(Store::open(pki.store.dir()), Err(Error::Store(_))),
            "{elsewhere}"
        );
    }
}

#[test]
fn two_programs_changing_the_workspace_lose_nothing() {
    let mut pki = pki();
    let at = now();
    let first = issue_into(&mut pki, "nas.home.example", None);
    let stamp = Store::stamp(pki.store.dir()).unwrap();

    // The window and the command line, say: each opened the workspace
    // before the other changed it.
    let mut window = Store::open(pki.store.dir()).unwrap();
    let mut command = Store::open(pki.store.dir()).unwrap();

    let request = LeafRequest::tls_server(["switch.home.example"]).unwrap();
    let issued = pki.issuing.issue(&request, &key(), at).unwrap();
    let second = window
        .record(&issued, &request, CaRole::Issuing, None, at)
        .unwrap()
        .serial
        .clone();
    // The other one's copy of the register is stale by now. Its change is
    // made on what the disk says all the same.
    command.revoke(&first, at).unwrap();
    command.set_group(&second, Some("Network")).unwrap();
    // And back: the first program deletes what the second one moved.
    window.delete(&second, at).unwrap();
    assert!(!pki.store.dir().join("certificates/Network").exists());

    let after = Store::open(pki.store.dir()).unwrap();
    assert_eq!(after.records().len(), 1);
    assert!(after.find(&first).unwrap().revoked_at.is_some());
    // Whoever shows the workspace can tell that it changed.
    assert_ne!(Store::stamp(pki.store.dir()).unwrap(), stamp);
    assert_eq!(Store::stamp(pki.store.dir().join("nowhere")), None);
}

#[test]
fn a_change_waits_for_another_programs_change_to_finish() {
    let mut pki = pki();
    let at = now();
    let serial = issue_into(&mut pki, "nas.home.example", None);

    // Another program has the workspace for a moment.
    let lock = fs::OpenOptions::new()
        .write(true)
        .open(pki.store.dir().join(".lock"))
        .unwrap();
    lock.lock().unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(300));
        drop(lock);
    });
    let started = std::time::Instant::now();
    pki.store.revoke(&serial, at).unwrap();
    assert!(started.elapsed() >= std::time::Duration::from_millis(250));
    release.join().unwrap();
}

/// Issues a certificate and puts its files into its folder in a form, the
/// way the window and the command line do. With a key, or as for a
/// device's own request, without.
fn issue_with_files(
    pki: &mut Pki,
    name: &str,
    by: CaRole,
    form: ExportForm,
    with_key: bool,
) -> (String, KeyPair) {
    let at = now();
    let request = LeafRequest::tls_server([name]).unwrap();
    let device_key = key();
    let issued = match by {
        CaRole::Root => pki.root.issue(&request, &device_key, at),
        CaRole::Issuing => pki.issuing.issue(&request, &device_key, at),
    }
    .unwrap();
    let folder = pki.store.new_certificate_folder(name, None).unwrap();
    let serial = pki
        .store
        .record_in(&folder, &issued, &request, by, None, at)
        .unwrap()
        .serial
        .clone();
    let key_der = device_key.serialize_der();
    let files = export(
        form,
        ExportSource {
            issued: &issued,
            private_key_der: with_key.then_some(key_der.as_slice()),
        },
        None,
    )
    .unwrap();
    for file in &files {
        folder.write(file).unwrap();
    }
    (serial, device_key)
}

/// The names of the files in a certificate's folder, in order.
fn files_of(pki: &Pki, folder: &str) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(pki.store.dir().join("certificates").join(folder))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn repack(form: ExportForm) -> Repack<'static> {
    Repack {
        form,
        opens: None,
        password: None,
        encryption: P12Encryption::Modern,
    }
}

#[test]
fn the_files_of_a_certificate_can_be_written_again_in_another_form() {
    let mut pki = pki();
    let (serial, device_key) = issue_with_files(
        &mut pki,
        "nas.home.example",
        CaRole::Issuing,
        ExportForm::Fullchain,
        true,
    );
    let folder = pki.store.dir().join("certificates/nas.home.example");
    let record = pki.store.find(&serial).unwrap().clone();
    assert_eq!(pki.store.form(&record), Some(ExportForm::Fullchain));
    assert!(pki.store.has_key(&record));
    assert_eq!(
        files_of(&pki, "nas.home.example"),
        ["fullchain.crt", "private-key.key"]
    );
    let leaf = encode(&pki.store.certificate_der(&record).unwrap());

    // Three fields instead of two: the same certificate and key, with the
    // intermediate CA in a file of its own, and nothing left of before.
    let repacked = pki
        .store
        .repackage(&serial, repack(ExportForm::Separate))
        .unwrap();
    assert_eq!(repacked.folder, folder);
    assert_eq!(
        files_of(&pki, "nas.home.example"),
        ["certificate.crt", "intermediate-ca.crt", "private-key.key"]
    );
    assert_eq!(
        fs::read_to_string(folder.join("certificate.crt")).unwrap(),
        leaf
    );
    assert_eq!(
        fs::read_to_string(folder.join("intermediate-ca.crt")).unwrap(),
        pki.issuing.certificate_pem()
    );
    assert_eq!(
        fs::read_to_string(folder.join("private-key.key")).unwrap(),
        device_key.serialize_pem()
    );
    assert_eq!(pki.store.form(&record), Some(ExportForm::Separate));

    // One file with a password: the key is inside it now and nowhere else.
    assert!(matches!(
        pki.store.repackage(&serial, repack(ExportForm::Pkcs12)),
        Err(Error::InvalidRequest(_))
    ));
    pki.store
        .repackage(
            &serial,
            Repack {
                password: Some("correct horse"),
                ..repack(ExportForm::Pkcs12)
            },
        )
        .unwrap();
    assert_eq!(files_of(&pki, "nas.home.example"), ["certificate.p12"]);
    assert_eq!(pki.store.form(&record), Some(ExportForm::Pkcs12));
    assert!(pki.store.has_key(&record));

    // Out of it again takes its password, and a wrong one changes nothing.
    for opens in [None, Some("wrong")] {
        assert!(matches!(
            pki.store.repackage(
                &serial,
                Repack {
                    opens,
                    ..repack(ExportForm::Fullchain)
                }
            ),
            Err(Error::InvalidRequest(_))
        ));
        assert_eq!(files_of(&pki, "nas.home.example"), ["certificate.p12"]);
    }
    pki.store
        .repackage(
            &serial,
            Repack {
                opens: Some("correct horse"),
                ..repack(ExportForm::Fullchain)
            },
        )
        .unwrap();
    assert_eq!(
        files_of(&pki, "nas.home.example"),
        ["fullchain.crt", "private-key.key"]
    );
    assert_eq!(
        fs::read_to_string(folder.join("private-key.key")).unwrap(),
        device_key.serialize_pem()
    );
    assert_eq!(
        fs::read_to_string(folder.join("fullchain.crt")).unwrap(),
        format!("{leaf}{}", pki.issuing.certificate_pem())
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(folder.join("private-key.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // The register is as it was: nothing was issued.
    assert_eq!(pki.store.records().len(), 1);
    assert_eq!(encode(&pki.store.certificate_der(&record).unwrap()), leaf);
    // What its owner put beside the files is not the app's to remove.
    fs::write(folder.join("notes.txt"), "on the NAS").unwrap();
    pki.store
        .repackage(&serial, repack(ExportForm::Separate))
        .unwrap();
    assert!(folder.join("notes.txt").exists());
}

fn encode(der: &[u8]) -> String {
    pem::encode_config(
        &pem::Pem::new("CERTIFICATE", der),
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    )
}

#[test]
fn a_certificate_for_a_device_s_own_key_has_no_key_to_pack() {
    let mut pki = pki();
    let (serial, _) = issue_with_files(
        &mut pki,
        "switch.home.example",
        CaRole::Issuing,
        ExportForm::Fullchain,
        false,
    );
    let record = pki.store.find(&serial).unwrap().clone();
    assert!(!pki.store.has_key(&record));
    assert_eq!(files_of(&pki, "switch.home.example"), ["fullchain.crt"]);

    pki.store
        .repackage(&serial, repack(ExportForm::Separate))
        .unwrap();
    assert_eq!(
        files_of(&pki, "switch.home.example"),
        ["certificate.crt", "intermediate-ca.crt"]
    );
    // One file with everything would have nothing to be the key in it.
    assert!(matches!(
        pki.store.repackage(
            &serial,
            Repack {
                password: Some("correct horse"),
                ..repack(ExportForm::Pkcs12)
            }
        ),
        Err(Error::InvalidRequest(_))
    ));
    assert_eq!(
        files_of(&pki, "switch.home.example"),
        ["certificate.crt", "intermediate-ca.crt"]
    );
}

#[test]
fn signed_by_the_root_a_certificate_has_one_form_of_separate_files() {
    let mut pki = pki();
    let (serial, _) = issue_with_files(
        &mut pki,
        "printer.home.example",
        CaRole::Root,
        ExportForm::Separate,
        true,
    );
    let record = pki.store.find(&serial).unwrap().clone();
    assert_eq!(
        files_of(&pki, "printer.home.example"),
        ["certificate.crt", "private-key.key"]
    );
    // No intermediate CA either way, so it goes by one name.
    assert_eq!(pki.store.form(&record), Some(ExportForm::Fullchain));
    pki.store
        .repackage(&serial, repack(ExportForm::Fullchain))
        .unwrap();
    assert_eq!(
        files_of(&pki, "printer.home.example"),
        ["certificate.crt", "private-key.key"]
    );
}

#[test]
fn a_certificate_of_a_replaced_issuing_ca_keeps_that_ca_in_its_chain() {
    let mut pki = pki();
    let (serial, _) = issue_with_files(
        &mut pki,
        "nas.home.example",
        CaRole::Issuing,
        ExportForm::Fullchain,
        true,
    );
    let replacement = pki
        .root
        .create_issuing("Test Issuing CA 2", key(), now())
        .unwrap();
    pki.store
        .set_issuing(replacement.certificate_der(), 2002)
        .unwrap();

    pki.store
        .repackage(&serial, repack(ExportForm::Separate))
        .unwrap();
    let intermediate = fs::read_to_string(
        pki.store
            .dir()
            .join("certificates/nas.home.example/intermediate-ca.crt"),
    )
    .unwrap();
    // The CA that signed it, not the one that signs today.
    assert_eq!(intermediate, pki.issuing.certificate_pem());
    assert_ne!(intermediate, replacement.certificate_pem());
}

/// Sets the format a workspace says it is in, as another build of yca
/// would have left it.
fn set_format(pki: &Pki, version: u32) {
    let file = pki.store.dir().join("ca.toml");
    let meta = fs::read_to_string(&file).unwrap();
    let line = meta
        .lines()
        .find(|line| line.starts_with("version = "))
        .unwrap()
        .to_owned();
    fs::write(&file, meta.replace(&line, &format!("version = {version}"))).unwrap();
}

#[test]
fn a_workspace_of_a_newer_format_is_refused() {
    let mut pki = pki();
    assert_eq!(format_of(&pki), "version = 1");
    let (serial, _) = issue_with_files(
        &mut pki,
        "nas.home.example",
        CaRole::Issuing,
        ExportForm::Fullchain,
        true,
    );

    // On opening, and also when it moved on while this build had it open.
    set_format(&pki, 2);
    let refused = pki.store.revoke(&serial, now()).unwrap_err().to_string();
    assert!(refused.contains("newer version"), "{refused}");
    let Err(refused) = Store::open(pki.store.dir()) else {
        panic!("a workspace of a later format was opened");
    };
    assert!(refused.to_string().contains("newer version"), "{refused}");
    // Nothing was touched by trying.
    assert_eq!(format_of(&pki), "version = 2");
}

fn format_of(pki: &Pki) -> String {
    fs::read_to_string(pki.store.dir().join("ca.toml"))
        .unwrap()
        .lines()
        .find(|line| line.starts_with("version = "))
        .unwrap()
        .to_owned()
}

#[test]
fn a_key_in_clear_beside_the_one_file_is_never_called_p12() {
    // Where going into the .p12 file was interrupted after the file was
    // written and before the key in clear was removed.
    let mut pki = pki();
    let (serial, device_key) = issue_with_files(
        &mut pki,
        "nas.home.example",
        CaRole::Issuing,
        ExportForm::Fullchain,
        true,
    );
    let folder = pki.store.dir().join("certificates/nas.home.example");
    let record = pki.store.find(&serial).unwrap().clone();
    let chain = fs::read(folder.join("fullchain.crt")).unwrap();
    let into_one = Repack {
        password: Some("correct horse"),
        ..repack(ExportForm::Pkcs12)
    };
    pki.store.repackage(&serial, into_one).unwrap();
    fs::write(folder.join("fullchain.crt"), chain).unwrap();
    fs::write(folder.join("private-key.key"), device_key.serialize_pem()).unwrap();

    // The folder is called by the form whose key lies open.
    assert_eq!(pki.store.form(&record), Some(ExportForm::Fullchain));
    assert!(pki.store.has_key(&record));
    // Done again, it is finished: the key is in the file and nowhere else.
    pki.store.repackage(&serial, into_one).unwrap();
    assert_eq!(files_of(&pki, "nas.home.example"), ["certificate.p12"]);
    assert_eq!(pki.store.form(&record), Some(ExportForm::Pkcs12));
}

#[test]
fn what_an_unfinished_write_left_behind_goes_with_the_rest() {
    let mut pki = pki();
    let (serial, device_key) = issue_with_files(
        &mut pki,
        "nas.home.example",
        CaRole::Issuing,
        ExportForm::Fullchain,
        true,
    );
    let folder = pki.store.dir().join("certificates/nas.home.example");
    // A private key under the name it had while it was being written.
    let stray = folder.join(".private-key.key.tmp");
    fs::write(&stray, device_key.serialize_pem()).unwrap();

    pki.store
        .repackage(&serial, repack(ExportForm::Separate))
        .unwrap();
    assert!(!stray.exists());
    assert_eq!(
        files_of(&pki, "nas.home.example"),
        ["certificate.crt", "intermediate-ca.crt", "private-key.key"]
    );

    // Deleting takes them as well, so that the folder goes.
    fs::write(&stray, device_key.serialize_pem()).unwrap();
    fs::write(folder.join(".certificate.p12.tmp"), "half a file").unwrap();
    pki.store.delete(&serial, now()).unwrap();
    assert!(!folder.exists());
}

#[test]
fn a_file_that_cannot_take_its_place_leaves_nothing_behind() {
    let pki = pki();
    let folder = pki
        .store
        .new_certificate_folder("nas.home.example", None)
        .unwrap();
    let key_file = ExportFile {
        name: "private-key.key".to_owned(),
        contents: key().serialize_pem().into_bytes(),
        holds_private_key: true,
        purpose: "the private key",
    };
    // Something is in the way that a file cannot replace.
    let in_the_way = folder.path().join("private-key.key");
    fs::create_dir(&in_the_way).unwrap();
    assert!(folder.write(&key_file).is_err());
    // The key did not stay under the name it was written under.
    assert!(!folder.path().join(".private-key.key.tmp").exists());
    fs::remove_dir(&in_the_way).unwrap();
}

#[cfg(unix)]
#[test]
fn deleting_takes_the_private_key_before_anything_can_stop_it() {
    use std::os::unix::fs::PermissionsExt;
    let lock = |dir: &std::path::Path, mode: u32| {
        fs::set_permissions(dir, fs::Permissions::from_mode(mode)).unwrap();
    };
    let mut pki = pki();
    let (serial, _) = issue_with_files(
        &mut pki,
        "nas.home.example",
        CaRole::Issuing,
        ExportForm::Fullchain,
        true,
    );
    let (other, _) = issue_with_files(
        &mut pki,
        "switch.home.example",
        CaRole::Issuing,
        ExportForm::Fullchain,
        true,
    );
    let dir = pki.store.dir().to_path_buf();
    // Whoever runs the tests as root is stopped by nothing.
    lock(&dir.join("register"), 0o555);
    if fs::remove_file(dir.join(format!("register/{serial}.pem"))).is_ok() {
        return;
    }

    // The register's own copy cannot be removed. The certificate is
    // deleted all the same as far as it matters: its key is gone.
    assert!(pki.store.delete(&serial, now()).is_err());
    assert!(
        !dir.join("certificates/nas.home.example/private-key.key")
            .exists()
    );
    lock(&dir.join("register"), 0o755);

    // Where the key itself cannot be removed, nothing is deleted: the
    // entry stays, to find the key by on the next attempt.
    let folder = dir.join("certificates/switch.home.example");
    lock(&folder, 0o555);
    assert!(pki.store.delete(&other, now()).is_err());
    assert!(folder.join("private-key.key").exists());
    assert!(Store::open(&dir).unwrap().find(&other).is_ok());
    lock(&folder, 0o755);
    pki.store.delete(&other, now()).unwrap();
    assert!(!folder.exists());
}

#[test]
fn writing_the_files_anew_tells_whoever_watches_the_workspace() {
    // Nothing in the register changes, but what a window shows of the
    // certificate does: its form, and whether its key is there.
    let mut pki = pki();
    let (serial, _) = issue_with_files(
        &mut pki,
        "nas.home.example",
        CaRole::Issuing,
        ExportForm::Fullchain,
        true,
    );
    let before = Store::stamp(pki.store.dir()).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    pki.store
        .repackage(&serial, repack(ExportForm::Separate))
        .unwrap();
    assert_ne!(Store::stamp(pki.store.dir()).unwrap(), before);
}

#[test]
fn an_entry_that_does_not_name_its_signer_still_finds_the_ca_that_signed_it() {
    // As in a register from before the entries named the signer, once
    // the issuing CA of then was replaced.
    let mut pki = pki();
    let (serial, _) = issue_with_files(
        &mut pki,
        "nas.home.example",
        CaRole::Issuing,
        ExportForm::Fullchain,
        true,
    );
    let replacement = pki
        .root
        .create_issuing("Test Issuing CA 2", key(), now())
        .unwrap();
    pki.store
        .set_issuing(replacement.certificate_der(), 2002)
        .unwrap();
    let index_file = pki.store.dir().join("index.toml");
    let index = fs::read_to_string(&index_file).unwrap();
    let named: String = index
        .lines()
        .filter(|line| !line.starts_with("issuer_key_id"))
        .map(|line| format!("{line}\n"))
        .collect();
    assert_ne!(named, index);
    fs::write(&index_file, named).unwrap();

    let mut old = Store::open(pki.store.dir()).unwrap();
    old.repackage(&serial, repack(ExportForm::Separate))
        .unwrap();
    assert_eq!(
        fs::read_to_string(
            pki.store
                .dir()
                .join("certificates/nas.home.example/intermediate-ca.crt")
        )
        .unwrap(),
        pki.issuing.certificate_pem()
    );
}
