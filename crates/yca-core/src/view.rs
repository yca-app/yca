//! What a client is shown: the workspace, its certificates and the
//! connected YubiKeys as plain data.
//!
//! The window, the command line's `--json` and the MCP server all hand out
//! exactly this, so that whoever works with a workspace, a person or a
//! program on a person's behalf, sees the same thing in the same words.
//! How a certificate stands, which CA signed what and whether a YubiKey
//! holds what the workspace says are decided here, once.

use std::path::Path;

use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::device::{CaRole, Devices};
use crate::export::{CERTIFICATE_FILE, ExportForm, FULLCHAIN_FILE, P12_FILE};
use crate::{Error, LeafProfile, Record, Status, Store};

/// The slot of a YubiKey's own attestation certificate.
const ATTESTATION_SLOT: &str = "f9";

/// A YubiKey as a client is shown it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceView {
    pub serial: u32,
    pub firmware: String,
    pub pin_attempts_left: u8,
    /// The PIN, PUK or management key is still the factory one.
    pub factory_credentials: bool,
    /// The PIN is the one every YubiKey ships with. Such a key gets a PIN
    /// and a PUK of the user's own before a CA is put on it.
    pub factory_pin: bool,
    /// Slot 9c holds a key or a certificate. Putting a new CA on this key
    /// destroys it.
    pub slot_in_use: bool,
    /// What slot 9c holds is a key without a certificate, left by a CA
    /// that was not finished. Nothing of use can be signed with it.
    pub key_without_certificate: bool,
    /// Other PIV slots that hold a certificate, which a reset destroys
    /// along with the CA. The key's own attestation certificate is not
    /// among them: a reset leaves it.
    pub other_slots: Vec<String>,
    pub ca: Option<DeviceCaView>,
}

/// The CA a YubiKey holds.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCaView {
    pub role: &'static str,
    pub subject: String,
    pub not_after: String,
    pub algorithm: Option<&'static str>,
    pub generated_on_device: Option<bool>,
    pub touch_required: Option<bool>,
    /// `false` when the key in the slot is not the key of the certificate.
    pub key_matches_certificate: bool,
    /// For an issuing CA: whether the root in question signed it. That
    /// root is the open PKI's, or with no PKI open, the one root CA on a
    /// connected YubiKey. `None` for a root CA, and when there is no such
    /// root to check against.
    pub signed_by_root: Option<bool>,
    /// With a workspace open: whether this is, to the byte, the CA
    /// certificate the workspace has for this role. A YubiKey holds the
    /// real one, so `false` on the workspace's own key means the folder
    /// was changed, or the key was given another CA.
    pub matches_workspace: Option<bool>,
}

/// The CA certificates of the open workspace, which those on the
/// connected YubiKeys are held against.
pub struct WorkspaceCas {
    pub root: Vec<u8>,
    pub issuing: Option<Vec<u8>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnusableReaderView {
    pub reader: String,
    pub reason: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicesView {
    pub usable: Vec<DeviceView>,
    pub unusable: Vec<UnusableReaderView>,
}

/// A workspace as a client is shown it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PkiView {
    pub path: String,
    pub root: CaView,
    pub issuing: Option<CaView>,
    /// Issuing CAs that were replaced, oldest first.
    pub retired: Vec<RetiredView>,
    pub certificates: Vec<CertificateView>,
}

/// An issuing CA that was replaced. Its certificates stay valid unless
/// the root CA revoked it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetiredView {
    pub subject: String,
    /// Serial number of its certificate; what revoking it goes by.
    pub serial: String,
    pub not_after: String,
    pub revoked_at: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaView {
    pub subject: String,
    pub yubikey: u32,
    pub not_after: String,
    /// The workspace keeps the YubiKey's statement that the key of this
    /// CA was generated inside it, so that no copy of the key exists.
    pub key_attested: bool,
    /// Fingerprints of its certificate, to hold against what a device
    /// shows when it asks whether to trust it. Empty if they could not
    /// be worked out.
    pub sha256: String,
    pub sha1: String,
    pub revocation: RevocationView,
}

/// How the revocation list a CA signed last stands.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationView {
    /// Number of that list; `None` if the CA has not signed one yet.
    pub number: Option<u64>,
    /// Until when devices treat that list as current.
    pub next_update: Option<String>,
    /// Revoked certificates the list does not name yet.
    pub unlisted: usize,
    /// An issuing CA that this one took the place of had signed a list.
    /// Devices that were given that one check lists, and so want one of
    /// this CA too. Without it, a CA with no list is missing nothing.
    pub replaced_had_list: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateView {
    pub serial: String,
    pub profile: &'static str,
    pub names: Vec<String>,
    pub issued_by: &'static str,
    pub issued_at: String,
    pub not_after: String,
    pub status: &'static str,
    pub revoked_at: Option<String>,
    pub replaces: Option<String>,
    /// The group its owner sorted it into, if any.
    pub group: Option<String>,
    /// Where the CA that signed it stands: `current`, or an issuing CA
    /// that was `replaced` since, or one that was replaced and `revoked`.
    /// A certificate of a replaced CA cannot be revoked on its own; one
    /// of a revoked CA is refused by devices that check the root's list.
    pub issuer: &'static str,
    /// What to show in Finder to get to its files: the certificate inside
    /// its folder in the workspace, so that the folder opens with its
    /// files in view. `None` if the folder is gone.
    pub location: Option<String>,
    /// The form its files are in, after what the device's upload form
    /// asks for: `fullchain` (the certificate with the intermediate CA
    /// in one file, and the private key), `separate` (each in a file of
    /// its own) or `p12` (everything in one file that opens with a
    /// password). `None` if its folder holds none of them.
    pub form: Option<&'static str>,
    /// Whether its private key is in the workspace. Not for a certificate
    /// issued for a device's own request, nor for one issued again for a
    /// key that stayed with the certificate before it.
    pub has_key: bool,
}

/// The connected YubiKeys as a client is shown them.
///
/// With a workspace open, `workspace` names its folder, and each issuing
/// CA is checked against that workspace's root; otherwise against the
/// root CA on a connected YubiKey, if there is exactly one.
pub fn devices(found: Devices, workspace: Option<&Path>) -> DevicesView {
    let workspace = workspace.and_then(|path| {
        let store = Store::open(path).ok()?;
        Some(WorkspaceCas {
            root: store.ca_certificate_der(CaRole::Root).ok()?,
            issuing: store.ca_certificate_der(CaRole::Issuing).ok(),
        })
    });
    let root = match &workspace {
        Some(workspace) => Some(workspace.root.clone()),
        None => found
            .select_ca(CaRole::Root, None)
            .ok()
            .and_then(|device| device.ca.as_ref())
            .map(|ca| ca.certificate_der.clone()),
    };
    devices_view(found, root.as_deref(), workspace.as_ref())
}

/// The connected YubiKeys as a client is shown them. `root_certificate_der`
/// is the root CA that issuing CAs are checked against, if there is one;
/// `workspace` holds the CA certificates of the open workspace.
pub fn devices_view(
    found: Devices,
    root_certificate_der: Option<&[u8]>,
    workspace: Option<&WorkspaceCas>,
) -> DevicesView {
    DevicesView {
        usable: found
            .usable
            .into_iter()
            .map(|device| DeviceView {
                serial: device.serial,
                firmware: {
                    let (major, minor, patch) = device.firmware;
                    format!("{major}.{minor}.{patch}")
                },
                pin_attempts_left: device.pin_attempts_left,
                factory_credentials: device.factory.any(),
                factory_pin: device.factory.pin == Some(true),
                slot_in_use: device.signature_slot_in_use() || device.ca.is_some(),
                key_without_certificate: device.key_without_certificate,
                other_slots: device
                    .occupied_slots
                    .iter()
                    .filter(|slot| !slot.is_signature_slot && slot.slot != ATTESTATION_SLOT)
                    .map(|slot| slot.slot.clone())
                    .collect(),
                ca: device.ca.map(|ca| DeviceCaView {
                    role: role_name(ca.role),
                    signed_by_root: root_certificate_der
                        .filter(|_| ca.role == CaRole::Issuing)
                        .map(|root| ca.is_signed_by(root)),
                    matches_workspace: workspace.map(|workspace| match ca.role {
                        CaRole::Root => workspace.root == ca.certificate_der,
                        CaRole::Issuing => {
                            workspace.issuing.as_deref() == Some(ca.certificate_der.as_slice())
                        }
                    }),
                    not_after: timestamp(ca.not_after),
                    algorithm: ca.key.as_ref().map(|key| key.algorithm),
                    generated_on_device: ca.key.as_ref().and_then(|key| key.generated_on_device),
                    touch_required: ca.key.as_ref().map(|key| key.touch_required),
                    key_matches_certificate: ca
                        .key
                        .as_ref()
                        .is_none_or(|key| key.matches_certificate),
                    subject: ca.subject,
                }),
            })
            .collect(),
        unusable: found
            .unusable
            .into_iter()
            .map(|reader| UnusableReaderView {
                reader: reader.reader,
                reason: reader.reason,
            })
            .collect(),
    }
}

/// A workspace as a client is shown it.
pub fn workspace(store: &Store) -> Result<PkiView, Error> {
    let now = OffsetDateTime::now_utc();
    let ca_view = |role| {
        let prints = store.ca_fingerprints(role).ok();
        store.ca(role).map(|ca| CaView {
            sha256: prints
                .as_ref()
                .map(|p| p.sha256.clone())
                .unwrap_or_default(),
            sha1: prints.as_ref().map(|p| p.sha1.clone()).unwrap_or_default(),
            subject: ca.subject.clone(),
            yubikey: ca.yubikey,
            not_after: timestamp(ca.not_after),
            key_attested: store.attestation(role).is_some(),
            revocation: revocation_view(store, role, now),
        })
    };
    Ok(PkiView {
        root: ca_view(CaRole::Root)
            .ok_or_else(|| Error::Store("the workspace folder has no root CA".to_owned()))?,
        issuing: ca_view(CaRole::Issuing),
        retired: store
            .retired()
            .iter()
            .map(|ca| RetiredView {
                subject: ca.subject.clone(),
                serial: ca.serial.clone(),
                not_after: timestamp(ca.not_after),
                revoked_at: ca.revoked_at.map(timestamp),
            })
            .collect(),
        // Newest first: what was just issued is what people look for.
        certificates: store
            .records()
            .iter()
            .rev()
            .map(|record| certificate_view(store, record, now))
            .collect(),
        path: store.dir().to_string_lossy().into_owned(),
    })
}

/// A list that cannot be read counts as none: everything revoked then
/// waits for a new one, which is the safe way to be wrong.
fn revocation_view(store: &Store, role: CaRole, now: OffsetDateTime) -> RevocationView {
    match store.crl_status(role, now) {
        Ok(status) => RevocationView {
            number: status.number,
            next_update: status.next_update.map(timestamp),
            unlisted: status.unlisted,
            replaced_had_list: status.replaced_had_list,
        },
        Err(_) => RevocationView {
            number: None,
            next_update: None,
            unlisted: store.revoked(role, now).len(),
            replaced_had_list: false,
        },
    }
}

pub fn certificate_view(store: &Store, record: &Record, now: OffsetDateTime) -> CertificateView {
    let issuer = match store.retired_issuer(record) {
        None => "current",
        Some(ca) if ca.revoked_at.is_some() => "revoked",
        Some(_) => "replaced",
    };
    CertificateView {
        issuer,
        location: store.certificate_location(record).map(|place| {
            // Shown inside its folder, Finder opens the folder itself.
            let shown = [FULLCHAIN_FILE, CERTIFICATE_FILE, P12_FILE]
                .iter()
                .map(|name| place.join(name))
                .find(|inside| inside.is_file())
                .unwrap_or(place);
            shown.to_string_lossy().into_owned()
        }),
        form: store.form(record).map(ExportForm::name),
        has_key: store.has_key(record),
        serial: record.serial.clone(),
        profile: match record.profile {
            LeafProfile::TlsServer => "tls-server",
            LeafProfile::TlsClient => "tls-client",
            LeafProfile::IpsecGateway => "ipsec-gateway",
            LeafProfile::IpsecClient => "ipsec-client",
        },
        names: record.names.clone(),
        group: record.group.clone(),
        issued_by: role_name(record.issued_by),
        issued_at: timestamp(record.issued_at),
        not_after: timestamp(record.not_after),
        status: match record.status(now) {
            // Revoked along with the issuing CA that signed it: devices
            // that have the root CA's list refuse it like any other.
            Status::Valid | Status::ExpiresSoon if issuer == "revoked" => "revoked",
            Status::Valid => "valid",
            Status::ExpiresSoon => "expires-soon",
            Status::Expired => "expired",
            Status::Revoked => "revoked",
        },
        revoked_at: record.revoked_at.map(timestamp),
        replaces: record.replaces.clone(),
    }
}

pub fn role_name(role: CaRole) -> &'static str {
    match role {
        CaRole::Root => "root",
        CaRole::Issuing => "issuing",
    }
}

pub fn timestamp(moment: OffsetDateTime) -> String {
    moment
        .format(&Rfc3339)
        .expect("a certificate date fits RFC 3339")
}
