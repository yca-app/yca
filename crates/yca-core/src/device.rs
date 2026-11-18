//! Discovery of connected YubiKeys.
//!
//! Everything here only reads from the device and needs no PIN. Nothing in
//! this module can change a PIN, generate a key or overwrite a slot.

use std::fmt;

use der::Encode;
use rcgen::{PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PublicKeyData, SignatureAlgorithm};
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, X509Certificate};
use yubikey::piv::{self, AlgorithmId, Key, ManagementSlotId, Origin, SlotAlgorithmId, SlotId};
use yubikey::reader::Context;
use yubikey::{PinPolicy, TouchPolicy, YubiKey};

use crate::Error;

/// The PIV slot yca keeps a CA key in: 9c, "Digital Signature".
pub(crate) const CA_SLOT: SlotId = SlotId::Signature;

/// A connected YubiKey with a usable PIV application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// Serial number printed on the key; tells the root key from the
    /// issuing key.
    pub serial: u32,
    /// Firmware version as (major, minor, patch).
    pub firmware: (u8, u8, u8),
    /// Name of the PC/SC reader the key shows up as.
    pub reader: String,
    /// How many wrong PINs the key still tolerates before it locks.
    pub pin_attempts_left: u8,
    /// Which of the key's credentials are still the ones every YubiKey
    /// leaves the factory with.
    pub factory: FactoryCredentials,
    /// PIV slots that already hold a certificate.
    pub occupied_slots: Vec<OccupiedSlot>,
    /// The CA held in slot 9c, if there is one.
    pub ca: Option<StoredCa>,
}

impl Device {
    /// RSA 3072 and 4096 keys need firmware 5.7 or newer; older keys stop
    /// at RSA 2048.
    pub fn supports_large_rsa(&self) -> bool {
        self.firmware >= (5, 7, 0)
    }

    /// Whether the slot yca uses for a CA key (9c) already holds something.
    /// Setting up a new CA on such a key would overwrite it.
    pub fn signature_slot_in_use(&self) -> bool {
        self.occupied_slots
            .iter()
            .any(|slot| slot.is_signature_slot)
    }
}

/// Whether a YubiKey still has the PIN, PUK and management key it was
/// made with. Those are public knowledge, so a key in this state protects
/// nothing. `None` means the firmware (older than 5.3) cannot tell.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FactoryCredentials {
    /// The PIN is the factory one.
    pub pin: Option<bool>,
    /// The PUK is the factory one.
    pub puk: Option<bool>,
    /// The management key is the factory one.
    pub management_key: Option<bool>,
}

impl FactoryCredentials {
    /// Whether anything is known to still be at its factory value.
    pub fn any(&self) -> bool {
        [self.pin, self.puk, self.management_key].contains(&Some(true))
    }

    pub(crate) fn read(yubikey: &mut YubiKey) -> Self {
        let mut is_factory = |slot| {
            piv::metadata(yubikey, SlotId::Management(slot))
                .ok()
                .and_then(|metadata| metadata.default)
        };
        Self {
            pin: is_factory(ManagementSlotId::Pin),
            puk: is_factory(ManagementSlotId::Puk),
            management_key: is_factory(ManagementSlotId::Management),
        }
    }
}

/// A PIV slot that holds a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OccupiedSlot {
    /// Slot name as used by Yubico's tools, for example `9c`.
    pub slot: String,
    /// Whether this is slot 9c, the one yca uses for a CA key.
    pub is_signature_slot: bool,
    /// Subject of the certificate stored in the slot.
    pub subject: String,
    /// Issuer of the certificate stored in the slot.
    pub issuer: String,
}

/// Which of the two CAs a YubiKey holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaRole {
    /// The self-signed root, normally kept in a safe.
    Root,
    /// The CA signed by the root that issues everyday certificates.
    Issuing,
}

impl fmt::Display for CaRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CaRole::Root => "root CA",
            CaRole::Issuing => "issuing CA",
        })
    }
}

/// A CA whose certificate and key live in slot 9c of a YubiKey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCa {
    /// Subject of the CA certificate.
    pub subject: String,
    /// Root or issuing CA.
    pub role: CaRole,
    /// When the CA certificate expires.
    pub not_after: OffsetDateTime,
    /// The CA certificate itself.
    pub certificate_der: Vec<u8>,
    /// Facts about the private key, as reported by the YubiKey. Firmware
    /// older than 5.3 cannot report them.
    pub key: Option<CaKeyInfo>,
}

impl StoredCa {
    /// Whether the CA with the certificate `root_certificate_der` signed
    /// this one, which makes this the issuing CA of that root's PKI. A
    /// root CA is signed by nothing but itself, so for a root this is
    /// always `false`.
    pub fn is_signed_by(&self, root_certificate_der: &[u8]) -> bool {
        if self.role != CaRole::Issuing {
            return false;
        }
        let (Ok((_, own)), Ok((_, root))) = (
            X509Certificate::from_der(&self.certificate_der),
            X509Certificate::from_der(root_certificate_der),
        ) else {
            return false;
        };
        own.verify_signature(Some(root.public_key())).is_ok()
    }
}

/// What the YubiKey reports about the key in slot 9c.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaKeyInfo {
    /// Key type, for example `ECC P-384`.
    pub algorithm: &'static str,
    /// `Some(true)` if the key was generated inside the YubiKey and so has
    /// never existed anywhere else; `Some(false)` if it was imported.
    pub generated_on_device: Option<bool>,
    /// Whether every signature needs the PIN.
    pub pin_for_every_signature: bool,
    /// Whether signing needs a touch.
    pub touch_required: bool,
    /// Whether the key in the slot is the one the CA certificate names. If
    /// it is not, the slot was only half overwritten at some point and
    /// nothing signed with it would validate.
    pub matches_certificate: bool,
}

/// A smart card reader that is present but could not be opened as a
/// YubiKey with PIV, for example a FIDO-only Security Key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnusableReader {
    /// Name of the PC/SC reader.
    pub reader: String,
    /// Why it could not be used.
    pub reason: String,
}

/// What is plugged in right now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Devices {
    /// YubiKeys yca can work with.
    pub usable: Vec<Device>,
    /// Readers that are present but not usable.
    pub unusable: Vec<UnusableReader>,
}

impl Devices {
    /// Picks the YubiKey to sign with.
    ///
    /// Without a serial number this is the one connected key holding a CA
    /// of the wanted role, so with both keys plugged in everyday issuing
    /// still goes to the issuing CA. A serial number names the key
    /// explicitly; it must then hold a CA of that role.
    pub fn select_ca(&self, role: CaRole, serial: Option<u32>) -> Result<&Device, Error> {
        let has_role = |device: &&Device| device.ca.as_ref().is_some_and(|ca| ca.role == role);

        if let Some(serial) = serial {
            let device = self
                .usable
                .iter()
                .find(|device| device.serial == serial)
                .ok_or_else(|| Error::Device(format!("YubiKey {serial} is not connected")))?;
            return Some(device).filter(has_role).ok_or_else(|| {
                Error::Device(format!("YubiKey {serial} does not hold the {role}"))
            });
        }

        let mut matching = self.usable.iter().filter(has_role);
        match (matching.next(), matching.next()) {
            (Some(device), None) => Ok(device),
            (None, _) => Err(Error::Device(format!(
                "no connected YubiKey holds the {role}"
            ))),
            (Some(_), Some(_)) => Err(Error::Device(format!(
                "more than one connected YubiKey holds a {role}; pick one by serial number"
            ))),
        }
    }
}

/// Lists connected YubiKeys without changing anything on them.
pub fn list_devices() -> Result<Devices, Error> {
    let mut context = match Context::open() {
        Ok(context) => context,
        // PC/SC reports "no readers" as an error rather than an empty list.
        Err(e) if is_no_readers(&e) => return Ok(Devices::default()),
        Err(e) => return Err(device_error(e)),
    };
    let readers = match context.iter() {
        Ok(readers) => readers,
        Err(e) if is_no_readers(&e) => return Ok(Devices::default()),
        Err(e) => return Err(device_error(e)),
    };

    let mut devices = Devices::default();
    for reader in readers {
        let name = reader.name().into_owned();
        let mut yubikey = match reader.open() {
            Ok(yubikey) => yubikey,
            Err(e) => {
                devices.unusable.push(UnusableReader {
                    reader: name,
                    reason: e.to_string(),
                });
                continue;
            }
        };
        let described = describe(&mut yubikey, name);
        release(yubikey);
        devices.usable.push(described?);
    }
    Ok(devices)
}

/// Lets go of a YubiKey that was only looked at.
///
/// A connection that is simply dropped resets the card, and that cuts off
/// every other connection to the same YubiKey: a root CA that was opened
/// with its PIN and is about to sign would find its card "reset" and
/// refuse. Looking must not do that, so the card is left as it is.
pub(crate) fn release(yubikey: YubiKey) {
    let _ = yubikey.disconnect(pcsc::Disposition::LeaveCard);
}

/// What one connected YubiKey holds. Reads only.
fn describe(yubikey: &mut YubiKey, reader: String) -> Result<Device, Error> {
    let version = yubikey.version();
    let keys = Key::list(yubikey).map_err(device_error)?;
    let occupied_slots = keys
        .iter()
        .map(|key| OccupiedSlot {
            slot: slot_name(key.slot()),
            is_signature_slot: key.slot() == CA_SLOT,
            subject: key.certificate().subject(),
            issuer: key.certificate().issuer(),
        })
        .collect();

    let ca = match keys.iter().find(|key| key.slot() == CA_SLOT) {
        Some(key) => {
            let der = key
                .certificate()
                .cert
                .to_der()
                .map_err(|e| Error::Parse(format!("certificate in slot 9c: {e}")))?;
            stored_ca(der, yubikey)?
        }
        None => None,
    };
    let pin_attempts_left = yubikey.get_pin_retries().map_err(device_error)?;
    let factory = FactoryCredentials::read(yubikey);

    Ok(Device {
        serial: yubikey.serial().into(),
        firmware: (version.major, version.minor, version.patch),
        reader,
        pin_attempts_left,
        factory,
        occupied_slots,
        ca,
    })
}

/// Describes the certificate in slot 9c, or `None` if it is not a CA
/// certificate.
fn stored_ca(certificate_der: Vec<u8>, yubikey: &mut YubiKey) -> Result<Option<StoredCa>, Error> {
    let (_, cert) = X509Certificate::from_der(&certificate_der)
        .map_err(|e| Error::Parse(format!("certificate in slot 9c: {e}")))?;
    let is_ca = cert
        .basic_constraints()
        .map_err(|e| Error::Parse(e.to_string()))?
        .is_some_and(|ext| ext.value.ca);
    if !is_ca {
        return Ok(None);
    }

    let role = if cert.subject().as_raw() == cert.issuer().as_raw() {
        CaRole::Root
    } else {
        CaRole::Issuing
    };
    let subject = cert.subject().to_string();
    let not_after = cert.validity().not_after.to_datetime();
    let key = match read_slot_key(yubikey) {
        Ok(key) => {
            let public_key = cert.public_key();
            Some(key.info(public_key.raw, public_key.subject_public_key.data.as_ref()))
        }
        Err(SlotKeyError::NotReported) => None,
        Err(SlotKeyError::Other(e)) => return Err(e),
    };

    Ok(Some(StoredCa {
        subject,
        role,
        not_after,
        certificate_der,
        key,
    }))
}

/// The key in slot 9c as the YubiKey describes it.
pub(crate) struct SlotKey {
    pub(crate) algorithm: AlgorithmId,
    /// The public key as it appears inside a SubjectPublicKeyInfo.
    pub(crate) public_key: Vec<u8>,
    pub(crate) touch_required: bool,
    pin_for_every_signature: bool,
    generated_on_device: Option<bool>,
}

impl SlotKey {
    /// A key yca has just generated in slot 9c, which always asks for the
    /// PIN and a touch.
    pub(crate) fn generated(algorithm: AlgorithmId, public_key: Vec<u8>) -> Self {
        Self {
            algorithm,
            public_key,
            touch_required: true,
            pin_for_every_signature: true,
            generated_on_device: Some(true),
        }
    }

    /// The signature algorithm yca uses with this key, or `None` for a key
    /// type it cannot sign with yet.
    pub(crate) fn signature_algorithm(&self) -> Option<&'static SignatureAlgorithm> {
        match self.algorithm {
            AlgorithmId::EccP256 => Some(&PKCS_ECDSA_P256_SHA256),
            AlgorithmId::EccP384 => Some(&PKCS_ECDSA_P384_SHA384),
            // A CA key of another kind can be looked at but not used.
            _ => None,
        }
    }

    /// `certificate_spki` is the certificate's whole SubjectPublicKeyInfo,
    /// `certificate_key` just the key inside it.
    fn info(&self, certificate_spki: &[u8], certificate_key: &[u8]) -> CaKeyInfo {
        let matches_certificate = match self.signature_algorithm() {
            // The same comparison `Authority::load` makes.
            Some(algorithm) => {
                let slot = SlotPublicKey {
                    key: &self.public_key,
                    algorithm,
                };
                slot.subject_public_key_info() == certificate_spki
            }
            None => self.public_key == certificate_key,
        };
        CaKeyInfo {
            algorithm: algorithm_name(self.algorithm),
            generated_on_device: self.generated_on_device,
            pin_for_every_signature: self.pin_for_every_signature,
            touch_required: self.touch_required,
            matches_certificate,
        }
    }
}

struct SlotPublicKey<'a> {
    key: &'a [u8],
    algorithm: &'static SignatureAlgorithm,
}

impl PublicKeyData for SlotPublicKey<'_> {
    fn der_bytes(&self) -> &[u8] {
        self.key
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.algorithm
    }
}

pub(crate) enum SlotKeyError {
    /// The firmware is too old to describe its keys.
    NotReported,
    Other(Error),
}

/// Asks the YubiKey about the key in slot 9c. Needs no PIN.
pub(crate) fn read_slot_key(yubikey: &mut YubiKey) -> Result<SlotKey, SlotKeyError> {
    let metadata = match piv::metadata(yubikey, CA_SLOT) {
        Ok(metadata) => metadata,
        Err(yubikey::Error::NotSupported) => return Err(SlotKeyError::NotReported),
        Err(e) => return Err(SlotKeyError::Other(device_error(e))),
    };
    let SlotAlgorithmId::Asymmetric(algorithm) = metadata.algorithm else {
        return Err(SlotKeyError::Other(Error::Device(
            "slot 9c does not hold a signing key".to_owned(),
        )));
    };
    let public_key = metadata
        .public
        .ok_or(SlotKeyError::NotReported)?
        .subject_public_key
        .raw_bytes()
        .to_vec();
    let (pin_policy, touch_policy) = metadata.policy.ok_or(SlotKeyError::NotReported)?;

    Ok(SlotKey {
        algorithm,
        public_key,
        touch_required: touch_policy != TouchPolicy::Never,
        pin_for_every_signature: pin_policy == PinPolicy::Always,
        generated_on_device: metadata.origin.map(|origin| origin == Origin::Generated),
    })
}

pub(crate) fn algorithm_name(algorithm: AlgorithmId) -> &'static str {
    match algorithm {
        AlgorithmId::Rsa1024 => "RSA 1024",
        AlgorithmId::Rsa2048 => "RSA 2048",
        AlgorithmId::Rsa3072 => "RSA 3072",
        AlgorithmId::Rsa4096 => "RSA 4096",
        AlgorithmId::EccP256 => "ECC P-256",
        AlgorithmId::EccP384 => "ECC P-384",
        AlgorithmId::Ed25519 => "Ed25519",
        _ => "of a kind yca does not know",
    }
}

pub(crate) fn device_error(error: yubikey::Error) -> Error {
    match error {
        yubikey::Error::WrongPin { tries } => Error::WrongPin {
            attempts_left: tries,
        },
        yubikey::Error::PinLocked => Error::PinLocked,
        other => Error::Device(other.to_string()),
    }
}

fn is_no_readers(error: &yubikey::Error) -> bool {
    matches!(
        error,
        yubikey::Error::PcscError {
            inner: Some(pcsc::Error::NoReadersAvailable)
        }
    )
}

fn slot_name(slot: SlotId) -> String {
    format!("{:02x}", u8::from(slot))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads only, but needs a YubiKey, so it is run by hand:
    /// `cargo test -p yca-core -- --ignored looking_at`.
    ///
    /// Before looking left the card alone, the second look reset it, and a
    /// root CA that had been opened to sign an issuing CA on another
    /// YubiKey found its connection cut off.
    #[test]
    #[ignore = "needs a connected YubiKey"]
    fn looking_at_the_keys_leaves_other_connections_alone() {
        let found = list_devices().unwrap();
        assert!(!found.usable.is_empty(), "connect a YubiKey first");
        for device in &found.usable {
            let mut held = crate::signer::open_device(device.serial).unwrap();
            list_devices().unwrap();
            // A card that was reset refuses with "the smart card has been
            // reset, so any shared state information is invalid".
            held.get_pin_retries()
                .unwrap_or_else(|e| panic!("YubiKey {}: {e}", device.serial));
        }
    }

    fn device(serial: u32, role: Option<CaRole>) -> Device {
        Device {
            serial,
            firmware: (5, 7, 4),
            reader: "test".to_owned(),
            pin_attempts_left: 3,
            factory: FactoryCredentials::default(),
            occupied_slots: Vec::new(),
            ca: role.map(|role| StoredCa {
                subject: "CN=Test".to_owned(),
                role,
                not_after: OffsetDateTime::UNIX_EPOCH,
                certificate_der: Vec::new(),
                key: None,
            }),
        }
    }

    fn devices(list: Vec<Device>) -> Devices {
        Devices {
            usable: list,
            unusable: Vec::new(),
        }
    }

    #[test]
    fn everyday_issuing_picks_the_issuing_ca_even_with_the_root_plugged_in() {
        let both = devices(vec![
            device(1, Some(CaRole::Root)),
            device(2, Some(CaRole::Issuing)),
        ]);
        assert_eq!(both.select_ca(CaRole::Issuing, None).unwrap().serial, 2);
        assert_eq!(both.select_ca(CaRole::Root, None).unwrap().serial, 1);
    }

    #[test]
    fn a_missing_ca_is_an_error() {
        let only_root = devices(vec![device(1, Some(CaRole::Root)), device(3, None)]);
        assert!(only_root.select_ca(CaRole::Issuing, None).is_err());
        assert!(devices(Vec::new()).select_ca(CaRole::Root, None).is_err());
    }

    #[test]
    fn two_cas_of_the_same_role_need_a_serial_number() {
        let two = devices(vec![
            device(1, Some(CaRole::Issuing)),
            device(2, Some(CaRole::Issuing)),
        ]);
        assert!(two.select_ca(CaRole::Issuing, None).is_err());
        assert_eq!(two.select_ca(CaRole::Issuing, Some(2)).unwrap().serial, 2);
    }

    #[test]
    fn a_serial_number_never_overrides_the_role() {
        let both = devices(vec![
            device(1, Some(CaRole::Root)),
            device(2, Some(CaRole::Issuing)),
        ]);
        // Asking for everyday issuing must not end up signing with the root.
        assert!(both.select_ca(CaRole::Issuing, Some(1)).is_err());
        assert!(both.select_ca(CaRole::Issuing, Some(9)).is_err());
    }

    #[test]
    fn an_issuing_ca_belongs_only_to_the_root_that_signed_it() {
        use crate::Authority;
        use rcgen::KeyPair;

        let key = || KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let stored = |role, certificate_der: &[u8]| StoredCa {
            subject: "CN=Test".to_owned(),
            role,
            not_after: OffsetDateTime::UNIX_EPOCH,
            certificate_der: certificate_der.to_vec(),
            key: None,
        };
        let at = OffsetDateTime::now_utc();
        let root = Authority::create_root("Root", key(), at).unwrap();
        let other_root = Authority::create_root("Other Root", key(), at).unwrap();
        let issuing = root.create_issuing("Issuing", key(), at).unwrap();
        let issuing = stored(CaRole::Issuing, issuing.certificate_der());

        assert!(issuing.is_signed_by(root.certificate_der()));
        assert!(!issuing.is_signed_by(other_root.certificate_der()));
        // A root is nobody's issuing CA, not even its own.
        let root_on_key = stored(CaRole::Root, root.certificate_der());
        assert!(!root_on_key.is_signed_by(root.certificate_der()));
        // Something that is no certificate at all signed nothing.
        assert!(!issuing.is_signed_by(b"not a certificate"));
    }
}
