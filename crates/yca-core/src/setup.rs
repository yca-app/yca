//! Opening a CA that lives on a YubiKey, and putting a new one there.
//!
//! The functions that write to a YubiKey are all here:
//! [`Authority::create_root_on_yubikey`],
//! [`Authority::create_issuing_on_yubikey`] and [`protect_yubikey`].

use der::Encode;
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, X509Certificate};
use yubikey::certificate::{CertInfo, Certificate};
use yubikey::piv::{self, AlgorithmId, SlotId};
use yubikey::{MgmKey, PinPolicy, TouchPolicy, YubiKey};

use crate::device::{
    CA_SLOT, FIRMWARE_TOO_OLD, FactoryCredentials, KeyInSlot, SlotKey, device_error, key_in_slot,
    release,
};
use crate::signer::{checked_pin, not_the_last_attempt, open_device};
use crate::{Authority, Error, SigningKey, Turn, YubiKeySigner};

/// Key type for a new CA key generated inside a YubiKey.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CaKeyType {
    /// NIST P-256.
    EccP256,
    /// NIST P-384.
    #[default]
    EccP384,
}

/// A CA to put on a YubiKey.
#[derive(Debug, Clone)]
pub struct NewCa<'a> {
    /// Name of the CA; becomes its common name.
    pub name: &'a str,
    /// Type of the key to generate.
    pub key_type: CaKeyType,
    /// Replace whatever slot 9c holds now. Without this, a slot that is in
    /// use is left alone and setup fails.
    pub replace_existing: bool,
}

/// The YubiKey's own statement that a key was generated inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    /// Certificate over the CA key, signed by this YubiKey's attestation
    /// key. Yubico's tools and documentation call this the attestation.
    pub certificate_der: Vec<u8>,
    /// Certificate of this YubiKey's attestation key, signed by Yubico.
    pub intermediate_der: Vec<u8>,
}

impl Attestation {
    /// Whether this is a YubiKey's statement about the key of the given
    /// CA certificate: the attested key is that certificate's key, and
    /// the statement is signed by the attestation key that comes with it.
    ///
    /// Whose attestation key that is, is not looked into: the chain up to
    /// Yubico's own root is not followed.
    pub fn vouches_for(&self, ca_certificate_der: &[u8]) -> bool {
        let parse = |der| X509Certificate::from_der(der).map(|(_, certificate)| certificate);
        let (Ok(attestation), Ok(intermediate), Ok(ca)) = (
            parse(&self.certificate_der),
            parse(&self.intermediate_der),
            parse(ca_certificate_der),
        ) else {
            return false;
        };
        attestation.public_key().subject_public_key.data == ca.public_key().subject_public_key.data
            && attestation
                .verify_signature(Some(intermediate.public_key()))
                .is_ok()
    }
}

impl Authority<YubiKeySigner> {
    /// Opens the CA stored in slot 9c of the YubiKey with the given serial
    /// number. Checks the PIN; writes nothing.
    pub fn open_on_yubikey(serial: u32, pin: &str) -> Result<Self, Error> {
        let signer = YubiKeySigner::open(serial, pin)?;
        let certificate = signer.with_device(read_ca_certificate)?;
        Self::load(&certificate, signer)
    }

    /// Creates a new root CA on a YubiKey: generates the key inside it,
    /// signs the root certificate with that key and stores the certificate
    /// next to the key.
    ///
    /// The key is created so that every signature needs the PIN and a
    /// touch; that cannot be changed afterwards. Signing the root
    /// certificate is the first such signature, so this waits for a touch.
    /// `before_signing` is called once the key is made and that signature
    /// is about to be asked for: the moment to say that the YubiKey wants
    /// its touch now.
    pub fn create_root_on_yubikey(
        serial: u32,
        pin: &str,
        root: &NewCa<'_>,
        now: OffsetDateTime,
        before_signing: impl FnOnce(),
    ) -> Result<(Self, Option<Attestation>), Error> {
        let signer = new_ca_key(serial, pin, root)?;
        before_signing();
        let finish = || -> Result<(Vec<u8>, Option<Attestation>), Error> {
            // Signing through a reference keeps the signer here, where it
            // can say why a signature failed.
            let certificate = match Authority::create_root(root.name, &signer, now) {
                Ok(root) => root.certificate_der().to_vec(),
                Err(e) => return Err(signer.take_last_error().unwrap_or(e)),
            };
            let attestation = store_certificate(&signer, &certificate)?;
            Ok((certificate, attestation))
        };
        let (certificate, attestation) =
            finish().map_err(|cause| Error::SetupInterrupted(Box::new(cause)))?;

        Ok((Self::load(&certificate, signer)?, attestation))
    }

    /// Creates an issuing CA on a second YubiKey: generates the key inside
    /// it, has `root` sign the certificate and stores the certificate next
    /// to the key.
    ///
    /// `serial` and `pin` belong to the YubiKey that will hold the issuing
    /// CA. The signature comes from the root, so it is the root's YubiKey
    /// that waits for a touch. The new key signs nothing here.
    /// `before_signing` is called once the new key is made and the root is
    /// about to sign: not before, because while the key is being made it
    /// is the other YubiKey that flickers, and that one wants no touch.
    pub fn create_issuing_on_yubikey<R: SigningKey>(
        root: &Authority<R>,
        serial: u32,
        pin: &str,
        issuing: &NewCa<'_>,
        now: OffsetDateTime,
        before_signing: impl FnOnce(),
    ) -> Result<(Self, Option<Attestation>), Error> {
        // Before anything is generated: a root that cannot sign any more.
        root.ensure_not_expired(now)?;
        let signer = new_ca_key(serial, pin, issuing)?;
        before_signing();
        let finish = || -> Result<(Vec<u8>, Option<Attestation>), Error> {
            let certificate = root
                .create_issuing(issuing.name, &signer, now)?
                .certificate_der()
                .to_vec();
            let attestation = store_certificate(&signer, &certificate)?;
            Ok((certificate, attestation))
        };
        let (certificate, attestation) =
            finish().map_err(|cause| Error::SetupInterrupted(Box::new(cause)))?;

        Ok((Self::load(&certificate, signer)?, attestation))
    }
}

/// Generates a new CA key in slot 9c of a YubiKey. On success the slot
/// holds the new key and whatever it held before is gone.
fn new_ca_key(serial: u32, pin: &str, ca: &NewCa<'_>) -> Result<YubiKeySigner, Error> {
    let pin = checked_pin(pin)?;
    if ca.name.trim().is_empty() {
        return Err(Error::InvalidRequest("a CA name is required".to_owned()));
    }
    // Kept until the CA is finished or given up: a look at this YubiKey
    // by another program in between would leave a key without its
    // certificate.
    let turn = Turn::wait()?;
    let mut yubikey = open_device(serial)?;

    // Everything that can fail goes before the point of no return. First
    // of all a YubiKey that does not say what its slot holds: no answer is
    // not an empty slot, and a key that is written to without knowing
    // could be somebody's CA. Nor could a CA on it be used afterwards.
    let in_slot = key_in_slot(&mut yubikey);
    if in_slot == KeyInSlot::Untold {
        return Err(Error::Device(FIRMWARE_TOO_OLD.to_owned()));
    }
    let in_use = in_slot == KeyInSlot::Yes || Certificate::read(&mut yubikey, CA_SLOT).is_ok();
    if !ca.replace_existing && in_use {
        return Err(Error::SlotInUse);
    }
    // A CA key behind the PIN every YubiKey ships with protects nothing.
    // Nor does one behind the PUK every YubiKey ships with, which sets a
    // new PIN, or the management key, which writes over what the key
    // holds.
    let factory = FactoryCredentials::read(&mut yubikey);
    if factory.pin == Some(true) {
        return Err(Error::FactoryPin);
    }
    if factory.puk == Some(true) || factory.management_key == Some(true) {
        return Err(Error::FactoryPukOrKey);
    }
    not_the_last_attempt(&mut yubikey)?;
    yubikey.verify_pin(&pin).map_err(device_error)?;
    authenticate(&mut yubikey)?;

    // Point of no return: this replaces any key already in the slot.
    let algorithm = match ca.key_type {
        CaKeyType::EccP256 => AlgorithmId::EccP256,
        CaKeyType::EccP384 => AlgorithmId::EccP384,
    };
    let public_key = piv::generate(
        &mut yubikey,
        CA_SLOT,
        algorithm,
        PinPolicy::Always,
        TouchPolicy::Always,
    )
    .map_err(device_error)?;
    let key = SlotKey::generated(
        algorithm,
        public_key.subject_public_key.raw_bytes().to_vec(),
    );
    YubiKeySigner::new(turn, yubikey, pin, key)
}

/// Stores a CA certificate next to its key and collects the YubiKey's
/// attestation of that key.
fn store_certificate(
    signer: &YubiKeySigner,
    certificate: &[u8],
) -> Result<Option<Attestation>, Error> {
    signer.with_unlocked_device(|yubikey| {
        authenticate(yubikey)?;
        Certificate::from_bytes(certificate.to_vec())
            .and_then(|cert| cert.write(yubikey, CA_SLOT, CertInfo::Uncompressed))
            .map_err(device_error)?;
        attest(yubikey, certificate)
    })
}

/// Asks a YubiKey to attest the CA key it holds and checks the answer
/// against the CA certificate in the same slot. Needs no PIN and changes
/// nothing. Returns `None` if the firmware cannot attest.
///
/// A YubiKey only attests keys that were generated inside it, so an
/// imported key makes this fail.
pub fn attest_ca_on_yubikey(serial: u32) -> Result<Option<Attestation>, Error> {
    let _turn = Turn::wait()?;
    let mut yubikey = open_device(serial)?;
    let attestation = read_ca_certificate(&mut yubikey)
        .and_then(|certificate| attest(&mut yubikey, &certificate));
    // Only looked at: a signer that holds this YubiKey stays connected.
    release(yubikey);
    attestation
}

fn read_ca_certificate(yubikey: &mut YubiKey) -> Result<Vec<u8>, Error> {
    Certificate::read(yubikey, CA_SLOT)
        .map_err(device_error)?
        .cert
        .to_der()
        .map_err(|e| Error::Parse(format!("certificate in slot 9c: {e}")))
}

/// Unlocks key generation and certificate storage. The PIN must have
/// been verified just before.
///
/// Uses the management key that [`protect_yubikey`] stored on the key
/// behind the PIN, or the factory one if there is none.
fn authenticate(yubikey: &mut YubiKey) -> Result<(), Error> {
    // The factory key differs with the firmware: 3DES before 5.7, AES-192
    // from then on. The library knows which one a key was made with.
    let key = match MgmKey::get_protected(yubikey) {
        Ok(key) => key,
        Err(_) => MgmKey::get_default(yubikey).map_err(device_error)?,
    };
    yubikey.authenticate(&key).map_err(|_| {
        Error::Device(
            "this YubiKey's management key is neither the factory one nor stored on the \
             key behind the PIN; setting up a CA on such a key is not supported"
                .to_owned(),
        )
    })
}

/// The PIN and the PUK every YubiKey leaves the factory with.
const FACTORY_PIN: &str = "123456";
const FACTORY_PUK: &str = "12345678";

/// What [`protect_yubikey`] changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protected {
    /// The PUK was replaced. `false` if it had been changed before.
    pub puk_changed: bool,
    /// A random management key was set and stored behind the PIN. `false`
    /// if the management key had been changed before.
    pub management_key_protected: bool,
}

/// Replaces the factory credentials of a YubiKey: sets a new PIN, a new
/// PUK and a random management key that is kept on the key itself, where
/// only the PIN can reach it.
///
/// Only for a key whose PIN is still the factory one. A PUK or management
/// key that was already changed is left alone. Nothing else on the key is
/// touched; a CA that is already there keeps working with the new PIN.
pub fn protect_yubikey(serial: u32, new_pin: &str, new_puk: &str) -> Result<Protected, Error> {
    check_new_credential("PIN", new_pin, FACTORY_PIN)?;
    check_new_credential("PUK", new_puk, FACTORY_PUK)?;

    let _turn = Turn::wait()?;
    let mut yubikey = open_device(serial)?;
    let factory = FactoryCredentials::read(&mut yubikey);
    if factory.pin != Some(true) {
        return Err(Error::InvalidRequest(
            "the PIN of this YubiKey is not the factory one any more; \
             yca only changes the credentials of a key in its factory state"
                .to_owned(),
        ));
    }
    yubikey
        .verify_pin(FACTORY_PIN.as_bytes())
        .map_err(device_error)?;

    // The PIN goes last: if anything before it fails, running this again
    // still finds the factory PIN and can finish the job.
    let management_key_protected = factory.management_key == Some(true);
    if management_key_protected {
        let factory_key = MgmKey::get_default(&yubikey).map_err(device_error)?;
        yubikey.authenticate(&factory_key).map_err(device_error)?;
        // Of the kind this firmware uses: 3DES before 5.7, AES-192 after.
        MgmKey::generate_for(&yubikey, &mut getrandom::SysRng)
            .map_err(device_error)?
            .set_protected(&mut yubikey)
            .map_err(device_error)?;
    }
    let puk_changed = factory.puk == Some(true);
    if puk_changed {
        yubikey
            .change_puk(FACTORY_PUK.as_bytes(), new_puk.as_bytes())
            .map_err(device_error)?;
    }
    yubikey
        .change_pin(FACTORY_PIN.as_bytes(), new_pin.as_bytes())
        .map_err(device_error)?;

    Ok(Protected {
        puk_changed,
        management_key_protected,
    })
}

/// Gives a YubiKey whose PIN is already its owner's what
/// [`protect_yubikey`] gives a new one besides the PIN: a PUK in place of
/// the factory one, and a random management key in place of the factory
/// one, kept on the key itself where only the PIN can reach it.
///
/// A key gets into this state when its PIN alone was changed, by another
/// tool, or by unblocking it with the factory PUK. Whoever holds such a
/// key sets a new PIN with the PUK everybody knows, and signs.
///
/// `new_puk` is needed where the PUK is the factory one. What was changed
/// before is left alone, and so is everything else on the key: a CA that
/// is there keeps working. A wrong `pin` costs one of the key's attempts,
/// and none is tried with the last.
pub fn finish_protecting(
    serial: u32,
    pin: &str,
    new_puk: Option<&str>,
) -> Result<Protected, Error> {
    let pin = checked_pin(pin)?;
    let _turn = Turn::wait()?;
    let mut yubikey = open_device(serial)?;
    let factory = FactoryCredentials::read(&mut yubikey);
    if factory.pin == Some(true) {
        return Err(Error::FactoryPin);
    }
    let puk_changed = factory.puk == Some(true);
    let management_key_protected = factory.management_key == Some(true);
    if !puk_changed && !management_key_protected {
        return Err(Error::InvalidRequest(
            "nothing on this YubiKey is at its factory value any more".to_owned(),
        ));
    }
    // Settled before anything is asked of the key.
    let new_puk = match (puk_changed, new_puk) {
        (true, Some(puk)) => {
            check_new_credential("PUK", puk, FACTORY_PUK)?;
            Some(puk)
        }
        (true, None) => {
            return Err(Error::InvalidRequest(
                "the PUK of this YubiKey is the factory one; it needs a new PUK".to_owned(),
            ));
        }
        (false, _) => None,
    };
    not_the_last_attempt(&mut yubikey)?;
    yubikey.verify_pin(&pin).map_err(device_error)?;

    if management_key_protected {
        let factory_key = MgmKey::get_default(&yubikey).map_err(device_error)?;
        yubikey.authenticate(&factory_key).map_err(device_error)?;
        // Of the kind this firmware uses: 3DES before 5.7, AES-192 after.
        MgmKey::generate_for(&yubikey, &mut getrandom::SysRng)
            .map_err(device_error)?
            .set_protected(&mut yubikey)
            .map_err(device_error)?;
    }
    if let Some(puk) = new_puk {
        yubikey
            .change_puk(FACTORY_PUK.as_bytes(), puk.as_bytes())
            .map_err(device_error)?;
    }
    Ok(Protected {
        puk_changed,
        management_key_protected,
    })
}

/// Changes the PIN of a YubiKey. Nothing else on the key is touched: a CA
/// that is there keeps working, with the new PIN.
///
/// A wrong current PIN costs one of the key's attempts, and none is tried
/// with the last. A key that still has its factory PIN is not for this:
/// [`protect_yubikey`] gives it a PUK and a management key of its own
/// along with the PIN.
pub fn change_pin(serial: u32, current_pin: &str, new_pin: &str) -> Result<(), Error> {
    let current = checked_pin(current_pin)?;
    check_new_credential("PIN", new_pin, FACTORY_PIN)?;
    if new_pin == current_pin {
        return Err(Error::InvalidRequest(
            "the new PIN is the one the YubiKey has".to_owned(),
        ));
    }
    let _turn = Turn::wait()?;
    let mut yubikey = open_device(serial)?;
    if FactoryCredentials::read(&mut yubikey).pin == Some(true) {
        return Err(Error::FactoryPin);
    }
    not_the_last_attempt(&mut yubikey)?;
    yubikey
        .change_pin(&current, new_pin.as_bytes())
        .map_err(device_error)
}

/// Sets a new PIN with the PUK: for a PIN that was forgotten, or locked
/// by three wrong attempts. Nothing else on the key is touched.
///
/// A wrong PUK costs one of the PUK's attempts. Once those are used up
/// nothing unblocks the key any more; only [`reset_piv`] is left.
pub fn unblock_pin(serial: u32, puk: &str, new_pin: &str) -> Result<(), Error> {
    if !(6..=8).contains(&puk.len()) {
        return Err(Error::InvalidRequest(
            "the PUK must be 6 to 8 characters long".to_owned(),
        ));
    }
    check_new_credential("PIN", new_pin, FACTORY_PIN)?;
    let _turn = Turn::wait()?;
    let mut yubikey = open_device(serial)?;
    yubikey
        .unblock_pin(puk.as_bytes(), new_pin.as_bytes())
        .map_err(|e| match e {
            yubikey::Error::WrongPin { tries } => Error::WrongPuk {
                attempts_left: tries,
            },
            yubikey::Error::PinLocked => Error::PukLocked,
            other => device_error(other),
        })
}

/// Resets the PIV application of a YubiKey to the state it left the
/// factory in. DESTROYS every PIV key and certificate on it: the CA in
/// slot 9c, and whatever other PIV slots hold. The PIN, the PUK and the
/// management key are the factory ones again afterwards.
///
/// For a YubiKey whose PIN and PUK are both lost, and for starting over.
/// It needs neither, which is the point; the caller has to be sure of the
/// serial number. The other applications of the YubiKey (FIDO2, OATH,
/// OpenPGP) are separate from PIV and are not touched.
pub fn reset_piv(serial: u32) -> Result<(), Error> {
    let _turn = Turn::wait()?;
    let mut yubikey = open_device(serial)?;
    // A YubiKey resets PIV only once both the PIN and the PUK are locked,
    // so that it cannot happen in passing. Lock them.
    lock(|wrong| yubikey.verify_pin(wrong))?;
    lock(|wrong| yubikey.change_puk(wrong, wrong))?;
    yubikey.reset_device().map_err(device_error)
}

/// Values no PIN or PUK has: nobody can type them.
const NOT_A_PIN: [[u8; 8]; 2] = [[0x01; 8], [0x02; 8]];

/// Uses up the attempts of a PIN or a PUK with values that are not it.
fn lock(mut attempt: impl FnMut(&[u8]) -> Result<(), yubikey::Error>) -> Result<(), Error> {
    // A YubiKey can be set to allow up to 255 attempts.
    for round in 0..600 {
        match attempt(&NOT_A_PIN[round % 2]) {
            Err(yubikey::Error::PinLocked | yubikey::Error::WrongPin { tries: 0 }) => {
                return Ok(());
            }
            // One attempt less. Had a value been let in after all, the
            // other one would not be.
            Err(yubikey::Error::WrongPin { .. }) | Ok(()) => {}
            Err(other) => return Err(device_error(other)),
        }
    }
    Err(Error::Device(
        "the YubiKey did not lock its PIN; nothing was reset".to_owned(),
    ))
}

/// A PIN or PUK is six to eight characters and must not be the factory
/// value it replaces.
fn check_new_credential(what: &str, value: &str, factory: &str) -> Result<(), Error> {
    if !(6..=8).contains(&value.len()) || !value.is_ascii() {
        return Err(Error::InvalidRequest(format!(
            "the {what} must be 6 to 8 characters, without accents"
        )));
    }
    if value == factory {
        return Err(Error::InvalidRequest(format!(
            "the new {what} must differ from the factory one"
        )));
    }
    Ok(())
}

/// Asks the YubiKey to attest the key in slot 9c and checks that the answer
/// is about the key of `ca_certificate` and comes from this YubiKey.
/// Returns `None` if the firmware cannot attest.
fn attest(yubikey: &mut YubiKey, ca_certificate: &[u8]) -> Result<Option<Attestation>, Error> {
    let certificate_der = match piv::attest(yubikey, CA_SLOT) {
        Ok(certificate) => certificate.to_vec(),
        Err(yubikey::Error::NotSupported) => return Ok(None),
        Err(e) => return Err(device_error(e)),
    };
    let intermediate_der = Certificate::read(yubikey, SlotId::Attestation)
        .map_err(device_error)?
        .cert
        .to_der()
        .map_err(|e| Error::Parse(format!("attestation certificate: {e}")))?;

    let attestation = Attestation {
        certificate_der,
        intermediate_der,
    };
    if !attestation.vouches_for(ca_certificate) {
        return Err(Error::Device(
            "the YubiKey's attestation does not match the key it just generated".to_owned(),
        ));
    }
    Ok(Some(attestation))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_credentials_are_checked_before_the_key_is_touched() {
        assert!(check_new_credential("PIN", "482915", FACTORY_PIN).is_ok());
        assert!(check_new_credential("PUK", "73920461", FACTORY_PUK).is_ok());
        for bad in ["", "12345", "123456789", "ěščřžý"] {
            assert!(
                matches!(
                    check_new_credential("PIN", bad, FACTORY_PIN),
                    Err(Error::InvalidRequest(_))
                ),
                "{bad:?}"
            );
        }
        // Setting the factory value again would change nothing.
        assert!(check_new_credential("PIN", FACTORY_PIN, FACTORY_PIN).is_err());
        assert!(check_new_credential("PUK", FACTORY_PUK, FACTORY_PUK).is_err());
        // An unreachable YubiKey is only reported after the values pass.
        assert!(matches!(
            protect_yubikey(1, FACTORY_PIN, "73920461"),
            Err(Error::InvalidRequest(_))
        ));
    }

    #[test]
    fn a_pin_change_that_cannot_work_never_reaches_the_key() {
        // Each of these would cost an attempt, or set a PIN nobody should
        // have, if it got as far as the YubiKey.
        for (current, new) in [
            ("12345", "482915"),     // too short to be the PIN
            ("482915", "12345"),     // too short to become one
            ("482915", FACTORY_PIN), // the PIN everybody knows
            ("482915", "482915"),    // no change at all
            ("482915", "ěščřžýáí"),  // not typed the same everywhere
        ] {
            assert!(
                matches!(change_pin(1, current, new), Err(Error::InvalidRequest(_))),
                "{current:?} -> {new:?}"
            );
        }
        for (puk, new) in [
            ("12345", "482915"),
            ("123456789", "482915"),
            ("73920461", FACTORY_PIN),
            ("73920461", "1234"),
        ] {
            assert!(
                matches!(unblock_pin(1, puk, new), Err(Error::InvalidRequest(_))),
                "{puk:?} -> {new:?}"
            );
        }
    }

    #[test]
    fn locking_stops_once_the_key_says_it_is_locked() {
        // Three attempts, counted down to none.
        let mut left = 3u8;
        let mut tried = Vec::new();
        lock(|wrong| {
            tried.push(wrong.to_vec());
            left -= 1;
            Err(yubikey::Error::WrongPin { tries: left })
        })
        .unwrap();
        assert_eq!(tried.len(), 3);
        // Two values take turns, so that neither can be the real one twice.
        assert_ne!(tried[0], tried[1]);

        // Already locked: one look is enough.
        let mut looks = 0;
        lock(|_| {
            looks += 1;
            Err(yubikey::Error::PinLocked)
        })
        .unwrap();
        assert_eq!(looks, 1);

        // A key that fails otherwise is not hammered.
        let mut looks = 0;
        assert!(
            lock(|_| {
                looks += 1;
                Err(yubikey::Error::GenericError)
            })
            .is_err()
        );
        assert_eq!(looks, 1);
    }
}
