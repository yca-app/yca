//! Signing with a CA key that lives in a YubiKey.

use std::sync::Mutex;

use rcgen::{PublicKeyData, SignatureAlgorithm, SigningKey};
use sha2::{Digest, Sha256, Sha384};
use yubikey::piv::{self, AlgorithmId};
use yubikey::{Serial, YubiKey};
use zeroize::Zeroizing;

use crate::device::{
    CA_SLOT, FIRMWARE_TOO_OLD, SlotKey, SlotKeyError, algorithm_name, device_error, read_slot_key,
};
use crate::{Error, Turn};

/// A PIV PIN is six to eight characters long.
const PIN_LENGTH: std::ops::RangeInclusive<usize> = 6..=8;

/// The CA key in slot 9c of one YubiKey.
///
/// The private key never leaves the YubiKey. Every signature sends the PIN
/// to the key again, because the slot asks for it each time, and blocks
/// until the key is touched if the key was set up to require a touch.
///
/// For as long as it is open, no other program of yca's talks to the
/// YubiKeys: one that looked at this key between the PIN and a signature
/// would make the key forget the PIN.
pub struct YubiKeySigner {
    yubikey: Mutex<YubiKey>,
    pin: Zeroizing<Vec<u8>>,
    piv_algorithm: AlgorithmId,
    algorithm: &'static SignatureAlgorithm,
    public_key: Vec<u8>,
    touch_required: bool,
    last_error: Mutex<Option<Error>>,
    /// Given up last, once the connection above is closed.
    _turn: Turn,
}

impl YubiKeySigner {
    /// Opens the CA key on the YubiKey with the given serial number and
    /// checks the PIN.
    ///
    /// A wrong PIN costs one of the key's attempts, so this never retries;
    /// the error says how many attempts are left. A PIN of impossible
    /// length is rejected without being sent to the key, and none is sent
    /// while the key has a single attempt left.
    pub fn open(serial: u32, pin: &str) -> Result<Self, Error> {
        let pin = checked_pin(pin)?;
        let turn = Turn::wait()?;
        let mut yubikey = open_device(serial)?;
        let key = read_slot_key(&mut yubikey).map_err(|e| match e {
            SlotKeyError::NotReported => Error::Device(FIRMWARE_TOO_OLD.to_owned()),
            SlotKeyError::Other(e) => e,
        })?;
        // Fail on an unsupported key before spending a PIN attempt.
        let signer = Self::new(yubikey, pin, key, turn)?;
        signer.with_device(|yubikey| {
            not_the_last_attempt(yubikey)?;
            yubikey.verify_pin(&signer.pin).map_err(device_error)
        })?;
        Ok(signer)
    }

    /// Wraps an open YubiKey whose slot 9c holds `key`, and keeps the turn
    /// it was opened in. Does not check the PIN; the caller has, or the
    /// first signature will.
    pub(crate) fn new(
        yubikey: YubiKey,
        pin: Zeroizing<Vec<u8>>,
        key: SlotKey,
        turn: Turn,
    ) -> Result<Self, Error> {
        let algorithm = key.signature_algorithm().ok_or_else(|| {
            Error::Device(format!(
                "{} CA keys on a YubiKey are not supported yet",
                algorithm_name(key.algorithm)
            ))
        })?;
        Ok(Self {
            yubikey: Mutex::new(yubikey),
            pin,
            piv_algorithm: key.algorithm,
            algorithm,
            public_key: key.public_key,
            touch_required: key.touch_required,
            last_error: Mutex::new(None),
            _turn: turn,
        })
    }

    /// Whether the YubiKey waits for a touch before it signs.
    pub fn touch_required(&self) -> bool {
        self.touch_required
    }

    /// Why the most recent signature failed, if it did. The signing
    /// interface itself can only say that the key refused.
    pub fn take_last_error(&self) -> Option<Error> {
        self.last_error.lock().ok()?.take()
    }

    /// Runs `f` with exclusive access to the YubiKey.
    pub(crate) fn with_device<T>(
        &self,
        f: impl FnOnce(&mut YubiKey) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut yubikey = self
            .yubikey
            .lock()
            .map_err(|_| Error::Device("the YubiKey connection is unusable".to_owned()))?;
        f(&mut yubikey)
    }

    /// Like [`Self::with_device`], with the PIN verified first.
    pub(crate) fn with_unlocked_device<T>(
        &self,
        f: impl FnOnce(&mut YubiKey) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.with_device(|yubikey| {
            yubikey.verify_pin(&self.pin).map_err(device_error)?;
            f(yubikey)
        })
    }

    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, Error> {
        self.with_device(|yubikey| {
            match self.sign_once(yubikey, digest) {
                // Something else let go of this YubiKey since it was
                // opened, which resets the card under every connection to
                // it. Nothing was signed; connect again and sign.
                Err(Refusal::Reset) => {
                    yubikey.reconnect().map_err(device_error)?;
                    self.sign_once(yubikey, digest)
                }
                other => other,
            }
            .map_err(|refusal| match refusal {
                Refusal::Reset => Error::Device(
                    "the YubiKey was reset by another program while it was signing".to_owned(),
                ),
                Refusal::Other(error) => error,
            })
        })
    }

    /// One attempt at a signature: the PIN, then the signature itself.
    fn sign_once(&self, yubikey: &mut YubiKey, digest: &[u8]) -> Result<Vec<u8>, Refusal> {
        // Slot 9c wants the PIN immediately before each signature.
        yubikey.verify_pin(&self.pin).map_err(Refusal::from)?;
        let signature =
            piv::sign_data(yubikey, digest, self.piv_algorithm, CA_SLOT).map_err(|e| match e {
                // The key answers "security status not satisfied" both to
                // a missing PIN and to a missing touch. The PIN was
                // accepted a moment ago, which leaves the touch.
                yubikey::Error::AuthenticationError if self.touch_required => {
                    Refusal::Other(Error::NotTouched)
                }
                other => Refusal::from(other),
            })?;
        Ok(signature.to_vec())
    }
}

/// Why a YubiKey did not sign.
enum Refusal {
    /// The card was reset under this connection. Another connection to
    /// the same YubiKey was closed, by this program or by another one.
    Reset,
    Other(Error),
}

impl From<yubikey::Error> for Refusal {
    fn from(error: yubikey::Error) -> Self {
        match error {
            yubikey::Error::PcscError {
                inner: Some(pcsc::Error::ResetCard),
            } => Refusal::Reset,
            other => Refusal::Other(device_error(other)),
        }
    }
}

/// Rejects a PIN of impossible length without sending it to the key, where
/// it would cost an attempt.
pub(crate) fn checked_pin(pin: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    if !PIN_LENGTH.contains(&pin.len()) {
        return Err(Error::InvalidRequest(
            "the PIN must be 6 to 8 characters long".to_owned(),
        ));
    }
    Ok(Zeroizing::new(pin.as_bytes().to_vec()))
}

/// Refuses to try a PIN while a wrong one would lock the YubiKey: a slip
/// of the finger is not worth that. For a PIN a person typed, right
/// before it is sent and in the same turn at the YubiKeys, so that no
/// other program of yca's uses up an attempt between the count and the
/// try.
pub(crate) fn not_the_last_attempt(yubikey: &mut YubiKey) -> Result<(), Error> {
    match yubikey.get_pin_retries().map_err(device_error)? {
        0 => Err(Error::PinLocked),
        1 => Err(Error::LastAttempt),
        _ => Ok(()),
    }
}

/// Connects to a YubiKey. The caller has the turn at the YubiKeys.
pub(crate) fn open_device(serial: u32) -> Result<YubiKey, Error> {
    YubiKey::open_by_serial(Serial(serial)).map_err(device_error)
}

impl PublicKeyData for YubiKeySigner {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.algorithm
    }
}

impl SigningKey for YubiKeySigner {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        // The YubiKey signs a digest; ECDSA signatures come back in the
        // DER form X.509 uses.
        let digest = match self.piv_algorithm {
            AlgorithmId::EccP384 => Sha384::digest(msg).to_vec(),
            _ => Sha256::digest(msg).to_vec(),
        };
        self.sign_digest(&digest).map_err(|e| {
            if let Ok(mut last_error) = self.last_error.lock() {
                *last_error = Some(e);
            }
            rcgen::Error::RemoteKeyError
        })
    }
}
