/// Everything that can go wrong in the core library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Building or signing a certificate failed.
    #[error("certificate generation failed: {0}")]
    Generate(#[from] rcgen::Error),

    /// A stored certificate could not be read.
    #[error("could not parse certificate: {0}")]
    Parse(String),

    /// The certificate and the signing key do not belong together, for
    /// example because the wrong YubiKey is plugged in.
    #[error("the signing key does not match the CA certificate")]
    KeyMismatch,

    /// The certificate is not a CA certificate.
    #[error("the certificate is not a CA certificate")]
    NotCa,

    /// The CA certificate has expired, so nothing can be issued from it.
    #[error("the CA certificate has expired")]
    CaExpired,

    /// The caller asked for something a profile does not allow.
    #[error("{0}")]
    InvalidRequest(String),

    /// The password given for a `.p12` file does not open it.
    #[error("the password does not open the .p12 file")]
    WrongP12Password,

    /// Talking to a YubiKey failed.
    #[error("YubiKey error: {0}")]
    Device(String),

    /// The YubiKey rejected the PIN. Each wrong PIN uses up one attempt.
    #[error("wrong PIN, {attempts_left} attempts left before the YubiKey locks")]
    WrongPin {
        /// How many more wrong PINs the key tolerates.
        attempts_left: u8,
    },

    /// The YubiKey was asked to sign and did not, most likely because
    /// nobody touched it before it gave up waiting.
    #[error("the YubiKey did not sign; it was probably not touched in time")]
    NotTouched,

    /// Too many wrong PINs; the YubiKey must be unblocked with its PUK.
    #[error("the PIN is locked; unblock it with the PUK first")]
    PinLocked,

    /// One more wrong PIN would lock it, so none is tried: a slip of the
    /// finger is not worth a locked PIN.
    #[error(
        "only one PIN attempt is left on this YubiKey; a wrong PIN now would lock it. Enter the \
         correct PIN once in another tool to reset the counter, then retry."
    )]
    LastAttempt,

    /// Another program is talking to the YubiKeys and has not finished in
    /// the time anything it does there takes.
    #[error("another program is using the YubiKeys; try again when it has finished")]
    KeysBusy,

    /// The YubiKey rejected the PUK. Each wrong PUK uses up one attempt,
    /// and there is nothing to unblock a PUK with.
    #[error("wrong PUK, {attempts_left} attempts left before it locks permanently")]
    WrongPuk {
        /// How many more wrong PUKs the key tolerates.
        attempts_left: u8,
    },

    /// Too many wrong PUKs. Nothing unblocks a PUK: the PIV application
    /// of the YubiKey has to be reset, which destroys the CA on it.
    #[error("the PUK is locked; only resetting the YubiKey's PIV application is left")]
    PukLocked,

    /// The YubiKey still has the PIN it left the factory with, which
    /// everybody knows. A CA must not be created behind it.
    #[error("this YubiKey still has its factory PIN; set a new one first")]
    FactoryPin,

    /// The PIN is the person's own, but the PUK or the management key is
    /// still the one every YubiKey leaves the factory with. The PUK sets
    /// a new PIN and the management key overwrites what the key holds, so
    /// a CA must not be created behind them either.
    #[error(
        "this YubiKey still has its factory PUK or management key, which everybody knows; give \
         it its own first"
    )]
    FactoryPukOrKey,

    /// Slot 9c of the YubiKey already holds a key or a certificate, and
    /// the caller did not ask to replace it.
    #[error("slot 9c of this YubiKey is already in use")]
    SlotInUse,

    /// A new key was generated on the YubiKey, replacing whatever the slot
    /// held, but the CA could not be completed.
    #[error("a new key was generated in slot 9c, but the CA was not finished: {0}")]
    SetupInterrupted(#[source] Box<Error>),

    /// Reading or writing the PKI folder failed, or it does not hold what
    /// was asked for.
    #[error("{0}")]
    Store(String),

    /// Building an export file failed.
    #[error("could not build the export: {0}")]
    Export(String),

    /// The operating system could not provide random bytes.
    #[error("random number generator failed: {0}")]
    Random(String),
}
