//! Core library of yca, a certificate authority for YubiKey.
//!
//! In short: a root CA and an issuing CA, each backed by a signing key that
//! never leaves its hardware, issue certificates from a small set of fixed
//! profiles instead of exposing X.509 options.
//!
//! Signing goes through [`SigningKey`], so the same code runs against a
//! YubiKey in production and against an in-memory [`KeyPair`] in tests.

pub mod agent;
mod authority;
mod csr;
pub mod device;
mod error;
mod export;
mod profile;
mod revocation;
mod setup;
mod signer;
mod store;
pub mod view;

pub use authority::{Authority, IssuedCertificate};
pub use csr::SigningRequest;
pub use error::Error;
pub use export::{
    CERTIFICATE_FILE, ExportFile, ExportForm, ExportSource, FULLCHAIN_FILE, INTERMEDIATE_FILE,
    KEY_FILE, P12_FILE, P12Encryption, P12Options, export, key_from_p12, p12_encryption,
};
pub use profile::{LeafProfile, LeafRequest};
pub use rcgen::{
    KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_RSA_SHA256, PublicKeyData,
    RsaKeySize, SignatureAlgorithm, SigningKey,
};
pub use revocation::{RevocationList, Revoked};
pub use setup::{
    Attestation, CaKeyType, NewCa, Protected, attest_ca_on_yubikey, change_pin, finish_protecting,
    protect_yubikey, reset_piv, unblock_pin,
};
pub use signer::YubiKeySigner;
pub use store::{
    CaEntry, CertificateFolder, CrlStatus, Deleted, Fingerprints, Record, Renewal, Repack,
    Repacked, RetiredCa, Status, Store,
};
