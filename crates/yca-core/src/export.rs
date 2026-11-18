//! The files that take a certificate to where it is used.
//!
//! The user says what the upload form of the device asks for; the form
//! decides which files that takes and what is in each, so nobody has to
//! think about the certificate chain. A folder gets exactly the files of
//! one form, each named after the field it goes into, and nothing else to
//! pick the right one from.

use p12_keystore::{
    Certificate, EncryptionAlgorithm, KeyStore, KeyStoreEntry, MacAlgorithm, Pkcs12ImportPolicy,
    PrivateKey, PrivateKeyChain,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::authority::{encode_pem, encode_pem_as};
use crate::{Error, IssuedCertificate};

/// The certificate on its own, or the only certificate file where the
/// root CA signed and there is no chain to speak of.
pub const CERTIFICATE_FILE: &str = "certificate.crt";
/// The certificate followed by the intermediate CA.
pub const FULLCHAIN_FILE: &str = "fullchain.crt";
/// The intermediate CA: the issuing CA that signed the certificate.
pub const INTERMEDIATE_FILE: &str = "intermediate-ca.crt";
/// The private key of the certificate.
pub const KEY_FILE: &str = "private-key.key";
/// Certificate, intermediate CA and private key in one file that opens
/// with a password.
pub const P12_FILE: &str = "certificate.p12";

/// What the upload form of the device asks for, and so which files a
/// certificate is handed over as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExportForm {
    /// A field for the certificate and one for the private key. The
    /// certificate file holds the intermediate CA as well: the full chain.
    #[default]
    Fullchain,
    /// A field each for the certificate, the intermediate CA and the
    /// private key.
    Separate,
    /// One file that opens with a password: certificate, intermediate CA
    /// and private key together, as PKCS #12. What a form with a single
    /// file and a password takes, and what a laptop or a phone imports.
    #[serde(rename = "p12")]
    Pkcs12,
}

impl ExportForm {
    /// The name the form goes by outside the program.
    pub fn name(self) -> &'static str {
        match self {
            ExportForm::Fullchain => "fullchain",
            ExportForm::Separate => "separate",
            ExportForm::Pkcs12 => "p12",
        }
    }
}

/// How the `.p12` file is encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum P12Encryption {
    /// AES-256 with SHA-256. What current systems expect.
    #[default]
    Modern,
    /// Triple DES with SHA-1. Weaker, but older systems import nothing
    /// else.
    Compatible,
}

/// One file of a certificate's folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportFile {
    /// File name, without a directory.
    pub name: String,
    /// What to write into it.
    pub contents: Vec<u8>,
    /// Whether the file holds a private key and deserves care.
    pub holds_private_key: bool,
    /// One line on what the file is for.
    pub purpose: &'static str,
}

/// What the files are made from.
#[derive(Debug, Clone, Copy)]
pub struct ExportSource<'a> {
    /// The certificate to install.
    pub issued: &'a IssuedCertificate,
    /// The certificate's private key in PKCS#8 form, if yca generated it.
    /// A certificate issued for a device's own request has none.
    pub private_key_der: Option<&'a [u8]>,
}

/// Password and encryption of a `.p12` file.
#[derive(Debug, Clone, Copy)]
pub struct P12Options<'a> {
    /// The password that opens the file. Must not be empty; phones refuse
    /// a `.p12` without one.
    pub password: &'a str,
    /// How to encrypt it.
    pub encryption: P12Encryption,
    /// The name the certificate shows up under after import.
    pub label: &'a str,
}

/// Builds the files of one form. [`ExportForm::Pkcs12`] needs the private
/// key and `p12`; the other forms ignore `p12` and leave the key file out
/// if there is no key.
///
/// The root CA certificate is never among them. A device does not send
/// it, and whoever has to trust it gets it from one place, the workspace.
pub fn export(
    form: ExportForm,
    source: ExportSource<'_>,
    p12: Option<P12Options<'_>>,
) -> Result<Vec<ExportFile>, Error> {
    let issued = source.issued;
    let mut files = match (form, issued.intermediate_der()) {
        (ExportForm::Pkcs12, _) => {
            let options = p12
                .ok_or_else(|| Error::InvalidRequest("a .p12 file needs a password".to_owned()))?;
            let key_der = source.private_key_der.ok_or_else(|| {
                Error::InvalidRequest(
                    "a .p12 file holds the private key, which only exists for a certificate \
                     yca generated the key for"
                        .to_owned(),
                )
            })?;
            return Ok(vec![ExportFile {
                name: P12_FILE.to_owned(),
                contents: pkcs12(issued, key_der, options)?,
                holds_private_key: true,
                purpose: "certificate, intermediate CA and private key; opens with the password",
            }]);
        }
        // Signed by the root itself: there is no chain, and both forms
        // come to the same one file.
        (_, None) => vec![public(
            CERTIFICATE_FILE,
            issued.pem(),
            "certificate; the root CA signed it directly, so there is no intermediate CA",
        )],
        (ExportForm::Fullchain, Some(_)) => vec![public(
            FULLCHAIN_FILE,
            issued.fullchain_pem(),
            "certificate followed by the intermediate CA; goes where the certificate is asked for",
        )],
        (ExportForm::Separate, Some(intermediate)) => vec![
            public(CERTIFICATE_FILE, issued.pem(), "certificate"),
            public(
                INTERMEDIATE_FILE,
                encode_pem(intermediate),
                "intermediate CA certificate",
            ),
        ],
    };
    files.extend(source.private_key_der.map(|der| ExportFile {
        name: KEY_FILE.to_owned(),
        contents: encode_pem_as("PRIVATE KEY", der).into_bytes(),
        holds_private_key: true,
        purpose: "private key of the certificate",
    }));
    Ok(files)
}

/// Takes the private key out of a `.p12` file, in PKCS#8 form. For packing
/// a certificate anew whose key is nowhere else.
pub fn key_from_p12(contents: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let keystore =
        KeyStore::from_pkcs12(contents, password, Pkcs12ImportPolicy::Relaxed).map_err(|_| {
            Error::InvalidRequest("the password does not open the .p12 file".to_owned())
        })?;
    let (_, chain) = keystore
        .private_key_chain()
        .ok_or_else(|| Error::Export("the .p12 file holds no private key".to_owned()))?;
    Ok(Zeroizing::new(chain.key().as_der().to_vec()))
}

fn public(name: &str, pem: String, purpose: &'static str) -> ExportFile {
    ExportFile {
        name: name.to_owned(),
        contents: pem.into_bytes(),
        holds_private_key: false,
        purpose,
    }
}

fn pkcs12(
    issued: &IssuedCertificate,
    key_der: &[u8],
    options: P12Options<'_>,
) -> Result<Vec<u8>, Error> {
    if options.password.is_empty() {
        return Err(Error::InvalidRequest(
            "the .p12 password must not be empty".to_owned(),
        ));
    }
    let failed = |e: p12_keystore::error::Error| Error::Export(e.to_string());

    // The leaf first, then the issuing CA. The root stays out: whoever
    // imports the file must trust it separately anyway.
    let mut chain = vec![Certificate::from_der(issued.der()).map_err(failed)?];
    if let Some(intermediate) = issued.intermediate_der() {
        chain.push(Certificate::from_der(intermediate).map_err(failed)?);
    }
    // Ties the key to its certificate inside the file.
    let key_id = Sha256::digest(issued.der())[..20].to_vec();

    let mut keystore = KeyStore::new();
    keystore.add_entry(
        options.label,
        KeyStoreEntry::PrivateKeyChain(PrivateKeyChain::new(
            key_id,
            PrivateKey::from_der(key_der).map_err(failed)?,
            chain,
        )),
    );
    let (encryption, mac) = match options.encryption {
        P12Encryption::Modern => (
            EncryptionAlgorithm::PbeWithHmacSha256AndAes256,
            MacAlgorithm::HmacSha256,
        ),
        P12Encryption::Compatible => (
            EncryptionAlgorithm::PbeWithShaAnd3KeyTripleDesCbc,
            MacAlgorithm::HmacSha1,
        ),
    };
    keystore
        .writer(options.password)
        .encryption_algorithm(encryption)
        .mac_algorithm(mac)
        .write()
        .map_err(failed)
}
