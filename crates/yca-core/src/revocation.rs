//! Certificate revocation lists: how devices learn that a certificate was
//! revoked.

use rcgen::{
    CertificateRevocationListParams, KeyIdMethod, RevokedCertParams, SerialNumber, SigningKey,
};
use time::{Duration, OffsetDateTime};
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::revocation_list::CertificateRevocationList;

use crate::authority::{encode_pem_as, start_of_validity};
use crate::{Authority, Error};

/// How long a revocation list stays current. Devices that check
/// revocation refuse to work with a list past this point, so a new one
/// has to reach them before then. A year keeps a CA that is operated by
/// hand from causing outages.
const VALIDITY: Duration = Duration::days(365);

/// A certificate to put on a revocation list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revoked {
    /// Serial number of the certificate, in hexadecimal.
    pub serial: String,
    /// When it was revoked.
    pub revoked_at: OffsetDateTime,
}

/// A signed revocation list of one CA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationList {
    der: Vec<u8>,
    number: u64,
    entries: usize,
    next_update: OffsetDateTime,
}

impl RevocationList {
    /// The list in DER form.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The list in PEM form.
    pub fn pem(&self) -> String {
        encode_pem_as("X509 CRL", &self.der)
    }

    /// The number of this list; each list of a CA has a higher one than
    /// the last, which is how a device tells a newer list from an older.
    pub fn number(&self) -> u64 {
        self.number
    }

    /// How many certificates the list revokes.
    pub fn len(&self) -> usize {
        self.entries
    }

    /// Whether the list revokes nothing. Such a list is still worth
    /// distributing: it tells devices that nothing is revoked.
    pub fn is_empty(&self) -> bool {
        self.entries == 0
    }

    /// When devices start to consider this list out of date.
    pub fn next_update(&self) -> OffsetDateTime {
        self.next_update
    }
}

impl<S: SigningKey> Authority<S> {
    /// Signs a revocation list naming `revoked`, which must all be
    /// certificates this CA issued.
    ///
    /// `number` has to be higher than the number of every list this CA
    /// signed before. The list is current for a year, or until the CA
    /// expires if that comes first.
    pub fn revocation_list(
        &self,
        revoked: &[Revoked],
        number: u64,
        now: OffsetDateTime,
    ) -> Result<RevocationList, Error> {
        self.ensure_not_expired(now)?;
        let this_update = start_of_validity(now);
        let next_update = self.not_after.min(this_update + VALIDITY);

        let revoked_certs = revoked
            .iter()
            .map(|entry| {
                Ok(RevokedCertParams {
                    serial_number: SerialNumber::from_slice(&serial_bytes(&entry.serial)?),
                    // A revocation dated after the list itself would be
                    // rejected by strict validators.
                    revocation_time: entry.revoked_at.min(this_update),
                    reason_code: None,
                    invalidity_date: None,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let params = CertificateRevocationListParams {
            this_update,
            next_update,
            crl_number: SerialNumber::from_slice(&minimal_bytes(number)),
            issuing_distribution_point: None,
            revoked_certs,
            // The list must point at the CA by the identifier the CA
            // certificate carries, which for a CA made by another tool is
            // not necessarily the one rcgen would compute.
            key_identifier_method: match self.subject_key_identifier()? {
                Some(identifier) => KeyIdMethod::PreSpecified(identifier),
                None => KeyIdMethod::Sha256,
            },
        };
        let der = params.signed_by(&self.issuer)?.der().to_vec();
        self.check_list_signed_by_this_ca(&der)?;

        Ok(RevocationList {
            der,
            number,
            entries: revoked.len(),
            next_update,
        })
    }

    fn subject_key_identifier(&self) -> Result<Option<Vec<u8>>, Error> {
        let (_, ca) =
            X509Certificate::from_der(&self.cert_der).map_err(|e| Error::Parse(e.to_string()))?;
        Ok(ca
            .iter_extensions()
            .find_map(|extension| match extension.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(identifier) => Some(identifier.0.to_vec()),
                _ => None,
            }))
    }

    /// The same guard as for certificates: a list signed by any key but
    /// this CA's never leaves the library.
    fn check_list_signed_by_this_ca(&self, list_der: &[u8]) -> Result<(), Error> {
        let (_, ca) =
            X509Certificate::from_der(&self.cert_der).map_err(|e| Error::Parse(e.to_string()))?;
        let (_, list) = CertificateRevocationList::from_der(list_der)
            .map_err(|e| Error::Parse(e.to_string()))?;
        list.verify_signature(ca.public_key())
            .map_err(|_| Error::KeyMismatch)
    }
}

fn serial_bytes(serial: &str) -> Result<Vec<u8>, Error> {
    let invalid = || Error::InvalidRequest(format!("'{serial}' is not a serial number"));
    let digits: Vec<u8> = serial
        .chars()
        .filter(|c| *c != ':')
        .map(|c| c.to_digit(16).map(|digit| digit as u8).ok_or_else(invalid))
        .collect::<Result<_, _>>()?;
    if digits.is_empty() || !digits.len().is_multiple_of(2) {
        return Err(invalid());
    }
    Ok(digits
        .chunks(2)
        .map(|pair| pair[0] << 4 | pair[1])
        .collect())
}

/// Big-endian bytes without leading zeros, as an ASN.1 integer wants them.
fn minimal_bytes(number: u64) -> Vec<u8> {
    let bytes = number.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(7);
    bytes[first..].to_vec()
}
