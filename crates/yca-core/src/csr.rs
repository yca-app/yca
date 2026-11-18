//! Certificate signing requests: a device generates its own key, keeps the
//! private half and sends a request for a certificate.

use std::net::IpAddr;

use rcgen::{SigningKey, SubjectPublicKeyInfo};
use time::OffsetDateTime;
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;
use x509_parser::public_key::PublicKey;

use crate::{Authority, Error, IssuedCertificate, LeafRequest};

/// RSA keys below this size are refused; current platforms reject them.
const MIN_RSA_BITS: usize = 2048;

/// A request from a device that holds its own private key.
///
/// Only two things are taken from it: the public key and, as a
/// suggestion, the names the device asked for. Key usage, validity and
/// everything else come from the profile, never from the request.
#[derive(Debug, Clone)]
pub struct SigningRequest {
    public_key: SubjectPublicKeyInfo,
    names: Vec<String>,
}

impl SigningRequest {
    /// Reads a request in PEM or DER form and checks its signature, which
    /// proves that whoever made the request holds the private key.
    pub fn parse(input: &[u8]) -> Result<Self, Error> {
        let der = match std::str::from_utf8(input) {
            Ok(text) if text.trim_start().starts_with("-----BEGIN") => pem::parse(text)
                .map_err(|e| Error::InvalidRequest(format!("not a certificate request: {e}")))?
                .into_contents(),
            _ => input.to_vec(),
        };
        let (_, request) = X509CertificationRequest::from_der(&der)
            .map_err(|_| Error::InvalidRequest("not a certificate request".to_owned()))?;
        request.verify_signature().map_err(|_| {
            Error::InvalidRequest(
                "the request's signature does not match its key; \
                 the file is damaged or was altered"
                    .to_owned(),
            )
        })?;

        let info = &request.certification_request_info;
        if let Ok(PublicKey::RSA(rsa)) = info.subject_pki.parsed()
            && rsa.key_size() < MIN_RSA_BITS
        {
            return Err(Error::InvalidRequest(format!(
                "the request uses a {}-bit RSA key; at least {MIN_RSA_BITS} bits are required",
                rsa.key_size()
            )));
        }
        let public_key = SubjectPublicKeyInfo::from_der(info.subject_pki.raw).map_err(|_| {
            Error::InvalidRequest("the request uses an unsupported key type".to_owned())
        })?;

        let mut names = Vec::new();
        for extension in request.requested_extensions().into_iter().flatten() {
            if let ParsedExtension::SubjectAlternativeName(san) = extension {
                names.extend(san.general_names.iter().filter_map(general_name));
            }
        }
        if names.is_empty()
            && let Some(common_name) = info
                .subject
                .iter_common_name()
                .next()
                .and_then(|name| name.as_str().ok())
        {
            names.push(common_name.to_owned());
        }
        names.dedup();

        Ok(Self { public_key, names })
    }

    /// The names the device asked for: its subject alternative names, or
    /// its common name if it gave none. A suggestion only.
    pub fn names(&self) -> &[String] {
        &self.names
    }
}

fn general_name(name: &GeneralName<'_>) -> Option<String> {
    match name {
        GeneralName::DNSName(dns) => Some((*dns).to_owned()),
        GeneralName::RFC822Name(email) => Some((*email).to_owned()),
        GeneralName::IPAddress(bytes) => match bytes.len() {
            4 => <[u8; 4]>::try_from(*bytes)
                .ok()
                .map(|b| IpAddr::from(b).to_string()),
            16 => <[u8; 16]>::try_from(*bytes)
                .ok()
                .map(|b| IpAddr::from(b).to_string()),
            _ => None,
        },
        _ => None,
    }
}

impl<S: SigningKey> Authority<S> {
    /// Issues a certificate for the key in a device's request. The private
    /// key never leaves the device.
    pub fn sign_request(
        &self,
        request: &LeafRequest,
        signing_request: &SigningRequest,
        now: OffsetDateTime,
    ) -> Result<IssuedCertificate, Error> {
        self.issue(request, &signing_request.public_key, now)
    }
}
