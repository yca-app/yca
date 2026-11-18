//! A certificate authority: a CA certificate together with the key that
//! signs for it.

use rcgen::{
    BasicConstraints, CertificateParams, IsCa, Issuer, KeyUsagePurpose, PKCS_RSA_SHA256,
    PKCS_RSA_SHA384, PKCS_RSA_SHA512, PublicKeyData, SerialNumber, SignatureAlgorithm, SigningKey,
};
use time::{Duration, OffsetDateTime};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::Error;
use crate::profile::{LeafRequest, common_name};

/// Validity of a new root CA: 20 years, counted in days so leap years do
/// not matter.
const ROOT_VALIDITY: Duration = Duration::days(20 * 365 + 5);

/// Certificates start a little in the past so that a device whose clock
/// runs slightly behind does not reject a freshly issued certificate.
const BACKDATE: Duration = Duration::minutes(5);

/// A root or issuing CA that can sign certificates.
///
/// `S` is the signing key: a YubiKey in production, an in-memory key in
/// tests. The private key itself is never visible here.
pub struct Authority<S> {
    pub(crate) cert_der: Vec<u8>,
    pub(crate) not_after: OffsetDateTime,
    is_root: bool,
    pub(crate) issuer: Issuer<'static, S>,
}

impl<S: SigningKey> Authority<S> {
    /// Opens an existing CA from its stored certificate and its signing key.
    ///
    /// Fails if the certificate is not a CA certificate or if the key does
    /// not belong to it, which is what happens when the wrong YubiKey is
    /// plugged in.
    pub fn load(cert_der: &[u8], key: S) -> Result<Self, Error> {
        let (rest, cert) =
            X509Certificate::from_der(cert_der).map_err(|e| Error::Parse(e.to_string()))?;
        if !rest.is_empty() {
            return Err(Error::Parse("trailing data after certificate".to_owned()));
        }

        let is_ca = cert
            .basic_constraints()
            .map_err(|e| Error::Parse(e.to_string()))?
            .is_some_and(|ext| ext.value.ca);
        if !is_ca {
            return Err(Error::NotCa);
        }
        if cert.public_key().raw != key.subject_public_key_info().as_slice() {
            return Err(Error::KeyMismatch);
        }

        let not_after = cert.validity().not_after.to_datetime();
        let is_root = cert.subject().as_raw() == cert.issuer().as_raw();
        let issuer = Issuer::from_ca_cert_der(&cert_der.into(), key)?;

        Ok(Self {
            cert_der: cert_der.to_vec(),
            not_after,
            is_root,
            issuer,
        })
    }

    /// Creates a new self-signed root CA.
    pub fn create_root(name: &str, key: S, now: OffsetDateTime) -> Result<Self, Error> {
        let not_before = start_of_validity(now);
        let params = ca_params(
            name,
            BasicConstraints::Constrained(1),
            not_before,
            not_before + ROOT_VALIDITY,
        )?;
        let cert = params.self_signed(&key)?;
        let root = Self::load(cert.der(), key)?;
        root.check_signed_by_this_ca(root.certificate_der())?;
        Ok(root)
    }

    /// Creates an issuing CA signed by this CA. It is valid for as long as
    /// this CA is and cannot have CAs below it.
    pub fn create_issuing<K: SigningKey>(
        &self,
        name: &str,
        key: K,
        now: OffsetDateTime,
    ) -> Result<Authority<K>, Error> {
        self.ensure_not_expired(now)?;
        let mut params = ca_params(
            name,
            BasicConstraints::Constrained(0),
            start_of_validity(now),
            self.not_after,
        )?;
        params.use_authority_key_identifier_extension = true;
        let cert = params.signed_by(&key, &self.issuer)?;
        self.check_signed_by_this_ca(cert.der())?;
        Authority::load(cert.der(), key)
    }

    /// Issues an end-entity certificate for `public_key`.
    ///
    /// The certificate is valid for as long as its profile and this CA
    /// allow, whichever ends first.
    pub fn issue(
        &self,
        request: &LeafRequest,
        public_key: &impl PublicKeyData,
        now: OffsetDateTime,
    ) -> Result<IssuedCertificate, Error> {
        self.ensure_not_expired(now)?;

        let not_before = start_of_validity(now);
        let not_after = match request.max_validity() {
            // X.509 validity includes both end points, hence the second.
            Some(max) => self.not_after.min(not_before + max - Duration::seconds(1)),
            None => self.not_after,
        };

        let mut params = request.params(is_rsa(public_key.algorithm()))?;
        params.not_before = not_before;
        params.not_after = not_after;
        params.serial_number = Some(random_serial()?);

        let cert = params.signed_by(public_key, &self.issuer)?;
        self.check_signed_by_this_ca(cert.der())?;
        Ok(IssuedCertificate {
            der: cert.der().to_vec(),
            not_after,
            // A certificate issued directly by the root has no intermediate
            // to send along.
            intermediate_der: (!self.is_root).then(|| self.cert_der.clone()),
        })
    }

    /// Issues a certificate for the key of an earlier certificate.
    ///
    /// Changing a name or extending the validity needs only the public
    /// key, which the earlier certificate carries. The private key stays
    /// wherever it is, typically on the device, which then only needs the
    /// new certificate. The earlier certificate remains valid until it
    /// expires or is revoked.
    pub fn reissue(
        &self,
        request: &LeafRequest,
        previous_certificate_der: &[u8],
        now: OffsetDateTime,
    ) -> Result<IssuedCertificate, Error> {
        let (_, previous) = X509Certificate::from_der(previous_certificate_der)
            .map_err(|e| Error::Parse(e.to_string()))?;
        let public_key = rcgen::SubjectPublicKeyInfo::from_der(previous.public_key().raw)?;
        self.issue(request, &public_key, now)
    }

    /// The CA certificate in DER form.
    pub fn certificate_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// The CA certificate in PEM form.
    pub fn certificate_pem(&self) -> String {
        encode_pem(&self.cert_der)
    }

    /// The moment this CA expires. Nothing it issues can outlive it.
    pub fn not_after(&self) -> OffsetDateTime {
        self.not_after
    }

    /// Whether this is a self-signed root rather than an issuing CA.
    pub fn is_root(&self) -> bool {
        self.is_root
    }

    /// The signing key of this CA.
    pub fn key(&self) -> &S {
        self.issuer.key()
    }

    /// Confirms that a freshly signed certificate verifies against this
    /// CA's certificate.
    ///
    /// `load` can only compare public keys. This is the proof that the
    /// private key which actually signed is the one the CA certificate
    /// names, and it keeps a certificate nobody could validate from ever
    /// leaving the library.
    fn check_signed_by_this_ca(&self, issued_der: &[u8]) -> Result<(), Error> {
        let parse = |der| {
            X509Certificate::from_der(der)
                .map(|(_, cert)| cert)
                .map_err(|e| Error::Parse(e.to_string()))
        };
        let ca = parse(&self.cert_der)?;
        let issued = parse(issued_der)?;
        issued
            .verify_signature(Some(ca.public_key()))
            .map_err(|_| Error::KeyMismatch)
    }

    pub(crate) fn ensure_not_expired(&self, now: OffsetDateTime) -> Result<(), Error> {
        if now >= self.not_after {
            return Err(Error::CaExpired);
        }
        Ok(())
    }
}

/// An end-entity certificate together with what its holder has to present
/// alongside it.
#[derive(Debug, Clone)]
pub struct IssuedCertificate {
    der: Vec<u8>,
    not_after: OffsetDateTime,
    intermediate_der: Option<Vec<u8>>,
}

impl IssuedCertificate {
    /// A certificate that was issued earlier, put back together with the
    /// CA certificate that has to travel with it, for writing its files
    /// again.
    pub fn from_der(der: Vec<u8>, intermediate_der: Option<Vec<u8>>) -> Result<Self, Error> {
        let (_, certificate) =
            X509Certificate::from_der(&der).map_err(|e| Error::Parse(e.to_string()))?;
        let not_after = certificate.validity().not_after.to_datetime();
        Ok(Self {
            der,
            not_after,
            intermediate_der,
        })
    }

    /// The certificate in DER form.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The certificate alone, in PEM form.
    pub fn pem(&self) -> String {
        encode_pem(&self.der)
    }

    /// The serial number, in lowercase hexadecimal.
    pub fn serial(&self) -> Result<String, Error> {
        let (_, certificate) =
            X509Certificate::from_der(&self.der).map_err(|e| Error::Parse(e.to_string()))?;
        Ok(certificate
            .raw_serial()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    }

    /// The certificate followed by the issuing CA certificate, in PEM form.
    /// This is what a server sends to its peers; the root is left out
    /// because peers already have it.
    pub fn fullchain_pem(&self) -> String {
        let mut out = self.pem();
        if let Some(intermediate) = &self.intermediate_der {
            out.push_str(&encode_pem(intermediate));
        }
        out
    }

    /// The moment this certificate expires.
    pub fn not_after(&self) -> OffsetDateTime {
        self.not_after
    }

    /// The issuing CA certificate that has to travel with this one, or
    /// `None` if the root signed it directly.
    pub fn intermediate_der(&self) -> Option<&[u8]> {
        self.intermediate_der.as_deref()
    }
}

fn ca_params(
    name: &str,
    path_len: BasicConstraints,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> Result<CertificateParams, Error> {
    let name = name.trim();
    if name.is_empty() {
        return Err(Error::InvalidRequest("a CA name is required".to_owned()));
    }
    let mut params = CertificateParams::default();
    params.distinguished_name = common_name(name);
    params.is_ca = IsCa::Ca(path_len);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = not_before;
    params.not_after = not_after;
    params.serial_number = Some(random_serial()?);
    Ok(params)
}

pub(crate) fn start_of_validity(now: OffsetDateTime) -> OffsetDateTime {
    // Certificates carry whole seconds only.
    (now - BACKDATE)
        .replace_nanosecond(0)
        .expect("zero is a valid nanosecond")
}

/// A random 127-bit positive serial number. rcgen would otherwise derive
/// the serial from the public key, which repeats when a key is reused.
fn random_serial() -> Result<SerialNumber, Error> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| Error::Random(e.to_string()))?;
    bytes[0] &= 0x7f;
    if bytes[0] == 0 {
        bytes[0] = 1;
    }
    Ok(SerialNumber::from_slice(&bytes))
}

fn is_rsa(algorithm: &SignatureAlgorithm) -> bool {
    [&PKCS_RSA_SHA256, &PKCS_RSA_SHA384, &PKCS_RSA_SHA512].contains(&algorithm)
}

pub(crate) fn encode_pem(cert_der: &[u8]) -> String {
    encode_pem_as("CERTIFICATE", cert_der)
}

pub(crate) fn encode_pem_as(label: &str, der: &[u8]) -> String {
    pem::encode_config(
        &pem::Pem::new(label, der),
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    )
}
