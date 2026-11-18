//! Certificate profiles: the user says what a certificate is for, and the
//! profile decides key usage, extended key usage, SAN and maximum validity.

use std::net::IpAddr;
use std::str::FromStr;

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose,
    SanType,
};
use time::Duration;

use crate::Error;

/// id-kp-ipsecIKE (RFC 4945), expected by some IKEv2 implementations.
const EKU_IPSEC_IKE: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 17];

/// Apple platforms reject TLS server certificates valid for more than 825
/// days, even when they chain to a privately installed root.
const TLS_SERVER_MAX_DAYS: i64 = 825;

/// What an end-entity certificate is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LeafProfile {
    /// A web server or any other TLS server.
    TlsServer,
    /// A TLS client authenticating with a certificate.
    TlsClient,
    /// An IPsec/IKEv2 gateway such as a FortiGate or a MikroTik router.
    IpsecGateway,
    /// An IPsec/IKEv2 client such as a laptop or a phone.
    IpsecClient,
}

impl LeafProfile {
    /// The longest validity the target platforms accept, if they limit it.
    /// `None` means the certificate may live as long as its CA.
    pub(crate) fn max_validity(self) -> Option<Duration> {
        match self {
            LeafProfile::TlsServer => Some(Duration::days(TLS_SERVER_MAX_DAYS)),
            LeafProfile::TlsClient | LeafProfile::IpsecGateway | LeafProfile::IpsecClient => None,
        }
    }

    fn is_server(self) -> bool {
        matches!(self, LeafProfile::TlsServer | LeafProfile::IpsecGateway)
    }
}

/// A request for an end-entity certificate: a profile and the one or two
/// values the user fills in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafRequest {
    profile: LeafProfile,
    names: Vec<String>,
    validity_limit: Option<Duration>,
}

impl LeafRequest {
    /// A TLS server reachable under the given host names or IP addresses.
    pub fn tls_server<I, T>(hosts: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        Self::new(LeafProfile::TlsServer, hosts)
    }

    /// A TLS client identified by a name.
    pub fn tls_client(name: impl Into<String>) -> Result<Self, Error> {
        Self::new(LeafProfile::TlsClient, [name])
    }

    /// An IPsec gateway reachable under the given host names or IP addresses.
    pub fn ipsec_gateway<I, T>(hosts: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        Self::new(LeafProfile::IpsecGateway, hosts)
    }

    /// An IPsec client identified by a name or an e-mail address.
    pub fn ipsec_client(name_or_email: impl Into<String>) -> Result<Self, Error> {
        Self::new(LeafProfile::IpsecClient, [name_or_email])
    }

    /// A request for the given profile. Servers and gateways take one or
    /// more host names or IP addresses, clients exactly one name.
    pub fn for_profile<I, T>(profile: LeafProfile, names: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        let request = Self::new(profile, names)?;
        if !profile.is_server() && request.names.len() != 1 {
            return Err(Error::InvalidRequest(
                "a client certificate takes exactly one name".to_owned(),
            ));
        }
        Ok(request)
    }

    fn new<I, T>(profile: LeafProfile, names: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        let names: Vec<String> = names
            .into_iter()
            .map(|name| name.into().trim().to_owned())
            .collect();
        if names.is_empty() || names.iter().any(String::is_empty) {
            let what = if profile.is_server() {
                "at least one host name or IP address is required"
            } else {
                "a name is required"
            };
            return Err(Error::InvalidRequest(what.to_owned()));
        }
        Ok(Self {
            profile,
            names,
            validity_limit: None,
        })
    }

    /// Asks for a certificate that expires sooner than the longest the
    /// profile and the CA allow, which is the default.
    pub fn valid_for(mut self, limit: Duration) -> Result<Self, Error> {
        if limit <= Duration::ZERO {
            return Err(Error::InvalidRequest(
                "the validity must be longer than zero".to_owned(),
            ));
        }
        self.validity_limit = Some(limit);
        Ok(self)
    }

    /// The profile this request uses.
    pub fn profile(&self) -> LeafProfile {
        self.profile
    }

    /// The names the certificate is asked for.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// The longest this certificate may live regardless of its CA: the
    /// shorter of the profile's platform limit and the requested limit.
    pub(crate) fn max_validity(&self) -> Option<Duration> {
        match (self.profile.max_validity(), self.validity_limit) {
            (Some(profile), Some(requested)) => Some(profile.min(requested)),
            (profile, requested) => profile.or(requested),
        }
    }

    /// Certificate contents for this request, apart from validity and serial
    /// number, which depend on the issuing CA.
    pub(crate) fn params(&self, key_is_rsa: bool) -> Result<CertificateParams, Error> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::ExplicitNoCa;
        params.use_authority_key_identifier_extension = true;
        params.distinguished_name = common_name(&self.names[0]);

        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        if key_is_rsa && self.profile.is_server() {
            // Lets older peers that still use RSA key transport connect.
            params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
        }

        params.extended_key_usages = match self.profile {
            LeafProfile::TlsServer => vec![ExtendedKeyUsagePurpose::ServerAuth],
            LeafProfile::TlsClient | LeafProfile::IpsecClient => {
                vec![ExtendedKeyUsagePurpose::ClientAuth]
            }
            LeafProfile::IpsecGateway => vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::Other(EKU_IPSEC_IKE.to_vec()),
            ],
        };

        params.subject_alt_names = match self.profile {
            LeafProfile::TlsServer | LeafProfile::IpsecGateway => self
                .names
                .iter()
                .map(|name| host_san(name))
                .collect::<Result<_, _>>()?,
            LeafProfile::IpsecClient if self.names[0].contains('@') => {
                vec![SanType::Rfc822Name(ia5(&self.names[0])?)]
            }
            LeafProfile::TlsClient | LeafProfile::IpsecClient => Vec::new(),
        };

        Ok(params)
    }
}

/// A subject with only a common name. Organisation and the other X.500
/// fields are deliberately not offered.
pub(crate) fn common_name(name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    dn
}

fn host_san(host: &str) -> Result<SanType, Error> {
    match IpAddr::from_str(host) {
        Ok(ip) => Ok(SanType::IpAddress(ip)),
        Err(_) => Ok(SanType::DnsName(ia5(host)?)),
    }
}

fn ia5(value: &str) -> Result<rcgen::string::Ia5String, Error> {
    value.try_into().map_err(|_| {
        Error::InvalidRequest(format!(
            "'{value}' contains characters that are not allowed in a certificate name"
        ))
    })
}
