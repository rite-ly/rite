//! Params for the certificate actions.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::CertProfile;

/// The `with` block of `generate_csr`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct GenerateCsrParams {
    /// The certificate subject, written as an RFC 4514 name such as
    /// `CN=example.com,O=Acme,C=US`.
    pub subject: String,
    /// Subject alternative names to include, such as `DNS:example.com` or
    /// `IP:192.0.2.1`.
    #[serde(default)]
    pub san: Option<Vec<String>>,
}

/// The `with` block of `issue_certificate`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct IssueCertificateParams {
    /// The certificate profile, which determines its extensions. Defaults to
    /// `end_entity`.
    //
    // The least privileged shape is the default.
    #[serde(default = "end_entity")]
    pub profile: CertProfile,
    /// The certificate's validity period in days. Defaults to 3650 days.
    #[serde(default = "ten_years")]
    pub validity_days: u32,
    /// The issuer's common name when the step does not read an issuer
    /// certificate.
    #[serde(default)]
    pub issuer_cn: Option<String>,
    /// For `sub_ca`, how many CA certificates may follow this one in a chain.
    /// Defaults to 0.
    #[serde(default)]
    pub path_len: Option<u8>,
}

fn end_entity() -> CertProfile {
    CertProfile::EndEntity
}

fn ten_years() -> u32 {
    3650
}

impl Default for IssueCertificateParams {
    fn default() -> Self {
        Self {
            profile: end_entity(),
            validity_days: ten_years(),
            issuer_cn: None,
            path_len: None,
        }
    }
}
