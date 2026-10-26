//! Params for the certificate actions.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::CertProfile;

/// Params for `generate_csr` action.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct GenerateCsrParams {
    /// Subject as RFC 4514 DN string: `"CN=example.com,O=Acme,C=US"`
    pub subject: String,
    /// Subject Alternative Names: `"DNS:foo.com"`, `"IP:1.2.3.4"`, `"email:u@example.com"`
    #[serde(default)]
    pub san: Option<Vec<String>>,
}

/// Params for `issue_certificate` action.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct IssueCertificateParams {
    /// Certificate profile controlling extensions. `sub_ca` is also
    /// accepted as `intermediate_ca`.
    //
    // The least privileged shape is the default.
    #[serde(default = "end_entity")]
    pub profile: CertProfile,
    /// Certificate validity period in days, about ten years by default.
    #[serde(default = "ten_years")]
    pub validity_days: u32,
    /// Issuer Common Name override (as `CN=<value>`) when no `issuer_cert`
    /// input is provided. Defaults to the CSR subject, producing a
    /// self-issued certificate.
    #[serde(default)]
    pub issuer_cn: Option<String>,
    /// `pathLenConstraint` for `sub_ca` profile (default: 0).
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
