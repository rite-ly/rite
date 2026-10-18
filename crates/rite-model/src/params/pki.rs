//! Params for the certificate actions.

use serde::{Deserialize, Serialize};

/// Params for `generate_csr` action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateCsrParams {
    /// Subject as RFC 4514 DN string: `"CN=example.com,O=Acme,C=US"`
    pub subject: String,
    /// Subject Alternative Names: `"DNS:foo.com"`, `"IP:1.2.3.4"`, `"email:u@example.com"`
    #[serde(default)]
    pub san: Option<Vec<String>>,
}

/// Params for `issue_certificate` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IssueCertificateParams {
    /// Certificate profile controlling extensions.
    /// Supported: `"root_ca"`, `"sub_ca"` (or `"intermediate_ca"`), `"tls_server"`,
    /// `"code_signing"`, `"end_entity"` (default).
    #[serde(default)]
    pub profile: Option<String>,
    /// Certificate validity period in days (default: 3650 = ~10 years).
    #[serde(default)]
    pub validity_days: Option<u32>,
    /// Issuer Common Name override (as `CN=<value>`) when no `issuer_cert`
    /// input is provided. Defaults to the CSR subject, producing a
    /// self-issued certificate.
    #[serde(default)]
    pub issuer_cn: Option<String>,
    /// `pathLenConstraint` for `sub_ca` profile (default: 0).
    #[serde(default)]
    pub path_len: Option<u8>,
}
