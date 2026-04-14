//! Parameter structs for action handlers.

use serde::{Deserialize, Serialize};

// === Verification params ===

/// Params for `clock_check` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClockCheckParams {
    /// Message to display before showing the time.
    #[serde(default)]
    pub message: Option<String>,
}

/// Params for `confirm` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfirmParams {
    /// Message to display for confirmation.
    #[serde(default)]
    pub message: Option<String>,
}

/// Params for `oral_readback` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OralReadbackParams {
    /// Value to read aloud. Can be a literal string or artifact reference.
    #[serde(default)]
    pub value: Option<String>,
    /// Display format: `"nato_phonetic"` (default), `"hex"`, `"raw"`.
    #[serde(default)]
    pub format: Option<String>,
    /// Limit number of characters to read (for long values).
    #[serde(default)]
    pub characters: Option<u32>,
    /// If true, only record pass/fail result in evidence (no value recorded).
    #[serde(default)]
    pub sensitive: bool,
}

/// Params for `check_value` action.
///
/// Machine-verified comparison of two values. Use this when both values are known
/// to the system and comparison is deterministic (e.g., hash verification).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckValueParams {
    /// The computed or actual value to verify (required).
    pub actual: String,
    /// The expected value to compare against (required).
    pub expected: String,
    /// Human-readable description of what is being verified (for transcript/display).
    #[serde(default)]
    pub message: Option<String>,
    /// If true, only record pass/fail result in evidence (no values or lengths).
    #[serde(default)]
    pub sensitive: bool,
}

/// Params for `machine_info` action.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineInfoParams {
    /// Include hashed machine ID in evidence (default: true).
    #[serde(default = "default_true")]
    pub include_machine_id: bool,
    /// Include CPU model in evidence (default: true).
    #[serde(default = "default_true")]
    pub include_cpu: bool,
    /// Include OS information in evidence (default: true).
    #[serde(default = "default_true")]
    pub include_os: bool,
    /// Include memory protection status in evidence (default: true).
    #[serde(default = "default_true")]
    pub include_security_features: bool,
    /// Custom message to display before capturing machine info.
    #[serde(default)]
    pub message: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Default for MachineInfoParams {
    fn default() -> Self {
        Self {
            include_machine_id: true,
            include_cpu: true,
            include_os: true,
            include_security_features: true,
            message: None,
        }
    }
}

// === Attestation params ===

/// Params for `attest` action.
#[cfg(feature = "attestation")]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttestParams {
    /// The attestation statement.
    #[serde(default)]
    pub statement: Option<String>,
}

// === Crypto params ===

/// Params for `generate_keypair` action.
#[cfg(feature = "crypto")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateKeypairParams {
    /// Cryptographic algorithm (e.g., `"RSA-4096"`, `"ECDSA-P256"`).
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    /// Key usage flags.
    #[serde(default)]
    pub key_usage: Option<Vec<String>>,
    /// Backend-specific slot hint.
    #[serde(default)]
    pub slot: Option<String>,
}

#[cfg(feature = "crypto")]
fn default_algorithm() -> String {
    "RSA-4096".to_string()
}

#[cfg(feature = "crypto")]
impl Default for GenerateKeypairParams {
    fn default() -> Self {
        Self {
            algorithm: default_algorithm(),
            key_usage: None,
            slot: None,
        }
    }
}

/// Params for `wrap_key` action.
#[cfg(feature = "crypto")]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WrapKeyParams {
    /// Wrapping algorithm. Supported: `"CMS-RSA-GCM"` (default), `"CMS-RSA-CBC"`.
    #[serde(default)]
    pub algorithm: Option<String>,
}

/// Params for `unwrap_key` action.
#[cfg(feature = "crypto")]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UnwrapKeyParams {
    /// Wrapping algorithm. Should match the algorithm used for wrapping.
    #[serde(default)]
    pub algorithm: Option<String>,
    /// Label for the unwrapped key (defaults to `"unwrapped-key"`).
    #[serde(default)]
    pub label: Option<String>,
}

// === PKI params ===

/// Params for `generate_csr` action.
#[cfg(feature = "pki")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateCsrParams {
    /// Subject as RFC 4514 DN string: `"CN=example.com,O=Acme,C=US"`
    pub subject: String,
    /// Subject Alternative Names: `"DNS:foo.com"`, `"IP:1.2.3.4"`, `"email:u@example.com"`
    #[serde(default)]
    pub san: Option<Vec<String>>,
}

/// Params for `issue_certificate` action.
#[cfg(feature = "pki")]
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
    /// Fallback issuer Common Name when no `issuer_cert` input is provided.
    #[serde(default)]
    pub issuer_cn: Option<String>,
    /// `pathLenConstraint` for `sub_ca` profile (default: 0).
    #[serde(default)]
    pub path_len: Option<u8>,
}
