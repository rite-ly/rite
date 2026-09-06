//! Parameter structs for action handlers.

use serde::{Deserialize, Serialize};

/// Read a `with:` field that must hold a string, for `Action::validate`.
///
/// `Ok(None)` covers both an unset field and one deferred to run time, which
/// the literal projection leaves absent. Neither is an error before execution.
pub(crate) fn string_param<'a>(
    params: &'a serde_json::Value,
    field: &str,
) -> Result<Option<&'a str>, String> {
    match params.get(field) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or_else(|| format!("{field} must be a string, got {value}")),
    }
}

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

/// Display format for the `oral_readback` action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadbackFormat {
    /// NATO phonetic alphabet (default).
    #[default]
    #[serde(alias = "nato")]
    NatoPhonetic,
    /// Hex pairs, grouped by 4 bytes.
    Hex,
    /// Raw value, no transformation.
    Raw,
}

impl ReadbackFormat {
    /// Short label suitable for transcript display.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ReadbackFormat::NatoPhonetic => "nato_phonetic",
            ReadbackFormat::Hex => "hex",
            ReadbackFormat::Raw => "raw",
        }
    }
}

/// Params for `oral_readback` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OralReadbackParams {
    /// Value to read aloud. Can be a literal string or artifact reference.
    #[serde(default)]
    pub value: Option<String>,
    /// Display format. Defaults to NATO phonetic.
    #[serde(default)]
    pub format: Option<ReadbackFormat>,
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

/// Params for `attest` action.
#[cfg(feature = "attestation")]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttestParams {
    /// The attestation statement.
    #[serde(default)]
    pub statement: Option<String>,
}

/// Params for `gather_entropy` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GatherEntropyParams {
    /// Instruction shown to the participant describing how to produce the
    /// random value. Defaults to a generic dice suggestion; override per
    /// ceremony to mandate a specific method.
    #[serde(default)]
    pub instruction: Option<String>,
}

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
    /// Wrapping algorithm. Defaults to `"CMS-RSA-GCM"`.
    ///
    /// The OpenSSL backend accepts `"CMS-RSA-GCM"` and `"CMS-RSA-CBC"`. The
    /// other names `WrapAlgorithm` parses, `"AES-KW"`, `"AES-KWP"` and
    /// `"RSA-OAEP-SHA256"`, have no backend and fail when the step runs.
    #[serde(default)]
    pub algorithm: Option<String>,
}

/// Params for `sign_data` action.
#[cfg(feature = "crypto")]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignDataParams {
    /// Signature algorithm. Defaults to the one implied by the key.
    ///
    /// Worth setting for an RSA key, which can sign under either
    /// `"RSA-PKCS1-SHA256"` (the default) or `"RSA-PSS-SHA256"`. Every other
    /// key type admits exactly one algorithm, so naming it only restates the
    /// key.
    #[serde(default)]
    pub algorithm: Option<String>,
    /// Optional display message.
    #[serde(default)]
    pub message: Option<String>,
}

/// Params for `verify_signature` action.
#[cfg(feature = "crypto")]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerifySignatureParams {
    /// Signature algorithm. Defaults to the one implied by the public key.
    ///
    /// Required when checking an RSA-PSS signature, since an RSA key alone
    /// does not say which scheme was used.
    #[serde(default)]
    pub algorithm: Option<String>,
    /// Optional display message.
    #[serde(default)]
    pub message: Option<String>,
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
    /// Issuer Common Name override (as `CN=<value>`) when no `issuer_cert`
    /// input is provided. Defaults to the CSR subject, producing a
    /// self-issued certificate.
    #[serde(default)]
    pub issuer_cn: Option<String>,
    /// `pathLenConstraint` for `sub_ca` profile (default: 0).
    #[serde(default)]
    pub path_len: Option<u8>,
}
