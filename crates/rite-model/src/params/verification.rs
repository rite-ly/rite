//! Params for the verification actions.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::types::Vocabulary;

/// Params for `clock_check` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ClockCheckParams {
    /// Message to display before showing the time.
    #[serde(default)]
    pub message: Option<String>,
}

/// Params for `confirm` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ConfirmParams {
    /// Message to display for confirmation.
    #[serde(default)]
    pub message: Option<String>,
}

/// Display format for the `oral_readback` action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
#[non_exhaustive]
pub enum ReadbackFormat {
    /// NATO phonetic alphabet (default). Also written `nato`.
    #[default]
    NatoPhonetic,
    /// Hex pairs, grouped by 4 bytes.
    Hex,
    /// Raw value, no transformation.
    Raw,
}

crate::types::vocabulary!(ReadbackFormat {
    NatoPhonetic => "nato_phonetic" | "nato",
    Hex => "hex",
    Raw => "raw",
});

impl From<ReadbackFormat> for String {
    fn from(format: ReadbackFormat) -> Self {
        format.as_str().to_string()
    }
}

impl TryFrom<String> for ReadbackFormat {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_name(&s).ok_or_else(|| {
            format!(
                "unknown readback format '{s}': expected {}",
                crate::types::either(Self::ALL.iter().map(|format| format.as_str()))
            )
        })
    }
}

impl JsonSchema for ReadbackFormat {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ReadbackFormat".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        Self::names_schema()
    }
}

/// Params for `oral_readback` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct OralReadbackParams {
    /// Instruction shown before the readback, as on the other verification
    /// actions.
    #[serde(default)]
    pub message: Option<String>,
    /// Value to read aloud. Can be a literal string or artifact reference.
    #[serde(default)]
    pub value: Option<String>,
    /// Display format. Defaults to NATO phonetic.
    #[serde(default)]
    pub format: Option<ReadbackFormat>,
    /// Limit number of characters to read (for long values).
    #[serde(default)]
    pub characters: Option<u32>,
}

/// Params for `check_value` action.
///
/// Machine-verified comparison of two values. Use this when both values are known
/// to the system and comparison is deterministic (e.g., hash verification).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
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
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
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
