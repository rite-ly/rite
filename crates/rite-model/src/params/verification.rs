//! Params for the verification actions.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::types::Vocabulary;

/// The `with` block of `clock_check`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ClockCheckParams {
    /// Shown above the time.
    #[serde(default)]
    pub message: Option<String>,
}

/// The `with` block of `confirm`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ConfirmParams {
    /// The question the person answers.
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

/// The `with` block of `oral_readback`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct OralReadbackParams {
    /// A prompt shown before the value is read aloud.
    #[serde(default)]
    pub message: Option<String>,
    /// The value to read aloud, such as a fingerprint from an artifact.
    pub value: String,
    /// The format used to display the value. Defaults to `nato_phonetic`.
    #[serde(default)]
    pub format: Option<ReadbackFormat>,
    /// The number of characters to read aloud from the start of the value.
    #[serde(default)]
    pub characters: Option<u32>,
}

/// The `with` block of `check_value`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CheckValueParams {
    /// The value to compare with `expected`.
    pub actual: String,
    /// The value that `actual` must match.
    pub expected: String,
    /// A description of the check, shown with its result.
    #[serde(default)]
    pub message: Option<String>,
    /// Whether to hide the compared values when they do not match.
    #[serde(default)]
    pub sensitive: bool,
}

/// The `with` block of `machine_info`.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct MachineInfoParams {
    /// Whether to record a hash of the machine ID. Defaults to `true`.
    #[serde(default = "default_true")]
    pub include_machine_id: bool,
    /// Whether to record the processor model. Defaults to `true`.
    #[serde(default = "default_true")]
    pub include_cpu: bool,
    /// Whether to record the operating system and kernel versions. Defaults to
    /// `true`.
    #[serde(default = "default_true")]
    pub include_os: bool,
    /// Whether to record the machine's memory protections: RAM encryption,
    /// IOMMU DMA protection, and zeroing of freed pages. Defaults to `true`.
    #[serde(default = "default_true")]
    pub include_security_features: bool,
    /// Shown to the operator when the step starts.
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
