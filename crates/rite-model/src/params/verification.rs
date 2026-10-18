//! Params for the verification actions.

use serde::{Deserialize, Serialize};

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
