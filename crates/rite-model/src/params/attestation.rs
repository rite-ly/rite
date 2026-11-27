//! Params for the `attest`, `attest_key` and `verify_attestation` actions.

use rite_sdk::AccessWhen;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The `with` block of `attest`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AttestParams {
    /// The statement recorded in the transcript.
    #[serde(default)]
    pub statement: Option<String>,
}

/// The `with` block of `attest_key`. The key comes through `reads:`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AttestKeyParams {
    /// Shown to the operator when the step starts.
    #[serde(default)]
    pub message: Option<String>,
}

/// Parameters for `verify_attestation`. Inputs are supplied through `reads`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct VerifyAttestationParams {
    /// Message shown when the step starts.
    #[serde(default)]
    pub message: Option<String>,
    /// Claims the attestation must satisfy. If omitted, only the chain and key
    /// are checked.
    #[serde(default)]
    pub require: Option<AttestationRequirements>,
}

/// Claims an attestation must satisfy; a required claim the attestation does
/// not make fails the step.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AttestationRequirements {
    /// Accepted authentication policies.
    #[serde(default)]
    #[schemars(length(min = 1))]
    pub authentication: Option<Vec<AccessWhen>>,
    /// Accepted presence policies.
    #[serde(default)]
    #[schemars(length(min = 1))]
    pub presence: Option<Vec<AccessWhen>>,
    /// Device serial number that must match.
    #[serde(default)]
    pub serial: Option<u32>,
}
