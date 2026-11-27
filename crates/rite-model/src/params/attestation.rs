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

/// The `with` block of `verify_attestation`. The attestation, the key and the
/// roots come through `reads:`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct VerifyAttestationParams {
    /// Shown to the operator when the step starts.
    #[serde(default)]
    pub message: Option<String>,
    /// What the attestation must state; left out, only the chain and the key
    /// are checked.
    #[serde(default)]
    pub require: Option<AttestationRequirements>,
}

/// The claims an attestation must make. Each policy lists the values
/// accepted, since `per_session` and `cached` do not compare. A claim named
/// here that the attestation does not make fails the step.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AttestationRequirements {
    /// When the device asks for the PIN before using the key: the values
    /// accepted, such as `[per_use]`.
    #[serde(default)]
    #[schemars(length(min = 1))]
    pub authentication: Option<Vec<AccessWhen>>,
    /// When the device asks for a touch before using the key: the values
    /// accepted, such as `[per_use, cached]`.
    #[serde(default)]
    #[schemars(length(min = 1))]
    pub presence: Option<Vec<AccessWhen>>,
    /// The serial number of the device that must hold the key.
    #[serde(default)]
    pub serial: Option<u32>,
}
