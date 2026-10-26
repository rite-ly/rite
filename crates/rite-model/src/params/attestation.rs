//! Params for the `attest` action.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Params for `attest` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AttestParams {
    /// The attestation statement.
    #[serde(default)]
    pub statement: Option<String>,
}
