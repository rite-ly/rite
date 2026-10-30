//! Params for the `attest` action.

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
