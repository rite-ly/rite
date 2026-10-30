//! Params for the `gather_entropy` action.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The `with` block of `gather_entropy`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct GatherEntropyParams {
    /// Instructions shown to the participant for producing the random value.
    /// Without them, the prompt suggests rolling a die.
    #[serde(default)]
    pub instruction: Option<String>,
}
