//! Params for the `gather_entropy` action.

use serde::{Deserialize, Serialize};

/// Params for `gather_entropy` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GatherEntropyParams {
    /// Instruction shown to the participant describing how to produce the
    /// random value. Defaults to a generic dice suggestion; override per
    /// ceremony to mandate a specific method.
    #[serde(default)]
    pub instruction: Option<String>,
}
