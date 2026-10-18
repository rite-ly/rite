//! Params for the `attest` action.

use serde::{Deserialize, Serialize};

/// Params for `attest` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttestParams {
    /// The attestation statement.
    #[serde(default)]
    pub statement: Option<String>,
}
