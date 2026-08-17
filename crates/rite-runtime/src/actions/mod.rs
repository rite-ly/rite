//! Action support types used by handlers and the executor.
//!
//! The [`Action`](crate::Action) trait itself lives in [`crate::runner`];
//! this module hosts the supporting data types ([`ActionCategory`],
//! [`ActionMetadata`], [`ArtifactValue`]).

mod types;

use rite_model::ActionType;

pub use types::ArtifactValue;

/// Category of an action, determines how the frontend presents it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionCategory {
    /// Requires human verification or confirmation.
    Verification,
    /// Cryptographic operation against a backend.
    Crypto,
    /// Formal attestation with audit binding.
    Attestation,
}

impl std::fmt::Display for ActionCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionCategory::Verification => write!(f, "verification"),
            ActionCategory::Crypto => write!(f, "crypto"),
            ActionCategory::Attestation => write!(f, "attestation"),
        }
    }
}

/// Metadata describing an action, used for validation and presentation.
#[derive(Debug, Clone)]
pub struct ActionMetadata {
    /// Action type (used in YAML and the registry).
    pub action_type: ActionType,
    /// Short human-readable description.
    pub description: &'static str,
    /// Action category.
    pub category: ActionCategory,
}
