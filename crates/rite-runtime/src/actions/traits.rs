//! Action handler traits and metadata.

use crate::executor::ExecutionError;
use crate::state::{HandlerContext, StepResult};
use crate::step_info::StepInfo;
use crate::step_ui::StepUI;
use crate::transcript::StepEvidence;
use rite_model::ActionType;
use rite_sdk::Backend;

/// Category of action - determines UI presentation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionCategory {
    /// Requires human verification/confirmation
    Verification,
    /// Cryptographic operations
    Crypto,
    /// Formal attestations with audit binding
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

/// Metadata about an action, used for validation and UI.
#[derive(Debug, Clone)]
pub struct ActionMetadata {
    /// Action type (used in YAML and registry)
    pub action_type: ActionType,
    /// Human-readable description
    pub description: &'static str,
    /// Action category
    pub category: ActionCategory,
}

/// The core trait all action handlers must implement.
pub trait ActionHandler: Send + Sync {
    /// Returns metadata about this action.
    fn metadata(&self) -> ActionMetadata;

    /// Apply defaults to params based on step context.
    /// Called before validation.
    fn apply_defaults(&self, _params: &mut serde_json::Value, _step: &StepInfo) {
        // Default: no-op
    }

    /// Execute the action.
    ///
    /// Handlers receive an immutable context and return a tuple of:
    /// - [`StepResult`] containing the outcome and any produced artifacts
    /// - [`StepEvidence`] containing evidence for the transcript
    ///
    /// This follows the FP accumulator pattern. Evidence is generated during execution
    /// so that actions can use the same local variables (like timestamps) in both
    /// execution logic and evidence recording.
    ///
    /// The `backend` parameter provides access to the cryptographic backend for this
    /// step (if one is specified). Actions that need backend operations (key generation,
    /// signing, etc.) should use this parameter. The executor resolves the backend by
    /// name before calling the handler.
    fn execute(
        &self,
        step: &StepInfo,
        ctx: &HandlerContext,
        params: &serde_json::Value,
        ui: &mut dyn StepUI,
        backend: Option<&mut dyn Backend>,
    ) -> Result<(StepResult, StepEvidence), ExecutionError>;
}
