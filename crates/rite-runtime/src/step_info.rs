//! Step information for action handlers.
//!
//! This module provides [`StepInfo`], a lightweight struct containing
//! exactly what action handlers need from a step. This replaces the
//! AST `Step` type in the handler interface, enabling cleaner separation
//! between resolution and execution.

use rite_model::{ArtifactId, RoleId, StepId, StepInputs};

/// Information about a step needed by action handlers.
///
/// This is a subset of `Step` containing only what handlers need:
/// - Step ID (for error messages)
/// - Role (for attestation)
/// - Backend (for cryptographic operations)
/// - Produces (for artifact storage)
/// - Typed inputs (pre-resolved artifact references)
///
/// Constructed from `Step` by the executor before calling handlers.
#[derive(Debug, Clone)]
pub struct StepInfo {
    /// Step identifier (for error messages).
    pub id: StepId,

    /// Role that performs this step (for attestation).
    pub role: Option<RoleId>,

    /// Backend to use for this step (if action requires one).
    pub backend: Option<String>,

    /// Artifact ID this step produces (if any).
    pub produces: Option<ArtifactId>,

    /// Pre-resolved input artifact references.
    /// Handlers can access artifact IDs directly without parsing `${...}` strings.
    pub typed_inputs: Option<StepInputs>,
}

impl StepInfo {
    /// Create a new `StepInfo` from `Step` fields.
    pub fn new(
        id: StepId,
        role: Option<RoleId>,
        backend: Option<String>,
        produces: Option<ArtifactId>,
        typed_inputs: Option<StepInputs>,
    ) -> Self {
        Self {
            id,
            role,
            backend,
            produces,
            typed_inputs,
        }
    }

    /// Get the step ID as a string slice.
    pub fn id_str(&self) -> &str {
        self.id.as_str()
    }

    /// Get the role as a string reference (for display).
    pub fn role_str(&self) -> Option<&str> {
        self.role.as_ref().map(rite_model::RoleId::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rite_model::ArtifactRef;

    #[test]
    fn step_info_basic() {
        // Create typed inputs instead of raw JSON
        let typed_inputs = Some(StepInputs::Single(ArtifactRef::Produced {
            id: ArtifactId::new("foo"),
            property: None,
        }));

        let info = StepInfo::new(
            StepId::new("test_step"),
            Some(RoleId::new("operator")),
            Some("software".to_string()),
            Some(ArtifactId::new("output")),
            typed_inputs,
        );

        assert_eq!(info.id_str(), "test_step");
        assert_eq!(info.role_str(), Some("operator"));
        assert_eq!(info.backend, Some("software".to_string()));
        assert!(info.produces.is_some());
        assert!(info.typed_inputs.is_some());
    }
}
