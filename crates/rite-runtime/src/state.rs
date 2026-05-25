//! Execution state management for ceremonies.
//!
//! This module provides:
//! - [`ExecutionState`]: immutable state that accumulates during execution
//! - [`HandlerContext`]: read-only view for action handlers
//! - [`StepResult`]: what handlers return (outcome + produced artifacts)
//!
//! The design follows an FP accumulator pattern: state is recreated after
//! each step rather than mutated. This eliminates borrow conflicts and
//! makes state flow explicit.
//!
//! # Role resolution
//!
//! At runtime, role references have already been evaluated by the
//! expression system. Handlers receive plain role names (e.g. `"admin"`)
//! and use [`HandlerContext::resolve_role_name`] to get display names.

use std::collections::HashMap;

use rite_model::{ArtifactId, MaterialId, ParamId, RoleId, StepOutcome};

use crate::actions::ArtifactValue;

/// Complete execution state, recreated after each step.
///
/// This struct owns all state that evolves during ceremony execution.
/// Rather than mutating fields, new state is created via
/// [`ExecutionState::with_material`] (for materials loaded up front) and
/// via the executor's internal fold (for step results).
#[derive(Debug)]
pub struct ExecutionState {
    /// Resolved parameters (from ceremony defaults, CLI flags, or env vars).
    pub params: HashMap<ParamId, serde_json::Value>,
    /// Role ID → display name mapping.
    pub roles: HashMap<RoleId, String>,
    /// Material ID → display name mapping (for showing material titles).
    pub materials: HashMap<MaterialId, String>,
    /// Whether this is a dry run.
    pub dry_run: bool,
    /// Artifacts produced by completed steps and loaded materials.
    pub artifacts: HashMap<ArtifactId, ArtifactValue>,
}

fn resolve_role_in(roles: &HashMap<RoleId, String>, role_id: &RoleId) -> String {
    roles
        .get(role_id)
        .cloned()
        .unwrap_or_else(|| role_id.as_str().to_string())
}

impl ExecutionState {
    /// Create initial execution state.
    #[must_use]
    pub fn new(
        params: HashMap<ParamId, serde_json::Value>,
        roles: HashMap<RoleId, String>,
        materials: HashMap<MaterialId, String>,
        dry_run: bool,
    ) -> Self {
        Self {
            params,
            roles,
            materials,
            dry_run,
            artifacts: HashMap::new(),
        }
    }

    /// Create a read-only view for handlers.
    #[must_use]
    pub fn handler_context(&self) -> HandlerContext<'_> {
        HandlerContext {
            dry_run: self.dry_run,
            params: &self.params,
            artifacts: &self.artifacts,
            roles: &self.roles,
            materials: &self.materials,
        }
    }

    /// Add a material artifact.
    #[must_use]
    pub fn with_material(mut self, id: ArtifactId, artifact: ArtifactValue) -> Self {
        self.artifacts.insert(id, artifact);
        self
    }

    /// Resolve a role ID to a display name.
    #[must_use]
    pub fn resolve_role(&self, role_id: &RoleId) -> String {
        resolve_role_in(&self.roles, role_id)
    }
}

/// Read-only view of execution state for handlers.
///
/// Handlers receive this view; they cannot modify state directly. They
/// return a [`StepResult`], which the executor folds into the next state.
#[derive(Debug, Clone, Copy)]
pub struct HandlerContext<'a> {
    /// Whether this is a dry run.
    pub dry_run: bool,
    /// Instance parameters.
    pub params: &'a HashMap<ParamId, serde_json::Value>,
    /// Artifacts produced so far.
    pub artifacts: &'a HashMap<ArtifactId, ArtifactValue>,
    /// Role ID → display name mapping.
    pub roles: &'a HashMap<RoleId, String>,
    /// Material ID → display name mapping (for showing material titles in expressions).
    pub materials: &'a HashMap<MaterialId, String>,
}

impl HandlerContext<'_> {
    /// Resolve a role ID to a display name.
    #[must_use]
    pub fn resolve_role(&self, role_id: &RoleId) -> String {
        resolve_role_in(self.roles, role_id)
    }

    /// Resolve a role name to its display name.
    ///
    /// Takes a plain role name (not reference syntax) after expression
    /// evaluation. Example: `resolve_role_name("admin")` → "Alice (Admin)".
    #[must_use]
    pub fn resolve_role_name(&self, role_name: &str) -> String {
        self.resolve_role(&RoleId::new(role_name))
    }

    /// Get an artifact by ID.
    #[must_use]
    pub fn get_artifact(&self, id: &ArtifactId) -> Option<&ArtifactValue> {
        self.artifacts.get(id)
    }

    /// Resolve a material ID to a display name (title or ID).
    /// Returns `None` if the ID is not a material.
    #[must_use]
    pub fn resolve_material(&self, material_id: &MaterialId) -> Option<&str> {
        self.materials.get(material_id).map(String::as_str)
    }
}

/// Result of executing a step.
///
/// Handlers return this instead of mutating context. The executor uses
/// it to accumulate state.
#[derive(Debug)]
pub struct StepResult {
    /// Step outcome (completed or skipped).
    pub outcome: StepOutcome,
    /// Artifacts produced by this step.
    pub artifacts: Vec<(ArtifactId, ArtifactValue)>,
}

impl StepResult {
    /// Create a completed result with no artifacts.
    pub fn completed(message: impl Into<String>) -> Self {
        Self {
            outcome: StepOutcome::Completed {
                message: message.into(),
            },
            artifacts: Vec::new(),
        }
    }

    /// Create a completed result with one artifact.
    pub fn completed_with_artifact(
        message: impl Into<String>,
        id: ArtifactId,
        value: ArtifactValue,
    ) -> Self {
        Self {
            outcome: StepOutcome::Completed {
                message: message.into(),
            },
            artifacts: vec![(id, value)],
        }
    }

    /// Add an artifact to the result.
    #[must_use]
    pub fn with_artifact(mut self, id: ArtifactId, value: ArtifactValue) -> Self {
        self.artifacts.push((id, value));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handler_context_is_read_only_view() {
        let mut artifacts = HashMap::new();
        artifacts.insert(
            ArtifactId::new("test"),
            ArtifactValue::Bytes(b"value".to_vec()),
        );

        let state = ExecutionState {
            params: HashMap::new(),
            roles: HashMap::new(),
            materials: HashMap::new(),
            dry_run: true,
            artifacts,
        };

        let ctx = state.handler_context();

        assert!(ctx.dry_run);
        assert!(ctx.get_artifact(&ArtifactId::new("test")).is_some());
        assert!(ctx.get_artifact(&ArtifactId::new("missing")).is_none());
    }

    #[test]
    fn step_result_builder_pattern() {
        let result = StepResult::completed("Done")
            .with_artifact(ArtifactId::new("a"), ArtifactValue::Bytes(b"1".to_vec()))
            .with_artifact(ArtifactId::new("b"), ArtifactValue::Bytes(b"2".to_vec()));

        assert_eq!(result.artifacts.len(), 2);
    }
}
