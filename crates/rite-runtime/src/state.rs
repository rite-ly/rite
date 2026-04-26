//! Execution state management for ceremonies.
//!
//! This module provides:
//! - [`ExecutionState`]: immutable state that accumulates during execution
//! - [`HandlerContext`]: read-only view for action handlers
//! - [`StepResult`]: what handlers return (outcome + produced artifacts)
//!
//! The design follows an FP accumulator pattern: state is recreated after each step
//! rather than mutated. This eliminates borrow conflicts and makes state flow explicit.
//!
//! # Role Resolution
//!
//! At runtime, role references have already been evaluated by the expression
//! system. Handlers receive plain role names (e.g., "admin") and use
//! `HandlerContext::resolve_role_name()` to get display names.
//!
//! The expression evaluation happens in `expressions.rs`, which converts
//! `${role.admin}` → `"admin"` during step parameter evaluation.

use crate::actions::ArtifactValue;
use crate::executor::StepOutcome;
use crate::transcript::ExecutionEvent;
use rite_model::{ArtifactId, MaterialId, ParamId, RoleId};
use std::collections::HashMap;

/// Complete execution state, recreated after each step.
///
/// This struct owns all state that evolves during ceremony execution.
/// Rather than mutating fields, new state is created via `with_step_result()`.
#[derive(Debug)]
pub struct ExecutionState {
    // Immutable for entire ceremony
    /// Resolved parameters (from ceremony defaults, CLI flags, or env vars)
    pub params: HashMap<ParamId, serde_json::Value>,
    /// Role ID to display name mapping
    pub roles: HashMap<RoleId, String>,
    /// Material ID to display name mapping (for showing material titles)
    pub materials: HashMap<MaterialId, String>,
    /// Whether this is a dry run
    pub dry_run: bool,

    // Accumulates during execution
    /// Artifacts produced by steps
    pub artifacts: HashMap<ArtifactId, ArtifactValue>,
    /// Execution events for transcript
    pub events: Vec<ExecutionEvent>,
}

/// Resolve a role ID to a display name, falling back to the raw ID string.
fn resolve_role_in(roles: &HashMap<RoleId, String>, role_id: &RoleId) -> String {
    roles
        .get(role_id)
        .cloned()
        .unwrap_or_else(|| role_id.as_str().to_string())
}

impl ExecutionState {
    /// Create initial execution state.
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
            events: Vec::new(),
        }
    }

    /// Create a read-only view for handlers.
    pub fn handler_context(&self) -> HandlerContext<'_> {
        HandlerContext {
            dry_run: self.dry_run,
            params: &self.params,
            artifacts: &self.artifacts,
            roles: &self.roles,
            materials: &self.materials,
        }
    }

    /// Create new state with accumulated step result.
    ///
    /// This is the accumulator pattern: instead of mutating, we create new state.
    #[must_use]
    pub fn with_step_result(mut self, result: StepResult, event: ExecutionEvent) -> Self {
        // Accumulate artifacts
        for (id, value) in result.artifacts {
            self.artifacts.insert(id, value);
        }

        // Record event
        self.events.push(event);

        self
    }

    /// Add a material artifact.
    #[must_use]
    pub fn with_material(mut self, id: ArtifactId, artifact: ArtifactValue) -> Self {
        self.artifacts.insert(id, artifact);
        self
    }

    /// Resolve a role ID to a display name.
    pub fn resolve_role(&self, role_id: &RoleId) -> String {
        resolve_role_in(&self.roles, role_id)
    }
}

/// Read-only view of execution state for handlers.
///
/// This is what action handlers receive. It provides access to:
/// - Current artifacts (to read inputs)
/// - Parameters (for interpolation)
/// - Roles (for display)
/// - Dry run flag
///
/// Handlers cannot modify state directly; they return [`StepResult`] instead.
#[derive(Debug, Clone, Copy)]
pub struct HandlerContext<'a> {
    /// Whether this is a dry run
    pub dry_run: bool,
    /// Instance parameters
    pub params: &'a HashMap<ParamId, serde_json::Value>,
    /// Artifacts produced so far
    pub artifacts: &'a HashMap<ArtifactId, ArtifactValue>,
    /// Role ID to display name mapping
    pub roles: &'a HashMap<RoleId, String>,
    /// Material ID to display name mapping (for showing material titles in expressions)
    pub materials: &'a HashMap<MaterialId, String>,
}

impl HandlerContext<'_> {
    /// Resolve a role ID to a display name.
    pub fn resolve_role(&self, role_id: &RoleId) -> String {
        resolve_role_in(self.roles, role_id)
    }

    /// Resolve a role name to its display name.
    ///
    /// Takes a plain role name (not reference syntax) after expression evaluation.
    /// Example: `resolve_role_name("admin")` → "Alice (Admin)"
    pub fn resolve_role_name(&self, role_name: &str) -> String {
        self.resolve_role(&RoleId::new(role_name))
    }

    /// Get an artifact by ID.
    pub fn get_artifact(&self, id: &ArtifactId) -> Option<&ArtifactValue> {
        self.artifacts.get(id)
    }

    /// Resolve a material ID to a display name (title or ID).
    /// Returns None if not a material.
    pub fn resolve_material(&self, material_id: &MaterialId) -> Option<&str> {
        self.materials.get(material_id).map(String::as_str)
    }
}

/// Result of executing a step.
///
/// Handlers return this instead of mutating context.
/// The executor uses this to accumulate state.
#[derive(Debug)]
pub struct StepResult {
    /// Step outcome (completed or skipped)
    pub outcome: StepOutcome,
    /// Artifacts produced by this step
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

    /// Create a skipped result.
    pub fn skipped(reason: impl Into<String>) -> Self {
        Self {
            outcome: StepOutcome::Skipped {
                reason: reason.into(),
            },
            artifacts: Vec::new(),
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
    fn execution_state_accumulates_artifacts() {
        let state = ExecutionState::new(HashMap::new(), HashMap::new(), HashMap::new(), false);

        // Simulate step producing an artifact
        let result = StepResult::completed_with_artifact(
            "Generated keypair",
            ArtifactId::new("keypair"),
            ArtifactValue::Bytes(b"test".to_vec()),
        );

        let event = ExecutionEvent {
            step_id: "step1".into(),
            action: rite_model::ActionType::GenerateKeypair,
            role: None,
            started_at: chrono::Utc::now(),
            completed_at: chrono::Utc::now(),
            outcome: crate::transcript::step_outcome_to_event_outcome(&result.outcome),
            evidence: crate::transcript::StepEvidence::new(),
        };

        let state = state.with_step_result(result, event);

        assert!(state.artifacts.contains_key(&ArtifactId::new("keypair")));
        assert_eq!(state.events.len(), 1);
    }

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
            events: Vec::new(),
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
