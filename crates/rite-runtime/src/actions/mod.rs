//! Action infrastructure for ceremony steps.
//!
//! This module provides the core infrastructure for executing ceremony actions:
//!
//! - [`ActionHandler`] - Core trait for implementing actions
//! - [`ActionRegistry`] - Registry of available action handlers
//! - [`ArtifactValue`] - Runtime representation of produced artifacts
//!
//! For execution state, see [`crate::state`].
//!
//! Action implementations are in the `rite-stdlib` crate.

pub mod display;
mod traits;
mod types;

use std::collections::HashMap;
use std::sync::Arc;

use rite_model::ActionType;

// Re-export public API
pub use traits::{ActionCategory, ActionHandler, ActionMetadata};
pub use types::{ArtifactValue, KeyFormat};

/// Registry mapping action types to handlers.
pub struct ActionRegistry {
    handlers: HashMap<ActionType, Arc<dyn ActionHandler>>,
}

impl ActionRegistry {
    /// Create a new empty action registry.
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register an action handler.
    pub fn register(&mut self, handler: Arc<dyn ActionHandler>) {
        let action_type = handler.metadata().action_type;
        self.handlers.insert(action_type, handler);
    }

    /// Get handler by action type.
    pub fn get(&self, action: &ActionType) -> Option<&Arc<dyn ActionHandler>> {
        self.handlers.get(action)
    }

    /// List all registered action types.
    pub fn action_types(&self) -> impl Iterator<Item = &ActionType> {
        self.handlers.keys()
    }

    /// Return action types used in the execution plan that have no registered handler.
    ///
    /// Results are deduplicated and returned in first-occurrence order.
    pub fn unsupported_actions(&self, steps: &[rite_model::Step]) -> Vec<ActionType> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for step in steps {
            if !self.handlers.contains_key(&step.action) && seen.insert(step.action) {
                result.push(step.action);
            }
        }
        result
    }
}

impl Default for ActionRegistry {
    fn default() -> Self {
        Self::new()
    }
}
