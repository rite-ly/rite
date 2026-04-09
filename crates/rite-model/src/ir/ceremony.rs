//! Resolved ceremony IR types.
//!
//! These types represent a fully resolved ceremony, ready for execution.
//! All references have been validated, execution order computed, and
//! parameter values merged with defaults.
//!
//! Types are named without the `Resolved` prefix used in the `PoC` — they are
//! the ceremony model, not one of two competing representations.

use super::SymbolTable;
use super::ids::{ActId, ArtifactId, MaterialId, OutputId, ParamId, RoleId, SectionId, StepId};
use crate::material::MaterialSource;
use crate::types::{ActionType, DutyType, Metadata, OutputType, ParameterType};
use crate::expression::ExprValue;
use rite_sdk::BackendConfig;
use std::collections::HashMap;

/// A fully resolved ceremony, ready for execution.
///
/// All references have been validated, the execution order has been computed,
/// and parameter values have been merged with external inputs.
#[derive(Debug, Clone)]
pub struct Ceremony {
    /// Ceremony metadata (name, description).
    pub metadata: Metadata,

    /// Resolved roles, keyed by role ID.
    pub roles: SymbolTable<RoleId, Role>,

    /// Resolved acts, keyed by act ID (for script display).
    pub acts: SymbolTable<ActId, Act>,

    /// Resolved sections, keyed by section ID.
    pub sections: SymbolTable<SectionId, Section>,

    /// Resolved parameters with their values, keyed by parameter ID.
    pub parameters: SymbolTable<ParamId, Parameter>,

    /// Resolved materials with their sources, keyed by material ID.
    pub materials: SymbolTable<MaterialId, Material>,

    /// Pre-ceremony conditions (prose-only checklist).
    pub prerequisites: Vec<String>,

    /// Resolved outputs with their destinations, keyed by output ID.
    pub outputs: SymbolTable<OutputId, Output>,

    /// Backend configurations, keyed by backend name.
    pub backends: HashMap<String, BackendConfig>,

    /// Steps in execution order.
    ///
    /// Pre-computed topological order based on sections.
    pub execution_plan: Vec<Step>,

    /// Post-ceremony duties, in declaration order.
    pub post_ceremony: Vec<PostCeremonyDuty>,
}

/// A resolved role.
#[derive(Debug, Clone)]
pub struct Role {
    /// Role identifier.
    pub id: RoleId,

    /// Human-readable name (derived or explicit).
    pub name: String,

    /// Role type: the prefix before `__` (or the whole ID if no `__`).
    ///
    /// E.g. `"witness__1"` → `"witness"`, `"operator"` → `"operator"`.
    pub role_type: String,

    /// The person assigned to this role slot, if any.
    pub person: Option<String>,
}

/// A resolved act (for script display).
#[derive(Debug, Clone)]
pub struct Act {
    /// Act identifier.
    pub id: ActId,

    /// Human-readable name.
    pub name: Option<String>,

    /// Preamble text displayed at the start of the act.
    pub description: Option<String>,
}

/// A resolved section.
#[derive(Debug, Clone)]
pub struct Section {
    /// Section identifier.
    pub id: SectionId,

    /// Reference to the act this section belongs to.
    pub act: Option<ActId>,

    /// Human-readable name.
    pub name: Option<String>,

    /// Section description.
    pub description: Option<String>,

    /// Default role for steps in this section.
    pub default_role: Option<RoleId>,
}

/// A resolved step, ready for execution.
#[derive(Debug, Clone)]
pub struct Step {
    /// Step identifier.
    pub id: StepId,

    /// Display label for this step (e.g., `"1.1"`, `"2.3"`).
    ///
    /// Uses hierarchical numbering: `act.step_within_act`.
    /// When there's only one act, just the step number (e.g., `"1"`, `"2"`).
    pub step_label: String,

    /// Section this step belongs to.
    pub section: SectionId,

    /// Action to perform.
    pub action: ActionType,

    /// Backend to use for this step (if action requires one).
    ///
    /// References a backend declared in the ceremony's backends section.
    pub backend: Option<String>,

    /// Role that performs this step (resolved from step or section default).
    pub role: Option<RoleId>,

    /// Human-confirmed preconditions before this step executes.
    pub preconditions: Vec<String>,

    /// Action-specific parameters with expressions parsed (not yet evaluated).
    ///
    /// The runtime evaluates these to `serde_json::Value` before passing to handlers.
    pub params: ExprValue,

    /// Validated input artifact references (for ordering validation).
    pub inputs: Vec<ArtifactRef>,

    /// Pre-resolved input references for handlers.
    ///
    /// Handlers can access artifact IDs directly without parsing.
    pub typed_inputs: Option<StepInputs>,

    /// Artifact ID this step produces.
    pub produces: Option<ArtifactId>,

    /// Human-readable description for display (may contain interpolated expressions).
    pub description: Option<ExprValue>,

    /// Skip the default pause after step completion.
    ///
    /// When `true`, the executor auto-advances without waiting for user acknowledgment.
    pub auto_advance: bool,
}

/// A resolved parameter with its value.
#[derive(Debug, Clone)]
pub struct Parameter {
    /// Parameter identifier.
    pub id: ParamId,

    /// Declared type.
    pub declared_type: ParameterType,

    /// Resolved value (from CLI/env/prompt or default).
    pub value: serde_json::Value,

    /// Human-readable description.
    pub description: Option<String>,
}

/// What kind of material and its resolved source/identifier.
#[derive(Debug, Clone)]
pub enum MaterialKind {
    /// Digital: loaded from file path. `None` if source not yet provided.
    Digital {
        /// Resolved file source, or `None` if not yet provided.
        source: Option<MaterialSource>,
    },
    /// Physical: optional identifier string for display.
    Physical {
        /// Human-readable identifier (e.g., serial number).
        identifier: Option<String>,
        /// Item count for checklist rendering.
        quantity: Option<u32>,
    },
}

/// A resolved material with its source.
#[derive(Debug, Clone)]
pub struct Material {
    /// Material identifier.
    pub id: MaterialId,

    /// What kind of material and its resolved source/identifier.
    pub kind: MaterialKind,

    /// Optional human-readable title for display (falls back to material ID).
    pub title: Option<String>,

    /// Human-readable description.
    pub description: Option<String>,
}

impl Material {
    /// Get the display name for this material (title or ID).
    pub fn display_name(&self) -> &str {
        self.title.as_deref().unwrap_or(self.id.as_str())
    }

    /// Whether this is a digital material.
    pub fn is_digital(&self) -> bool {
        matches!(self.kind, MaterialKind::Digital { .. })
    }

    /// Whether this is a physical material.
    pub fn is_physical(&self) -> bool {
        matches!(self.kind, MaterialKind::Physical { .. })
    }
}

/// A resolved post-ceremony duty.
#[derive(Debug, Clone)]
pub struct PostCeremonyDuty {
    /// Duty identifier (always present; synthesized as `"duty_01"` etc. if absent in YAML).
    pub id: String,

    /// Type of duty.
    pub duty_type: DutyType,

    /// Role responsible for this duty (resolved from plain role ID string).
    pub role: Option<RoleId>,

    /// Description of this duty (overrides built-in prose for the type).
    pub description: Option<String>,

    /// Checklist sub-items.
    pub items: Vec<String>,

    /// For distribute_* types: who receives.
    pub recipient: Option<String>,

    /// For storage/archive types: where.
    pub location: Option<String>,
}

/// A resolved output declaration.
#[derive(Debug, Clone)]
pub struct Output {
    /// Output identifier.
    pub id: OutputId,

    /// Type of output.
    pub artifact_type: OutputType,

    /// Human-readable description.
    pub description: Option<String>,
}

/// Reference to an artifact (either a material or a produced artifact).
#[derive(Debug, Clone)]
pub enum ArtifactRef {
    /// References a pre-loaded material.
    Material {
        /// Material ID.
        id: MaterialId,
        /// Optional property accessor (e.g., `"public"` from a keypair).
        property: Option<String>,
    },

    /// References an artifact produced by an earlier step.
    Produced {
        /// Artifact ID.
        id: ArtifactId,
        /// Optional property accessor.
        property: Option<String>,
    },
}

impl ArtifactRef {
    /// Get a display name for this reference.
    pub fn display_name(&self) -> String {
        match self {
            ArtifactRef::Material { id, property: None } => id.to_string(),
            ArtifactRef::Material {
                id,
                property: Some(p),
            } => format!("{id}.{p}"),
            ArtifactRef::Produced { id, property: None } => id.to_string(),
            ArtifactRef::Produced {
                id,
                property: Some(p),
            } => format!("{id}.{p}"),
        }
    }

    /// Get the artifact ID from this reference.
    pub fn artifact_id(&self) -> ArtifactId {
        match self {
            ArtifactRef::Material { id, .. } => ArtifactId::new(id.as_str()),
            ArtifactRef::Produced { id, .. } => id.clone(),
        }
    }

    /// Get the property accessor from this reference (if any).
    pub fn property(&self) -> Option<&str> {
        match self {
            ArtifactRef::Material { property, .. } | ArtifactRef::Produced { property, .. } => {
                property.as_deref()
            }
        }
    }
}

/// Pre-resolved input references for a step.
///
/// At resolution time, the resolver parses `${artifact.name}` strings and determines
/// whether they reference materials or produced artifacts. This eliminates runtime
/// string parsing in handlers.
#[derive(Debug, Clone)]
pub enum StepInputs {
    /// Single artifact reference (e.g., `input: "${artifact.keypair}"`)
    Single(ArtifactRef),
    /// Named artifact references (e.g., `input: { key_to_wrap: "...", wrapping_key: "..." }`)
    Named(HashMap<String, ArtifactRef>),
}

impl StepInputs {
    /// Get a single input reference (returns `None` if this is `Named`).
    pub fn as_single(&self) -> Option<&ArtifactRef> {
        match self {
            StepInputs::Single(r) => Some(r),
            StepInputs::Named(_) => None,
        }
    }

    /// Get named input references (returns `None` if this is `Single`).
    pub fn as_named(&self) -> Option<&HashMap<String, ArtifactRef>> {
        match self {
            StepInputs::Single(_) => None,
            StepInputs::Named(m) => Some(m),
        }
    }

    /// Get a named input by key.
    pub fn get(&self, key: &str) -> Option<&ArtifactRef> {
        match self {
            StepInputs::Single(_) => None,
            StepInputs::Named(m) => m.get(key),
        }
    }
}
