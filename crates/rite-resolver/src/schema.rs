//! YAML schema types for ceremony deserialization.
//!
//! These are the AST types that map directly to the ceremony YAML format.
//! They are `pub(crate)` only; the crate's public API produces `rite_model` IR types.
//!
//! After parsing, the resolver transforms these into `rite_model::Ceremony` (IR).

use crate::serde_utils;
use indexmap::IndexMap;
use rite_model::{ActionType, BackendConfig, DutyType, OutputType, ParameterType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A complete ceremony definition as parsed from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Ceremony {
    /// Schema version (e.g., `"0.2"`).
    pub(crate) version: String,
    /// Ceremony name.
    pub(crate) name: String,
    /// Optional ceremony description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    /// Backend declarations (name → config).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub(crate) backends: HashMap<String, BackendConfig>,
    /// Roles participating in the ceremony (role ID → definition).
    pub(crate) roles: IndexMap<String, RoleDefinition>,
    /// Acts grouping sections (optional, for script organization).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) acts: Vec<Act>,
    /// Sections containing steps: determines execution order (section ID → body).
    pub(crate) sections: IndexMap<String, SectionBody>,
    /// Parameters that can be provided at ceremony instantiation.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub(crate) parameters: HashMap<String, Parameter>,
    /// Materials required before ceremony starts.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub(crate) materials: HashMap<String, Material>,
    /// Pre-ceremony conditions (prose-only checklist).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) prerequisites: Vec<String>,
    /// Output declarations for ceremony products.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub(crate) output: HashMap<String, OutputDeclaration>,
    /// Duties to be completed after the ceremony runtime stops (duty ID → body).
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub(crate) after: IndexMap<String, PostCeremonyDutyBody>,
}

/// A role definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RoleDefinition {
    /// Human-readable label for the role type.
    /// If absent, derived from the role ID via `derive_role_name`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    /// The person assigned to this role slot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) person: Option<String>,
}

/// A high-level act grouping sections for display purposes.
/// Acts are metadata only; they do not affect execution order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Act {
    /// Unique identifier for this act.
    pub(crate) id: String,
    /// Human-readable name (for scripts).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    /// Preamble text displayed at the start of the act.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
}

/// Body of a section (the section ID is the map key in the ceremony YAML).
///
/// Sections determine execution order: steps execute in section declaration order,
/// and within each section in step declaration order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SectionBody {
    /// Reference to the act this section belongs to (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) act: Option<String>,
    /// Human-readable name (for scripts).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    /// Longer description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    /// Default role for steps in this section.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) role: Option<String>,
    /// Steps in this section (step ID → body). Execution order follows declaration order.
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub(crate) steps: IndexMap<String, StepBody>,
}

/// Body of a step (the step ID is the map key in its parent section).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StepBody {
    /// Action to perform.
    pub(crate) action: ActionType,
    /// Backend to use for this step (if action requires one).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) backend: Option<String>,
    /// Action-specific parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) with: Option<serde_json::Value>,
    /// Role that performs this step (overrides section default).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) role: Option<String>,
    /// Human-confirmed preconditions before this step executes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) preconditions: Vec<String>,
    /// Artifact ID this step produces.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) creates: Option<String>,
    /// Input artifact(s) for this step: can be a string or structured object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reads: Option<serde_json::Value>,
    /// Human-readable description for paper scripts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    /// Skip the default pause after step completion.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) silent: bool,
    /// How a transient failure of this step is treated. Absent means the
    /// default (prompt the operator to retry or abort).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) retry: Option<RetrySpec>,
}

/// DSL `retry:` value: either the bare keyword `never` or a `{ attempts: N }`
/// map. Both YAML shapes parse under one key.
///
/// Deserialized with a hand-written visitor rather than `#[serde(untagged)]`
/// because `serde_yaml` cannot deserialize untagged struct variants (it fails
/// the map form). The visitor dispatches on the YAML node kind: a scalar is the
/// keyword form, a mapping is the `attempts` form.
#[derive(Debug, Clone)]
pub(crate) enum RetrySpec {
    /// `retry: never`
    Never,
    /// `retry: { attempts: N }`
    Attempts {
        /// Hard cap on total attempts.
        attempts: u32,
    },
}

impl Serialize for RetrySpec {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            RetrySpec::Never => serializer.serialize_str("never"),
            RetrySpec::Attempts { attempts } => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("attempts", attempts)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for RetrySpec {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RetryVisitor;

        impl<'de> serde::de::Visitor<'de> for RetryVisitor {
            type Value = RetrySpec;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("\"never\" or a mapping with an `attempts` field")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<RetrySpec, E> {
                match value {
                    "never" => Ok(RetrySpec::Never),
                    other => Err(E::custom(format!(
                        "unknown retry keyword '{other}', expected 'never' or {{ attempts: N }}"
                    ))),
                }
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<RetrySpec, A::Error> {
                let mut attempts: Option<u32> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "attempts" => {
                            if attempts.is_some() {
                                return Err(serde::de::Error::duplicate_field("attempts"));
                            }
                            attempts = Some(map.next_value()?);
                        }
                        other => return Err(serde::de::Error::unknown_field(other, &["attempts"])),
                    }
                }
                let attempts =
                    attempts.ok_or_else(|| serde::de::Error::missing_field("attempts"))?;
                Ok(RetrySpec::Attempts { attempts })
            }
        }

        deserializer.deserialize_any(RetryVisitor)
    }
}

/// A parameter that can be provided when instantiating a ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Parameter {
    /// Type of the parameter.
    #[serde(rename = "type")]
    pub(crate) param_type: ParameterType,
    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    /// Default value if not provided. When absent, the parameter is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) default: Option<serde_json::Value>,
}

/// A material required before the ceremony starts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Material {
    /// Digital content (cryptographic artifacts, certificates, etc.).
    Digital {
        /// Optional display title.
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        /// Optional description.
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        /// Default file path for this material (resolved relative to ceremony file).
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<std::path::PathBuf>,
    },
    /// Physical item participants must bring to the ceremony.
    Physical {
        /// Optional display title.
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        /// Optional description.
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        /// Default human-readable identifier (serial number, label, batch code).
        #[serde(skip_serializing_if = "Option::is_none")]
        identifier: Option<String>,
        /// Quantity for checklist rendering.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "serde_utils::deserialize_opt_u32"
        )]
        quantity: Option<u32>,
    },
}

impl Material {
    /// Get the title of this material (if set).
    pub(crate) fn title(&self) -> Option<&str> {
        match self {
            Material::Digital { title, .. } | Material::Physical { title, .. } => title.as_deref(),
        }
    }

    /// Get the description of this material (if set).
    pub(crate) fn description(&self) -> Option<&str> {
        match self {
            Material::Digital { description, .. } | Material::Physical { description, .. } => {
                description.as_deref()
            }
        }
    }

    /// Whether this is a digital material.
    pub(crate) fn is_digital(&self) -> bool {
        matches!(self, Material::Digital { .. })
    }

    /// Get the default file path (only meaningful for digital materials).
    pub(crate) fn path(&self) -> Option<&std::path::Path> {
        match self {
            Material::Digital { path, .. } => path.as_deref(),
            Material::Physical { .. } => None,
        }
    }
}

/// Declaration of a ceremony output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OutputDeclaration {
    /// Type of output.
    #[serde(rename = "type")]
    pub(crate) artifact_type: OutputType,
    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
}

/// Body of a post-ceremony duty (the duty ID is the map key in the `after:` block).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PostCeremonyDutyBody {
    /// Type of duty.
    #[serde(rename = "type")]
    pub(crate) kind: DutyType,
    /// Role responsible for this duty (plain role ID, e.g. `"ceremony_admin"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) role: Option<String>,
    /// Description of this duty. Overrides built-in prose for the type.
    /// Required when `kind` is `custom`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    /// Checklist sub-items.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) items: Vec<String>,
    /// For `distribute_*` types: who receives.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recipient: Option<String>,
    /// For storage/archive types: where.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) location: Option<String>,
}
