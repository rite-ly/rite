//! YAML schema types for ceremony deserialization.
//!
//! These are the AST types that map directly to the ceremony YAML format.
//! They are `pub(crate)` only; the crate's public API produces `rite_model` IR types.
//!
//! After parsing, the resolver transforms these into `rite_model::Ceremony` (IR).
//!
//! The doc comments on these types and their fields are the descriptions in
//! the ceremony schema, which editors show to ceremony authors. Notes for
//! this code's readers go in `//` comments.

use crate::serde_utils;
use indexmap::IndexMap;
use rite_model::{ActionType, BackendConfig, DutyType, OutputType, ParameterType, Sha256Digest};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A Rite ceremony definition.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub(crate) struct Ceremony {
    /// The ceremony definition format version, currently `"0.3"`.
    pub(crate) version: String,
    /// The ceremony's name, shown in the script and the report.
    pub(crate) name: String,
    /// What the ceremony is for, shown in the script and the report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    /// Backend configurations, keyed by name. Steps refer to a backend by name
    /// in `backend`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    #[schemars(schema_with = "crate::document::backends_schema")]
    pub(crate) backends: HashMap<String, BackendConfig>,
    /// Roles taking part in the ceremony, keyed by ID. Steps and sections refer
    /// to a role as `${role.<id>}`.
    pub(crate) roles: IndexMap<String, RoleDefinition>,
    /// Optional groups of sections in the script and report. Acts do not change
    /// step execution order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) acts: Vec<Act>,
    /// Sections, keyed by ID. Steps run in the order the sections and steps are
    /// written.
    pub(crate) sections: IndexMap<String, SectionBody>,
    /// Values supplied when the ceremony runs, keyed by name and available as
    /// `${param.<name>}`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub(crate) parameters: HashMap<String, Parameter>,
    /// Files and physical items needed for the ceremony, keyed by ID. Files are
    /// available as `${artifact.<id>}`; physical items appear in the script.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub(crate) materials: HashMap<String, Material>,
    /// Conditions met before the ceremony starts, printed as a checklist.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) prerequisites: Vec<String>,
    /// Declared outputs, keyed by artifact ID.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub(crate) output: HashMap<String, OutputDeclaration>,
    /// Post-ceremony duties, keyed by ID and printed as a checklist.
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub(crate) after: IndexMap<String, PostCeremonyDutyBody>,
    // Digest of the YAML text this definition was parsed from.
    //
    // Never read from YAML. `lower_ceremony`, the only place a definition is
    // deserialized, overwrites the placeholder with the digest of the text it
    // parsed.
    #[serde(skip, default = "unset_source_digest")]
    pub(crate) source_digest: Sha256Digest,
}

fn unset_source_digest() -> Sha256Digest {
    Sha256Digest::of(b"")
}

/// A role in the ceremony.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub(crate) struct RoleDefinition {
    /// The role's display name. If omitted, it is derived from the role ID.
    //
    // See `derive_role_name`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    /// The person assigned to this role.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) person: Option<String>,
}

/// An act, a group of sections in the script and the report.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub(crate) struct Act {
    /// The act's ID, which a section names under `act`.
    pub(crate) id: String,
    /// The name shown in the script and the report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    /// Shown at the start of the act.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
}

/// A section: steps that run in the order written.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub(crate) struct SectionBody {
    /// The ID of the act that contains this section.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) act: Option<String>,
    /// The name shown in the script and the report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    /// Shown at the start of the section.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    /// The default role for steps in this section, written as `${role.<id>}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) role: Option<String>,
    /// The section's steps, by ID, in the order they run.
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub(crate) steps: IndexMap<String, StepBody>,
}

/// A step: one action, performed by one role.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub(crate) struct StepBody {
    /// What the step does.
    pub(crate) action: ActionType,
    /// The name of a backend declared in `backends`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) backend: Option<String>,
    /// Parameters for the action. Values can be expressions, such as
    /// `${param.subject}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) with: Option<serde_json::Value>,
    /// The role that performs this step, written as `${role.<id>}`. Defaults to
    /// the section's role.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) role: Option<String>,
    /// Conditions a person confirms before the step runs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) preconditions: Vec<String>,
    /// The ID assigned to the artifact produced by this step. Later steps refer
    /// to it as `${artifact.<id>}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) creates: Option<String>,
    /// The inputs the step's action reads, under the names it expects. For
    /// example, `key: ${artifact.root_key}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reads: Option<serde_json::Value>,
    /// What the step does, in the script and on screen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    /// Whether to continue to the next step without pausing.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) silent: bool,
    /// What happens if the step fails. By default, the operator chooses whether
    /// to retry or abort. Use `never` to forbid retries, or `{ attempts: N }`
    /// to set the total number of attempts.
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

/// A value given when the ceremony runs.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub(crate) struct Parameter {
    /// The kind of value this parameter accepts.
    #[serde(rename = "type")]
    pub(crate) param_type: ParameterType,
    /// A description shown when the parameter is requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    /// The value used when none is supplied. If omitted, the parameter is
    /// required.
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

/// Something the ceremony produces.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub(crate) struct OutputDeclaration {
    /// The kind of artifact declared as an output.
    #[serde(rename = "type")]
    pub(crate) artifact_type: OutputType,
    /// A description of the declared output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
}

/// A duty done after the run ends.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub(crate) struct PostCeremonyDutyBody {
    /// The kind of post-ceremony duty.
    #[serde(rename = "type")]
    pub(crate) kind: DutyType,
    /// The ID of the role responsible for this duty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) role: Option<String>,
    /// Instructions for this duty. For `custom`, this field is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    /// Checklist items for this duty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) items: Vec<String>,
    /// The recipient of the distributed items.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recipient: Option<String>,
    /// The location where items are stored or archived.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) location: Option<String>,
}
