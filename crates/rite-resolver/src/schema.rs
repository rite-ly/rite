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
use rite_model::{
    ActionType, BackendConfig, DutyType, FileKind, KeyAlgorithm, KeyFingerprint, ParameterType,
    Sha256Digest,
};
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
///
/// Its `type:` is `physical`, `backend_key`, or the kind of file it is, so
/// the tag is not one name per variant, and the material is read through
/// [`MaterialDeclaration`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "MaterialDeclaration", into = "MaterialDeclaration")]
pub(crate) enum Material {
    /// A file carried into the ceremony.
    File {
        /// What the file holds.
        kind: FileKind,
        /// Optional display title.
        title: Option<String>,
        /// Optional description.
        description: Option<String>,
        /// Default file path for this material (resolved relative to ceremony file).
        path: Option<std::path::PathBuf>,
    },
    /// Physical item participants must bring to the ceremony.
    Physical {
        /// Optional display title.
        title: Option<String>,
        /// Optional description.
        description: Option<String>,
        /// Default human-readable identifier (serial number, label, batch code).
        identifier: Option<String>,
        /// Quantity for checklist rendering.
        quantity: Option<u32>,
    },
    /// A key a backend already holds, provisioned before the ceremony.
    BackendKey {
        /// Optional display title.
        title: Option<String>,
        /// Optional description.
        description: Option<String>,
        /// The backend that holds the key, by its name under `backends:`.
        backend: String,
        /// The reference the backend answers to, such as `piv:9d`.
        id: String,
        /// The algorithm the key must have.
        algorithm: KeyAlgorithm,
        /// The public key the backend must hold, when the ceremony pins it.
        fingerprint: Option<KeyFingerprint>,
    },
}

impl Material {
    /// Get the title of this material (if set).
    pub(crate) fn title(&self) -> Option<&str> {
        match self {
            Material::File { title, .. }
            | Material::Physical { title, .. }
            | Material::BackendKey { title, .. } => title.as_deref(),
        }
    }

    /// Get the description of this material (if set).
    pub(crate) fn description(&self) -> Option<&str> {
        match self {
            Material::File { description, .. }
            | Material::Physical { description, .. }
            | Material::BackendKey { description, .. } => description.as_deref(),
        }
    }

    /// Whether this material is a file.
    pub(crate) fn is_file(&self) -> bool {
        matches!(self, Material::File { .. })
    }

    /// Get the default file path (only meaningful for a file).
    pub(crate) fn path(&self) -> Option<&std::path::Path> {
        match self {
            Material::File { path, .. } => path.as_deref(),
            Material::Physical { .. } | Material::BackendKey { .. } => None,
        }
    }
}

/// A material as written: every field any type takes, sorted into a
/// [`Material`] once the type is known.
///
/// The editor schema already refuses a field the type does not take; the
/// conversion refuses it again for a reader that skipped the schema.
#[derive(Serialize, Deserialize)]
pub(crate) struct MaterialDeclaration {
    #[serde(rename = "type")]
    declared: MaterialType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path: Option<std::path::PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identifier: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "serde_utils::deserialize_opt_u32"
    )]
    quantity: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    algorithm: Option<KeyAlgorithm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fingerprint: Option<KeyFingerprint>,
}

/// A material's `type:`: `physical`, `backend_key`, or the kind of file it
/// is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MaterialType {
    /// An item brought to the ceremony.
    Physical,
    /// A key a backend already holds.
    BackendKey,
    /// A file holding this kind.
    File(FileKind),
}

impl MaterialType {
    /// Every name a material's `type:` takes.
    pub(crate) fn names() -> impl Iterator<Item = &'static str> {
        FileKind::ALL
            .iter()
            .map(|kind| kind.as_str())
            .chain(["physical", "backend_key"])
    }

    fn as_str(self) -> &'static str {
        match self {
            MaterialType::Physical => "physical",
            MaterialType::BackendKey => "backend_key",
            MaterialType::File(kind) => kind.as_str(),
        }
    }
}

/// The rule a material's `type:` follows, naming what replaces `digital`:
/// the editor schema's message and the reader's.
pub(crate) fn material_type_rule() -> String {
    let names: Vec<&str> = MaterialType::names().collect();
    format!(
        "a material's 'type' is 'physical', 'backend_key', or the kind of file it is ({}); a \
         file once declared 'digital' is 'bytes', or the kind it holds",
        names.join(", ")
    )
}

/// An output's `type:` as the editor schema states it: the names inline,
/// so the rule's message is found where the value breaks it.
fn output_type_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let names: Vec<&str> = FileKind::ALL.iter().map(|kind| kind.as_str()).collect();
    schemars::json_schema!({
        "description": "The kind of file the output is.",
        "type": "string",
        "enum": names,
        "x-message": output_type_rule(),
    })
}

/// The rule an output's `type:` follows, naming what replaces the types
/// that went with the kinds.
pub(crate) fn output_type_rule() -> String {
    let names: Vec<&str> = FileKind::ALL.iter().map(|kind| kind.as_str()).collect();
    format!(
        "an output's 'type' is the kind of file it is ({}); an output once declared \
         'document' is 'signature', 'bytes' or 'text'",
        names.join(", ")
    )
}

impl Serialize for MaterialType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for MaterialType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        match name.as_str() {
            "physical" => return Ok(MaterialType::Physical),
            "backend_key" => return Ok(MaterialType::BackendKey),
            _ => {}
        }
        FileKind::ALL
            .iter()
            .copied()
            .find(|kind| kind.as_str() == name)
            .map(MaterialType::File)
            .ok_or_else(|| {
                serde::de::Error::custom(format!("found '{name}': {}", material_type_rule()))
            })
    }
}

impl TryFrom<MaterialDeclaration> for Material {
    type Error = String;

    fn try_from(declared: MaterialDeclaration) -> Result<Self, String> {
        let MaterialDeclaration {
            declared,
            title,
            description,
            path,
            identifier,
            quantity,
            backend,
            id,
            algorithm,
            fingerprint,
        } = declared;
        let names_a_held_key =
            backend.is_some() || id.is_some() || algorithm.is_some() || fingerprint.is_some();
        match declared {
            MaterialType::File(kind) => {
                if identifier.is_some() || quantity.is_some() {
                    return Err(format!(
                        "a '{}' material is a file: 'identifier' and 'quantity' are for a \
                         physical one",
                        kind.as_str()
                    ));
                }
                if names_a_held_key {
                    return Err(format!(
                        "a '{}' material is a file: 'backend', 'id', 'algorithm' and \
                         'fingerprint' are for a 'backend_key' one",
                        kind.as_str()
                    ));
                }
                Ok(Material::File {
                    kind,
                    title,
                    description,
                    path,
                })
            }
            MaterialType::Physical => {
                if path.is_some() {
                    return Err(
                        "a physical material has no 'path': declare a file by its kind".into(),
                    );
                }
                if names_a_held_key {
                    return Err(
                        "a physical material has no 'backend', 'id', 'algorithm' or \
                                'fingerprint': declare a key a backend holds as 'backend_key'"
                            .into(),
                    );
                }
                Ok(Material::Physical {
                    title,
                    description,
                    identifier,
                    quantity,
                })
            }
            MaterialType::BackendKey => {
                if path.is_some() || identifier.is_some() || quantity.is_some() {
                    return Err(
                        "a 'backend_key' material is read from its backend: 'path', \
                                'identifier' and 'quantity' are for a file or a physical one"
                            .into(),
                    );
                }
                let missing: Vec<&str> = [
                    ("backend", backend.is_none()),
                    ("id", id.is_none()),
                    ("algorithm", algorithm.is_none()),
                ]
                .into_iter()
                .filter_map(|(field, absent)| absent.then_some(field))
                .collect();
                match (backend, id, algorithm) {
                    (Some(backend), Some(id), Some(algorithm)) => Ok(Material::BackendKey {
                        title,
                        description,
                        backend,
                        id,
                        algorithm,
                        fingerprint,
                    }),
                    _ => Err(format!(
                        "a 'backend_key' material needs '{}': the backend that holds the key, \
                         the id it answers to, and the algorithm the key must have",
                        missing.join("', '")
                    )),
                }
            }
        }
    }
}

impl From<Material> for MaterialDeclaration {
    fn from(material: Material) -> Self {
        match material {
            Material::File {
                kind,
                title,
                description,
                path,
            } => MaterialDeclaration {
                declared: MaterialType::File(kind),
                title,
                description,
                path,
                identifier: None,
                quantity: None,
                backend: None,
                id: None,
                algorithm: None,
                fingerprint: None,
            },
            Material::Physical {
                title,
                description,
                identifier,
                quantity,
            } => MaterialDeclaration {
                declared: MaterialType::Physical,
                title,
                description,
                path: None,
                identifier,
                quantity,
                backend: None,
                id: None,
                algorithm: None,
                fingerprint: None,
            },
            Material::BackendKey {
                title,
                description,
                backend,
                id,
                algorithm,
                fingerprint,
            } => MaterialDeclaration {
                declared: MaterialType::BackendKey,
                title,
                description,
                path: None,
                identifier: None,
                quantity: None,
                backend: Some(backend),
                id: Some(id),
                algorithm: Some(algorithm),
                fingerprint,
            },
        }
    }
}

/// Something the ceremony produces.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub(crate) struct OutputDeclaration {
    /// The kind of artifact declared as an output.
    #[serde(rename = "type")]
    #[schemars(schema_with = "output_type_schema")]
    pub(crate) artifact_type: FileKind,
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
