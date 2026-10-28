//! The JSON Schema of a whole ceremony definition, and its check.
//!
//! The schema is generated from the types the definition is read into, so
//! that every key the reader would drop is refused instead. Each step adds
//! what its action asks of it: a `backend:` where the action needs one, and
//! the `reads:` inputs its [`ReadsContract`] names. `with:` is left open here,
//! since each action's block is checked on its own, where a value still
//! carrying an expression is left to run time.
//!
//! A field the reader takes as text accepts any scalar, as YAML writes
//! `version: 0.3` or `name: 2026` without quotes and the reader still takes
//! them as text.
//!
//! The same schema, with each `with:` block held to its action's schema, is
//! published for editors and other tools: see [`editor_schema`].

use std::collections::HashMap;
use std::sync::OnceLock;

use rite_model::validate::{Check, Pointer, SchemaError};
use rite_model::{ActionType, BackendUsage, ReadsContract};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde_json::{Value, json};

use crate::schema::{Ceremony, Material, RetrySpec};

/// The check of a whole definition, compiled on first use and kept for the
/// process.
pub(crate) fn ceremony_check() -> Result<&'static Check, SchemaError> {
    static CHECK: OnceLock<Result<Check, SchemaError>> = OnceLock::new();
    CHECK
        .get_or_init(|| Check::new(ceremony_schema()))
        .as_ref()
        .map_err(Clone::clone)
}

/// Where each release publishes [`editor_schema`].
pub const CEREMONY_SCHEMA: &str = concat!(
    "https://ritely.io/schemas/",
    env!("CARGO_PKG_VERSION"),
    "/ceremony.schema.json"
);

/// The schema of a ceremony definition, for editors and other tools.
///
/// The schema the resolver checks a definition against, with each step's
/// `with:` block held to its action's schema as well. Any value there may be
/// an expression instead, a string holding `${`, since its value is known
/// only when the step runs. The resolver checks more than the schema says:
/// that references resolve, that an artifact is produced before it is read,
/// and the rules over several `with:` values.
///
/// It carries no descriptions yet: the types' own documentation is written
/// for this code's readers, not for a ceremony's authors. Each `x-message`
/// is also given as `errorMessage`, and as `patternErrorMessage` beside a
/// pattern, which editors built on VS Code's schema support show in place
/// of their own words.
#[must_use]
pub fn editor_schema() -> Schema {
    let mut definitions = serde_json::Map::new();
    let mut with: HashMap<ActionType, Value> = HashMap::new();
    for &action in ActionType::ALL {
        let mut schema = rite_model::params::with_schema(action).to_value();
        let shared = schema.as_object_mut().and_then(|o| o.remove("$defs"));
        if let Some(Value::Object(shared)) = shared {
            for (name, mut definition) in shared {
                without_descriptions(&mut definition);
                accept_expressions(&mut definition);
                definitions.entry(name).or_insert(definition);
            }
        }
        without_descriptions(&mut schema);
        accept_expressions(&mut schema);
        with.insert(action, schema);
    }
    definitions.insert(
        "Expression".to_string(),
        json!({
            "description": "A value given by an expression, known when the step runs.",
            "type": "string",
            "pattern": "\\$\\{",
        }),
    );
    let mut generated = build(|action| with.remove(&action));
    without_descriptions(&mut generated);
    let Value::Object(generated) = generated else {
        return Schema::default();
    };
    let mut schema = serde_json::Map::new();
    schema.insert(
        "$schema".to_string(),
        json!("https://json-schema.org/draft/2020-12/schema"),
    );
    schema.insert("$id".to_string(), json!(CEREMONY_SCHEMA));
    schema.insert("title".to_string(), json!("Rite ceremony definition"));
    for (key, value) in generated {
        if key == "title" {
            continue;
        }
        if key == "$defs"
            && let Value::Object(mut own) = value
        {
            for (name, definition) in std::mem::take(&mut definitions) {
                own.entry(name).or_insert(definition);
            }
            schema.insert(key, Value::Object(own));
        } else {
            schema.insert(key, value);
        }
    }
    schema.values_mut().for_each(editor_messages);
    Schema::from(schema)
}

/// Give each `x-message` in `schema` under the names editors read.
fn editor_messages(schema: &mut Value) {
    match schema {
        Value::Object(object) => {
            if let Some(message) = object.get("x-message").cloned() {
                if object.contains_key("pattern") {
                    object.insert("patternErrorMessage".to_string(), message.clone());
                }
                object.insert("errorMessage".to_string(), message);
            }
            object.values_mut().for_each(editor_messages);
        }
        Value::Array(items) => items.iter_mut().for_each(editor_messages),
        _ => {}
    }
}

/// The schema of a whole definition, as the resolver checks it.
pub(crate) fn ceremony_schema() -> Value {
    build(|_| None)
}

/// The schema of a whole definition, where `with` gives the schema of each
/// action's `with:` block, or none to leave it open.
fn build(mut with: impl FnMut(ActionType) -> Option<Value>) -> Value {
    let mut schema = rite_model::params::generator()
        .root_schema_for::<Ceremony>()
        .to_value();
    if let Value::Object(object) = &mut schema {
        object.remove("$schema");
    }
    as_text(&mut schema);
    if let Some(Value::Object(step)) = schema.pointer_mut("/$defs/StepBody") {
        let rules: Vec<Value> = ActionType::ALL
            .iter()
            .filter_map(|&action| {
                let mut rules = step_rules(action);
                if let Some(with) = with(action) {
                    rules.push(json!({ "properties": { "with": with } }));
                }
                (!rules.is_empty()).then(|| {
                    json!({
                        "if": {
                            "properties": { "action": { "const": action.to_string() } },
                            "required": ["action"],
                        },
                        "then": { "allOf": rules },
                    })
                })
            })
            .collect();
        step.insert("allOf".to_string(), Value::Array(rules));
    }
    schema
}

/// The definition as the check reads it: an absent or empty `reads:` or
/// `with:` is an empty map, so an input the action requires is reported by
/// name.
pub(crate) fn normalize(document: &mut Value) {
    let steps = document
        .get_mut("sections")
        .and_then(Value::as_object_mut)
        .into_iter()
        .flat_map(|sections| sections.values_mut())
        .filter_map(|section| section.get_mut("steps").and_then(Value::as_object_mut))
        .flat_map(|steps| steps.values_mut())
        .filter_map(Value::as_object_mut);
    for step in steps {
        for key in ["reads", "with"] {
            if step.get(key).is_none_or(Value::is_null) {
                step.insert(key.to_string(), json!({}));
            }
        }
    }
}

/// The part of the definition `at` is in, as a message names it, and where
/// `at` is inside that part.
///
/// A step, section, role, parameter, material, output, backend or duty is
/// named by its id. Anything else is placed in the definition itself, named
/// by the empty string.
pub(crate) fn place(at: &Pointer) -> (String, Pointer) {
    let segments = at.segments();
    let rest = |from: usize| {
        segments
            .get(from..)
            .unwrap_or_default()
            .iter()
            .fold(Pointer::root(), |pointer, segment| pointer.join(segment))
    };
    match segments {
        [sections, _, steps, step, ..] if sections == "sections" && steps == "steps" => {
            (format!("step '{step}'"), rest(4))
        }
        [collection, id, ..] => {
            let kind = match collection.as_str() {
                "sections" => "section",
                "roles" => "role",
                "parameters" => "parameter",
                "materials" => "material",
                "output" => "output",
                "backends" => "backend",
                "after" => "duty",
                _ => return (String::new(), at.clone()),
            };
            (format!("{kind} '{id}'"), rest(2))
        }
        _ => (String::new(), at.clone()),
    }
}

/// What a step of `action` must hold beside its own fields.
fn step_rules(action: ActionType) -> Vec<Value> {
    let mut rules = Vec::new();
    if action.backend_usage() == BackendUsage::Required {
        rules.push(json!({
            "required": ["backend"],
            "x-message": format!("action '{action}' requires a backend; add a 'backend:' field"),
        }));
    }
    let contract = action.reads_contract();
    if !contract.is_empty() {
        rules.push(json!({
            "required": ["reads"],
            "properties": { "reads": reads_schema(&contract) },
        }));
    }
    for &(field, input) in contract.with_field_requires {
        rules.push(json!({
            "if": {
                "properties": { "with": { "type": "object", "required": [field] } },
                "required": ["with"],
            },
            "then": {
                "properties": {
                    "reads": {
                        "required": [input],
                        "x-message": format!(
                            "'with.{field}' applies only when '{action}' reads '{input}', \
                             which this step does not"
                        ),
                    },
                },
            },
        }));
    }
    rules
}

/// The schema of a `reads:` map under `contract`: the inputs it requires and
/// accepts, one reference each or a list where the action takes a list, and
/// exactly one input of each group of alternatives.
fn reads_schema(contract: &ReadsContract) -> Value {
    let one = json!({ "type": "string" });
    let mut properties = serde_json::Map::new();
    let single = contract
        .required
        .iter()
        .chain(
            contract
                .exactly_one_of
                .iter()
                .flat_map(|group| group.iter()),
        )
        .chain(contract.optional);
    for name in single {
        properties.insert((*name).to_string(), one.clone());
    }
    for list in contract.lists {
        properties.insert(
            list.name.to_string(),
            json!({ "type": "array", "items": one, "minItems": list.at_least }),
        );
    }
    let required: Vec<&str> = contract
        .required
        .iter()
        .copied()
        .chain(contract.lists.iter().map(|list| list.name))
        .collect();
    let alternatives: Vec<Value> = contract
        .exactly_one_of
        .iter()
        .map(|group| {
            let named = group
                .iter()
                .map(|name| format!("'{name}'"))
                .collect::<Vec<_>>()
                .join(", ");
            json!({
                "oneOf": group.iter().map(|name| json!({ "required": [name] })).collect::<Vec<_>>(),
                "x-message": format!("'reads' must name exactly one of {named}"),
            })
        })
        .collect();
    let mut schema = json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false,
    });
    if !alternatives.is_empty()
        && let Value::Object(object) = &mut schema
    {
        object.insert("allOf".to_string(), Value::Array(alternatives));
    }
    schema
}

/// `schema` with no `description` keyword. A property or a definition of
/// that name is kept.
fn without_descriptions(schema: &mut Value) {
    match schema {
        Value::Object(object) => {
            object.remove("description");
            for (key, child) in object.iter_mut() {
                match (key.as_str(), child) {
                    ("properties" | "$defs", Value::Object(named)) => {
                        named.values_mut().for_each(without_descriptions);
                    }
                    (_, child) => without_descriptions(child),
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(without_descriptions),
        _ => {}
    }
}

/// Let `schema`, and every value it holds, be an expression instead, as the
/// resolver leaves any value carrying one to run time: a single value, a
/// list, a map, or the whole block.
///
/// A rule that only refers to a definition is left as it is, since the
/// definition takes an expression itself. So is a condition: an expression
/// is not known to meet it.
fn accept_expressions(schema: &mut Value) {
    within(schema);
    let Value::Object(object) = schema else {
        return;
    };
    if object.is_empty() || (object.len() == 1 && object.contains_key("$ref")) {
        return;
    }
    let rule = std::mem::take(object);
    object.insert(
        "anyOf".to_string(),
        json!([Value::Object(rule), { "$ref": "#/$defs/Expression" }]),
    );
}

/// Let every value `schema` holds be an expression. The rules `schema`
/// combines are about the same value, so they are reached but not changed.
fn within(schema: &mut Value) {
    let Value::Object(object) = schema else {
        return;
    };
    for (key, child) in object.iter_mut() {
        match (key.as_str(), child) {
            ("properties", Value::Object(properties)) => {
                properties.values_mut().for_each(accept_expressions);
            }
            ("items" | "additionalProperties", value) => accept_expressions(value),
            ("allOf" | "oneOf", Value::Array(rules)) => rules.iter_mut().for_each(within),
            ("then", rule) => within(rule),
            _ => {}
        }
    }
}

/// Make every plain text field accept any scalar: one with no rule on its
/// value beyond being a string.
fn as_text(schema: &mut Value) {
    match schema {
        Value::Object(object) => {
            let plain = object.get("type") == Some(&json!("string"))
                && !["enum", "const", "pattern"]
                    .iter()
                    .any(|keyword| object.contains_key(*keyword));
            if plain {
                object.insert("type".to_string(), json!(["string", "number", "boolean"]));
            }
            for child in object.values_mut() {
                as_text(child);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(as_text),
        _ => {}
    }
}

/// `backends:`: each entry names its provider, and the rest of it is the
/// provider's own configuration, read by the backend.
pub(crate) fn backends_schema(_: &mut SchemaGenerator) -> Schema {
    json_schema!({
        "type": "object",
        "additionalProperties": {
            "type": "object",
            "properties": { "provider": { "type": "string" } },
            "required": ["provider"],
        },
    })
}

impl JsonSchema for RetrySpec {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "RetrySpec".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "oneOf": [
                { "const": "never" },
                {
                    "type": "object",
                    "properties": {
                        "attempts": { "type": "integer", "minimum": 0, "maximum": u32::MAX },
                    },
                    "required": ["attempts"],
                    "additionalProperties": false,
                },
            ],
            "x-message": "'retry' must be 'never' or a map with an 'attempts' field",
        })
    }
}

/// A whole number from 0 to `u32::MAX`, 4294967295, written as text, with
/// any leading zeros.
const U32_TEXT: &str = "^0*([0-9]{1,9}|[1-3][0-9]{9}|4[01][0-9]{8}|42[0-8][0-9]{7}\
    |429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}\
    |4294967[01][0-9]{2}|42949672[0-8][0-9]|429496729[0-5])$";

impl JsonSchema for Material {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Material".into()
    }

    /// The fields a material takes depend on its `type:`. `quantity` takes a
    /// number written quoted as well, as the reader does.
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        let text = json!({ "type": "string" });
        let of_type = |name: &str, fields: Value| {
            json!({
                "if": {
                    "properties": { "type": { "const": name } },
                    "required": ["type"],
                },
                "then": { "properties": fields, "additionalProperties": false },
            })
        };
        json_schema!({
            "type": "object",
            "properties": {
                "type": { "type": "string", "enum": ["digital", "physical"] },
            },
            "required": ["type"],
            "allOf": [
                of_type("digital", json!({
                    "type": true,
                    "title": text,
                    "description": text,
                    "path": text,
                })),
                of_type("physical", json!({
                    "type": true,
                    "title": text,
                    "description": text,
                    "identifier": text,
                    "quantity": {
                        "type": ["integer", "string"],
                        "pattern": U32_TEXT,
                        "minimum": 0,
                        "maximum": u32::MAX,
                        "x-message": format!(
                            "'quantity' must be a whole number from 0 to {}",
                            u32::MAX
                        ),
                    },
                })),
            ],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn repository(path: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path)
    }

    /// The committed editor schema is the generated one. With
    /// `RITE_UPDATE_SCHEMA` set, the test writes it instead.
    #[test]
    fn the_committed_ceremony_schema_is_the_generated_one() {
        let mut generated = serde_json::to_string_pretty(&editor_schema()).unwrap();
        generated.push('\n');
        let path = repository("docs/schema/ceremony.schema.json");
        if std::env::var_os("RITE_UPDATE_SCHEMA").is_some() {
            std::fs::write(&path, generated).unwrap();
            return;
        }
        let committed = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            committed == generated,
            "docs/schema/ceremony.schema.json is not the generated schema; run \
             `RITE_UPDATE_SCHEMA=1 cargo test -p rite-resolver schema` and commit the result"
        );
    }

    /// Two actions' parameters that share a type share its definition, and
    /// none is named like one of the definition's own, so merging them loses
    /// nothing.
    #[test]
    fn the_actions_agree_on_every_definition_they_share() {
        let ceremony = ceremony_schema();
        let mut seen: HashMap<String, (ActionType, Value)> = HashMap::new();
        for &action in ActionType::ALL {
            let schema = rite_model::params::with_schema(action).to_value();
            let Some(Value::Object(definitions)) = schema.get("$defs") else {
                continue;
            };
            for (name, definition) in definitions {
                assert!(
                    ceremony.pointer(&format!("/$defs/{name}")).is_none(),
                    "{action} names a definition {name} the ceremony has"
                );
                if let Some((first, earlier)) = seen.get(name) {
                    assert_eq!(
                        earlier, definition,
                        "{name} differs in {first} and {action}"
                    );
                } else {
                    seen.insert(name.clone(), (action, definition.clone()));
                }
            }
        }
    }

    fn editor_validator() -> jsonschema::Validator {
        jsonschema::draft202012::new(editor_schema().as_value()).unwrap()
    }

    /// Every example passes the editor schema, read as an editor reads it:
    /// a plain YAML document, with no step's `with:` or `reads:` filled in.
    #[test]
    fn every_example_passes_the_editor_schema() {
        let validator = editor_validator();
        let mut examples = Vec::new();
        for directory in std::fs::read_dir(repository("examples")).unwrap() {
            let directory = directory.unwrap().path();
            if !directory.is_dir() {
                continue;
            }
            for file in std::fs::read_dir(&directory).unwrap() {
                let file = file.unwrap().path();
                if file.to_string_lossy().ends_with(".rite.yaml") {
                    examples.push(file);
                }
            }
        }
        assert!(examples.len() > 10, "{examples:?}");
        for example in examples {
            let yaml = std::fs::read_to_string(&example).unwrap();
            let options = marked_yaml::LoaderOptions::default().prevent_coercion(true);
            let node = marked_yaml::parse_yaml_with_options(0, &yaml, options).unwrap();
            let document = crate::lower::typed_json(&node);
            let errors: Vec<String> = validator
                .iter_errors(&document)
                .map(|e| format!("{} at {}", e, e.instance_path()))
                .collect();
            assert!(errors.is_empty(), "{}: {errors:#?}", example.display());
        }
    }

    /// In the editor schema, an expression stands for any value in `with:`,
    /// and a value that is neither breaks it.
    #[test]
    fn the_editor_schema_takes_an_expression_for_a_with_value() {
        let validator = editor_validator();
        let ceremony = |with: Value| {
            json!({
                "version": "0.3",
                "name": "Test",
                "roles": {},
                "backends": { "ssl": { "provider": "openssl" } },
                "sections": { "main": { "steps": { "gen": {
                    "action": "generate_key",
                    "backend": "ssl",
                    "with": with,
                } } } },
            })
        };
        assert!(validator.is_valid(&ceremony(json!({ "algorithm": "RSA-4096" }))));
        assert!(validator.is_valid(&ceremony(json!({ "algorithm": "${param.algorithm}" }))));
        assert!(!validator.is_valid(&ceremony(json!({ "algorithm": "RSA-9999" }))));
        assert!(!validator.is_valid(&ceremony(json!({ "algoritm": "RSA-4096" }))));
        // A list, a map, or the whole block may be one expression too.
        assert!(validator.is_valid(&ceremony(json!({
            "algorithm": "RSA-4096",
            "policy": { "usages": "${param.usages}" },
        }))));
        assert!(validator.is_valid(&ceremony(json!({
            "algorithm": "RSA-4096",
            "policy": "${param.policy}",
        }))));
        assert!(validator.is_valid(&ceremony(json!("${param.with}"))));
    }

    /// The schema stays within the keywords the engine knows, and compiles.
    #[test]
    fn the_ceremony_schema_compiles_within_the_keywords() {
        fn keywords(value: &Value, out: &mut Vec<String>) {
            match value {
                Value::Object(object) => {
                    for (key, child) in object {
                        out.push(key.clone());
                        // Property names are not keywords.
                        if matches!(key.as_str(), "properties" | "$defs")
                            && let Value::Object(named) = child
                        {
                            named.values().for_each(|v| keywords(v, out));
                        } else {
                            keywords(child, out);
                        }
                    }
                }
                Value::Array(items) => items.iter().for_each(|v| keywords(v, out)),
                _ => {}
            }
        }
        let schema = ceremony_schema();
        let mut found = Vec::new();
        keywords(&schema, &mut found);
        found.retain(|key| !rite_model::params::KEYWORDS.contains(&key.as_str()));
        found.sort();
        found.dedup();
        assert!(found.is_empty(), "outside the keywords: {found:?}");
        ceremony_check().unwrap();
    }
}
