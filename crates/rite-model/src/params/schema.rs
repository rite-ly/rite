//! The JSON Schema of each action's `with:` block, generated from the params
//! types.
//!
//! The schema is the check: it says which keys an action takes, which it
//! requires, and what each value may be. It is identical in every build. What
//! one binary cannot carry out is a separate question, answered by the action
//! handler.
//!
//! Generated schemas use a small set of keywords, so that a validator for that
//! set alone is enough to check them. [`KEYWORDS`] is that set, and a test
//! holds every generated schema to it.

use schemars::generate::SchemaSettings;
use schemars::transform::{Transform, transform_subschemas};
use schemars::{Schema, SchemaGenerator, json_schema};
use serde_json::Value;

use super::{
    AttestParams, AttestSlotParams, CheckValueParams, ClockCheckParams, ConfirmParams,
    EncryptDataParams, EnterShareParams, EntryParams, GatherEntropyParams, GenerateCsrParams,
    GenerateKeyParams, ImportKeyParams, IssueCertificateParams, MachineInfoParams,
    OralReadbackParams, PivReadCertificateParams, PivSignParams, RevealParams, SignDataParams,
    SplitSecretParams, UnwrapKeyParams, VerifySignatureParams, WrapKeyParams,
};
use crate::{ActionType, Format};

/// The keywords a generated schema may use: the ones that constrain a value,
/// the ones that combine schemas, and the annotations.
///
/// `x-message` is Rite's own annotation: the message to report when the
/// schema object carrying it, or one it combines, rejects a value.
pub const KEYWORDS: &[&str] = &[
    "type",
    "enum",
    "const",
    "pattern",
    "minimum",
    "maximum",
    "minItems",
    "items",
    "properties",
    "required",
    "additionalProperties",
    "allOf",
    "oneOf",
    "if",
    "then",
    "not",
    "$ref",
    "$defs",
    "description",
    "default",
    "title",
    "x-message",
];

/// The largest integer a JSON number holds exactly, `2^53 - 1`.
const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

/// A generator with the settings every params schema is made with.
#[must_use]
pub fn generator() -> SchemaGenerator {
    SchemaSettings::draft2020_12()
        .with_transform(Strict)
        .into_generator()
}

/// The whole schema of `action`'s `with:` block, with the definitions it
/// refers to.
#[must_use]
pub fn with_schema(action: ActionType) -> Schema {
    let mut generator = generator();
    let mut schema = action.params_schema(&mut generator);
    Strict.transform(&mut schema);
    let definitions = generator.take_definitions(true);
    if !definitions.is_empty() {
        schema.insert("$defs".to_string(), Value::Object(definitions));
    }
    schema
}

impl ActionType {
    /// The schema of this action's `with:` block.
    ///
    /// The one per-action list `with:` has: a new action fails to compile
    /// here until it names its params type. An action that takes no
    /// parameters accepts an empty block and nothing else.
    pub fn params_schema(self, generator: &mut SchemaGenerator) -> Schema {
        match self {
            ActionType::ClockCheck => generator.subschema_for::<ClockCheckParams>(),
            ActionType::Confirm => generator.subschema_for::<ConfirmParams>(),
            ActionType::CheckValue => generator.subschema_for::<CheckValueParams>(),
            ActionType::OralReadback => generator.subschema_for::<OralReadbackParams>(),
            ActionType::Reveal => generator.subschema_for::<RevealParams>(),
            ActionType::MachineInfo => generator.subschema_for::<MachineInfoParams>(),
            ActionType::EnterValue => enter_value(generator),
            ActionType::EnterSecret => generator.subschema_for::<EntryParams>(),
            ActionType::GenerateKey => generator.subschema_for::<GenerateKeyParams>(),
            ActionType::WrapKey => generator.subschema_for::<WrapKeyParams>(),
            ActionType::UnwrapKey => generator.subschema_for::<UnwrapKeyParams>(),
            ActionType::ImportKey => generator.subschema_for::<ImportKeyParams>(),
            ActionType::EncryptData => generator.subschema_for::<EncryptDataParams>(),
            ActionType::SplitSecret => generator.subschema_for::<SplitSecretParams>(),
            ActionType::EnterShare => generator.subschema_for::<EnterShareParams>(),
            ActionType::SignData => generator.subschema_for::<SignDataParams>(),
            ActionType::VerifySignature => generator.subschema_for::<VerifySignatureParams>(),
            ActionType::Attest => generator.subschema_for::<AttestParams>(),
            ActionType::GatherEntropy => generator.subschema_for::<GatherEntropyParams>(),
            ActionType::PivReadCertificate => generator.subschema_for::<PivReadCertificateParams>(),
            ActionType::PivSign => generator.subschema_for::<PivSignParams>(),
            ActionType::YubikeyAttestSlot => generator.subschema_for::<AttestSlotParams>(),
            ActionType::IssueCertificate => generator.subschema_for::<IssueCertificateParams>(),
            ActionType::GenerateCsr => generator.subschema_for::<GenerateCsrParams>(),
            // These take their inputs through `reads:` alone, and
            // `tpm_attest` has no handler in any build yet.
            ActionType::ExportPublic
            | ActionType::DecryptData
            | ActionType::CombineShares
            | ActionType::TpmAttest => json_schema!({
                "type": "object",
                "properties": {},
                "additionalProperties": false,
            }),
        }
    }
}

/// `enter_value` is `enter_secret` without the formats written down on a
/// sheet or read off a device: such a value is a secret, and the transcript
/// carries what this step was answered.
fn enter_value(generator: &mut SchemaGenerator) -> Schema {
    let entry = generator.subschema_for::<EntryParams>();
    let secret: Vec<&str> = Format::ALL
        .iter()
        .filter(|format| format.rows().is_some())
        .map(|format| format.as_str())
        .collect();
    json_schema!({
        "allOf": [
            entry,
            {
                "properties": {
                    "format": {
                        "not": { "enum": secret },
                        "x-message": format!(
                            "{} are for a value written down, which is a secret: use enter_secret",
                            secret.join(" and ")
                        ),
                    }
                }
            }
        ]
    })
}

/// A JSON Schema `enum` of names, for a vocabulary narrowed by an action.
pub(crate) fn names<'a>(names: impl Iterator<Item = &'a str>) -> Schema {
    let names: Vec<&str> = names.collect();
    json_schema!({ "type": "string", "enum": names })
}

/// Add a rule over several fields to a struct's schema, beside the ones its
/// fields carry.
pub(super) fn add_rule(schema: &mut Schema, rule: Value) {
    let rules = schema
        .ensure_object()
        .entry("allOf")
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Value::Array(rules) = rules {
        rules.push(rule);
    }
}

/// The schema of one field of a struct, to add to what its type says.
///
/// # Panics
///
/// If the struct has no such field, which is a mistake in this module.
pub(super) fn property<'a>(
    schema: &'a mut Schema,
    name: &str,
) -> &'a mut serde_json::Map<String, Value> {
    schema
        .get_mut("properties")
        .and_then(|properties| properties.get_mut(name))
        .and_then(Value::as_object_mut)
        .unwrap_or_else(|| panic!("the schema has no property '{name}'"))
}

/// What every generated schema is reduced to, so it stays within
/// [`KEYWORDS`] and says what serde accepts.
///
/// - An integer's Rust type becomes the bound it implies, in place of
///   `format: uint8` and the like, which name a Rust type.
/// - An optional field takes its value's schema. serde reads `null` as
///   absent, but nothing in a ceremony means it, so the schema leaves it out
///   rather than adding `null` to every optional field.
/// - A `null` default says nothing and is dropped.
#[derive(Clone)]
struct Strict;

impl Transform for Strict {
    fn transform(&mut self, schema: &mut Schema) {
        if let Some(Value::Array(kinds)) = schema.get_mut("type") {
            kinds.retain(|kind| kind != "null");
            if let [only] = kinds.as_slice() {
                let only = only.clone();
                schema.insert("type".to_string(), only);
            }
        }
        if let Some(Value::Array(branches)) = schema.get("anyOf")
            && let [value, null] = branches.as_slice()
            && *null == serde_json::json!({ "type": "null" })
            && let Value::Object(value) = value.clone()
        {
            schema.remove("anyOf");
            for (key, keyword) in value {
                schema.insert(key, keyword);
            }
        }
        if schema.get("default") == Some(&Value::Null) {
            schema.remove("default");
        }
        if schema.get("type").and_then(Value::as_str) == Some("integer") {
            let (low, high) = match schema.remove("format").as_ref().and_then(Value::as_str) {
                Some("uint8") => (0, i64::from(u8::MAX)),
                Some("uint16") => (0, i64::from(u16::MAX)),
                Some("uint32") => (0, i64::from(u32::MAX)),
                Some("uint" | "uint64") => (0, MAX_SAFE_INTEGER),
                Some("int8") => (i64::from(i8::MIN), i64::from(i8::MAX)),
                Some("int16") => (i64::from(i16::MIN), i64::from(i16::MAX)),
                Some("int32") => (i64::from(i32::MIN), i64::from(i32::MAX)),
                _ => (-MAX_SAFE_INTEGER, MAX_SAFE_INTEGER),
            };
            let minimum = schema
                .get("minimum")
                .and_then(Value::as_i64)
                .map_or(low, |min| min.max(low));
            let maximum = schema
                .get("maximum")
                .and_then(Value::as_i64)
                .map_or(high, |max| max.min(high));
            schema.insert("minimum".to_string(), minimum.into());
            schema.insert("maximum".to_string(), maximum.into());
        }
        transform_subschemas(self, schema);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use schemars::JsonSchema;
    use serde_json::json;

    /// An integer field's schema is bounded by its Rust type, signed or not,
    /// and a bound the field sets itself is kept when it is tighter.
    #[test]
    fn an_integer_is_bounded_by_its_rust_type() {
        #[derive(JsonSchema)]
        #[allow(dead_code)]
        struct Integers {
            small: i8,
            medium: i16,
            large: i32,
            count: u8,
            #[schemars(range(min = 1))]
            shares: u8,
        }
        let schema = generator().root_schema_for::<Integers>();
        let value = schema.as_value();
        let bounds = |name: &str| {
            let at = |keyword: &str| {
                value
                    .pointer(&format!("/properties/{name}/{keyword}"))
                    .cloned()
            };
            (at("minimum"), at("maximum"))
        };
        let expect = |low: i64, high: i64| (Some(json!(low)), Some(json!(high)));
        assert_eq!(bounds("small"), expect(-128, 127));
        assert_eq!(bounds("medium"), expect(-32768, 32767));
        assert_eq!(bounds("large"), expect(i32::MIN.into(), i32::MAX.into()));
        assert_eq!(bounds("count"), expect(0, 255));
        assert_eq!(bounds("shares"), expect(1, 255));
        assert!(value.pointer("/properties/small/format").is_none());
    }
}
