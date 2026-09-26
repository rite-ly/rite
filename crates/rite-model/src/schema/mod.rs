//! The published JSON Schemas for the transcript and the bundle index.
//!
//! The schemas are generated from the types that read and write the files,
//! and committed under `docs/schema/`. A test fails when the committed file
//! differs from the generated one; run it with `RITE_UPDATE_SCHEMA=1` to
//! write the new schema instead.
//!
//! The schemas are public, so their descriptions are written for readers of
//! the files, apart from the Rust doc comments: each type, variant and field
//! carries its own `schemars(description = ...)`. The line types below exist
//! only for the schema, so their doc comments are that text.
//!
//! A schema checks the shape of a line. It does not check what makes a
//! transcript evidence: that each leaf and chain value recomputes, that the
//! fact is written in canonical form, that each level is declared in the
//! header. `rite verify` checks those.

use std::path::PathBuf;
use std::sync::OnceLock;

use schemars::generate::SchemaSettings;
use schemars::transform::{Transform, transform_subschemas};
use schemars::{JsonSchema, Schema};
use serde::Deserialize;
use serde_json::Value;

use crate::Sha256Digest;
use crate::bundle::{BUNDLE_FORMAT, BUNDLE_SCHEMA, BundleIndex};
use crate::transcript::{
    FACT_TYPES, FACT_VOCABULARY, Level, StepFact, TRANSCRIPT_FORMAT, TRANSCRIPT_SCHEMA,
    TranscriptHeader,
};

#[derive(Deserialize, JsonSchema)]
#[serde(untagged)]
#[allow(dead_code)]
#[schemars(
    description = "One line of a transcript.jsonl file. The first line is the header; every other \
    line records one fact, either complete or withheld. Each line is a JSON object on its own \
    line, and the lines are chained: each line's chain value commits to the line and to every line \
    before it."
)]
enum TranscriptLine {
    Header(HeaderLine),
    Complete(CompleteLine),
    Withheld(WithheldLine),
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
#[schemars(
    description = "The first line of a transcript: what the file is, and the start of the chain."
)]
struct HeaderLine {
    #[serde(rename = "$schema")]
    #[schemars(
        description = "The URL of the JSON Schema of the release that wrote the transcript, for \
        editors and other tools. The chain does not commit to it, and a reader ignores it.",
        extend("format" = "uri")
    )]
    schema: Option<String>,
    header: TranscriptHeader,
    #[schemars(
        description = "The first chain value: SHA-256 over the byte 0x02 followed by the header in \
        RFC 8785 canonical JSON."
    )]
    chain: Sha256Digest,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
#[schemars(
    description = "A fact line with its content: the fact, the salt that hides it, and the values \
    that commit to both."
)]
struct CompleteLine {
    at: At,
    level: Level,
    #[schemars(
        description = "The commitment to the fact: SHA-256 over the byte 0x00, the 16 salt bytes, \
        and the fact in RFC 8785 canonical JSON."
    )]
    leaf: Sha256Digest,
    #[schemars(
        description = "The chain value after this line: SHA-256 over the byte 0x01, the previous \
        chain value, the length of `at` as an 8-byte big-endian integer, `at` in UTF-8, the level \
        as an 8-byte big-endian integer, and the leaf. The chain value of the last line is the \
        transcript's fingerprint."
    )]
    chain: Sha256Digest,
    #[schemars(regex(pattern = r"^[0-9a-f]{32}$"))]
    #[schemars(
        description = "16 random bytes, written as 32 lowercase hex digits. The leaf hashes the \
        decoded bytes. The salt keeps a withheld fact from being guessed from its leaf."
    )]
    salt: String,
    fact: StepFact,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
#[schemars(
    description = "A fact line whose fact is withheld from a disclosure. It keeps the time, the \
    level, the leaf and the chain value, so it folds into the chain exactly as the complete line \
    does, and the transcript keeps its fingerprint."
)]
struct WithheldLine {
    at: At,
    level: Level,
    #[schemars(description = "The commitment to the withheld fact.")]
    leaf: Sha256Digest,
    #[schemars(description = "The chain value after this line.")]
    chain: Sha256Digest,
}

#[derive(Deserialize, JsonSchema)]
#[schemars(extend(
    "format" = "date-time",
    "pattern" = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
))]
#[allow(dead_code)]
#[schemars(
    description = "When the fact was recorded: an RFC 3339 time in UTC with six fractional digits. \
    The chain commits to this exact string."
)]
struct At(String);

/// Bounds every integer to `±(2^53 - 1)`, the range the canonical form
/// writes, or to its Rust type's range where that is narrower. Covers an
/// optional integer, whose type is `["integer", "null"]`.
#[derive(Clone)]
struct SafeIntegers;

const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

impl Transform for SafeIntegers {
    fn transform(&mut self, schema: &mut Schema) {
        let integer = match schema.get("type") {
            Some(Value::String(kind)) => kind == "integer",
            Some(Value::Array(kinds)) => kinds.iter().any(|kind| kind == "integer"),
            _ => false,
        };
        if integer {
            // `uint32` and friends describe a Rust type, not the wire; only
            // the bound they imply is kept.
            let (low, high) = match schema.remove("format").as_ref().and_then(Value::as_str) {
                Some("uint8") => (0, i64::from(u8::MAX)),
                Some("uint16") => (0, i64::from(u16::MAX)),
                Some("uint32") => (0, i64::from(u32::MAX)),
                Some("int8") => (i64::from(i8::MIN), i64::from(i8::MAX)),
                Some("int16") => (i64::from(i16::MIN), i64::from(i16::MAX)),
                Some("int32") => (i64::from(i32::MIN), i64::from(i32::MAX)),
                _ => (-MAX_SAFE_INTEGER, MAX_SAFE_INTEGER),
            };
            let minimum = schema
                .get("minimum")
                .and_then(Value::as_i64)
                .map_or(low, |min| min.max(low));
            schema.insert("minimum".to_string(), minimum.into());
            schema.insert("maximum".to_string(), high.into());
        }
        transform_subschemas(self, schema);
    }
}

fn schema_of<T: JsonSchema>() -> Schema {
    SchemaSettings::draft2020_12()
        .with_transform(SafeIntegers)
        .into_generator()
        .into_root_schema_for::<T>()
}

/// The schema describes one format version: pin the version fields to it.
fn pin(schema: &mut Schema, pointer: &str, value: u32) {
    schema
        .pointer_mut(pointer)
        .and_then(Value::as_object_mut)
        .unwrap_or_else(|| panic!("no {pointer} in the schema"))
        .insert("const".to_string(), value.into());
}

/// Name the schema: its `$id`, where the release publishes it, and a title.
/// Both go first, after `$schema`, where a reader looks for them.
fn identify(schema: Schema, id: &str, title: &str) -> Schema {
    let Value::Object(generated) = schema.to_value() else {
        panic!("a root schema is an object");
    };
    let mut named = serde_json::Map::new();
    for (key, value) in generated {
        if key == "title" {
            continue;
        }
        let first = key == "$schema";
        named.insert(key, value);
        if first {
            named.insert("$id".to_string(), id.into());
            named.insert("title".to_string(), title.into());
        }
    }
    Schema::try_from(Value::Object(named)).expect("still a schema")
}

fn transcript_schema() -> Schema {
    let mut schema = identify(
        schema_of::<TranscriptLine>(),
        TRANSCRIPT_SCHEMA,
        &format!("Rite transcript line (format {TRANSCRIPT_FORMAT}, vocabulary {FACT_VOCABULARY})"),
    );
    let header = "/$defs/TranscriptHeader/properties";
    pin(
        &mut schema,
        &format!("{header}/rite_transcript"),
        TRANSCRIPT_FORMAT,
    );
    pin(
        &mut schema,
        &format!("{header}/vocabulary"),
        FACT_VOCABULARY,
    );
    schema
}

fn bundle_schema() -> Schema {
    let mut schema = identify(
        schema_of::<BundleIndex>(),
        BUNDLE_SCHEMA,
        &format!("Rite bundle index (format {BUNDLE_FORMAT})"),
    );
    pin(&mut schema, "/properties/rite_bundle", BUNDLE_FORMAT);
    schema
}

fn schema_path(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/schema")
        .join(file)
}

/// Compare the committed schema with the generated one, or write it when
/// `RITE_UPDATE_SCHEMA` is set.
fn check_committed(file: &str, schema: &Schema) {
    let mut generated = serde_json::to_string_pretty(schema).expect("serialize schema");
    generated.push('\n');
    let path = schema_path(file);
    if std::env::var_os("RITE_UPDATE_SCHEMA").is_some() {
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("schema dir");
        std::fs::write(&path, generated).expect("write schema");
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == generated,
        "docs/schema/{file} is not the generated schema; run \
         `RITE_UPDATE_SCHEMA=1 cargo test -p rite-model schema` and commit the result"
    );
}

fn validator(schema: &Schema) -> jsonschema::Validator {
    jsonschema::draft202012::new(schema.as_value()).expect("a valid schema")
}

fn transcript_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| validator(&transcript_schema()))
}

/// Check one serialized fact against the published transcript schema, as
/// the fact of a complete line.
pub(crate) fn assert_fact_matches_schema(fact: &Value) {
    let line = serde_json::json!({
        "at": "2026-09-22T10:00:00.000000Z",
        "level": 10,
        "salt": "00000000000000000000000000000000",
        "fact": fact,
        "leaf": Sha256Digest::of(b"leaf").as_str(),
        "chain": Sha256Digest::of(b"chain").as_str(),
    });
    let errors: Vec<String> = transcript_validator()
        .iter_errors(&line)
        .map(|e| e.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "fact does not match the schema: {errors:?}\n{fact}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::BundleFile;

    /// A field without its own description falls back to its doc comment,
    /// which shows as Rust link syntax or as the comment's line breaks.
    #[test]
    fn descriptions_hold_no_rust_syntax() {
        for schema in [transcript_schema(), bundle_schema()] {
            let text = serde_json::to_string(&schema).expect("serialize");
            for doc_comment in ["](", "::", "\\n"] {
                assert!(!text.contains(doc_comment), "{doc_comment} in {text}");
            }
        }
    }

    #[test]
    fn committed_schemas_are_the_generated_ones() {
        check_committed("transcript.schema.json", &transcript_schema());
        check_committed("bundle.schema.json", &bundle_schema());
    }

    /// The fact types the schema lists are the ones a reader knows.
    #[test]
    fn the_schema_lists_every_fact_type() {
        let schema = transcript_schema();
        let variants = schema
            .pointer("/$defs/StepFact/oneOf")
            .and_then(Value::as_array)
            .expect("StepFact variants");
        let mut tags: Vec<&str> = variants
            .iter()
            .filter_map(|v| v.pointer("/properties/type/const").and_then(Value::as_str))
            .collect();
        let mut known = FACT_TYPES.to_vec();
        tags.sort_unstable();
        known.sort_unstable();
        assert_eq!(tags, known);
    }

    fn demo_file(path: &str) -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/demo")
            .join(path);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    /// The demo bundle's complete transcript, and its public disclosure,
    /// which holds withheld lines.
    #[test]
    fn every_line_of_the_demo_transcripts_matches() {
        for file in [
            "demo-bundle/transcript.jsonl",
            "demo-disclosure/transcript.jsonl",
        ] {
            for (i, line) in demo_file(file).lines().enumerate() {
                let value: Value = serde_json::from_str(line).expect("json");
                assert!(
                    transcript_validator().is_valid(&value),
                    "{file} line {} does not match the schema",
                    i + 1
                );
            }
        }
    }

    #[test]
    fn the_demo_bundle_indexes_match() {
        let validator = validator(&bundle_schema());
        for file in ["demo-bundle/bundle.json", "demo-disclosure/bundle.json"] {
            let value: Value = serde_json::from_str(&demo_file(file)).expect("json");
            assert!(validator.is_valid(&value), "{file}");
        }
    }

    #[test]
    fn a_withheld_line_matches_and_a_mixed_one_does_not() {
        let withheld = serde_json::json!({
            "at": "2026-09-22T10:00:00.000000Z",
            "level": 30,
            "leaf": Sha256Digest::of(b"leaf").as_str(),
            "chain": Sha256Digest::of(b"chain").as_str(),
        });
        assert!(transcript_validator().is_valid(&withheld));

        let mut salt_only = withheld;
        salt_only
            .as_object_mut()
            .expect("an object")
            .insert("salt".to_string(), "00".repeat(16).into());
        assert!(!transcript_validator().is_valid(&salt_only));
    }

    #[test]
    fn integers_beyond_the_canonical_range_do_not_match() {
        let line = serde_json::json!({
            "at": "2026-09-22T10:00:00.000000Z",
            "level": 1_u64 << 53,
            "leaf": Sha256Digest::of(b"leaf").as_str(),
            "chain": Sha256Digest::of(b"chain").as_str(),
        });
        assert!(!transcript_validator().is_valid(&line));
    }

    #[test]
    fn bundle_indexes_match() {
        let validator = validator(&bundle_schema());
        for index in [
            BundleIndex::complete(Sha256Digest::of(b"t"), vec![BundleFile::transcript()]),
            BundleIndex::disclosure(Sha256Digest::of(b"t"), Level::PUBLIC, vec![]),
        ] {
            let value = serde_json::to_value(&index).expect("serialize");
            assert!(validator.is_valid(&value), "{value}");
        }
    }
}
