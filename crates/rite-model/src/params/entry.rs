//! Params for the `enter_value` and `enter_secret` actions.

use schemars::{JsonSchema, Schema};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::FormatSpec;
use super::schema::add_rule;

/// The `with` block of `enter_value` and `enter_secret`.
//
// The shape fields are turned into one rule by `EntryShape`, which is also
// what `rite check` applies to them.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = one_rule)]
#[non_exhaustive]
pub struct EntryParams {
    /// The prompt shown to the person entering the value.
    pub message: String,
    /// The value's format, such as `hex` or `base64`, or a pattern object such
    /// as `{ pattern: "..." }`. If omitted, the value is treated as text.
    /// Encoded input is stored as decoded bytes.
    #[serde(default)]
    pub format: Option<FormatSpec>,
    /// The exact length required. The unit depends on `format`: characters for
    /// text, bytes for encodings, or words for `bip39`.
    #[serde(default)]
    #[schemars(range(min = 1))]
    pub length: Option<usize>,
    /// The minimum accepted length, in the unit set by `format`.
    #[serde(default)]
    #[schemars(range(min = 1))]
    pub min_length: Option<usize>,
    /// The maximum accepted length, in the unit set by `format`.
    #[serde(default)]
    #[schemars(range(min = 1))]
    pub max_length: Option<usize>,
}

/// The fields describe one rule: an exact length stands alone, and a pattern
/// says the whole shape. The rules that compare two values are
/// [`EntryShape::validator`](super::EntryShape::validator)'s.
fn one_rule(schema: &mut Schema) {
    let absent = |fields: &[&str]| -> Vec<serde_json::Value> {
        fields
            .iter()
            .map(|field| json!({ "not": { "required": [field] } }))
            .collect()
    };
    add_rule(
        schema,
        json!({
            "if": { "required": ["length"] },
            "then": {
                "allOf": absent(&["min_length", "max_length"]),
                "x-message": "'length' is exact, so 'min_length' and 'max_length' cannot be \
                    given beside it",
            },
        }),
    );
    add_rule(
        schema,
        json!({
            "if": {
                "properties": { "format": { "type": "object" } },
                "required": ["format"],
            },
            "then": {
                "allOf": absent(&["length", "min_length", "max_length"]),
                "x-message": "a pattern says the whole shape of the value, so 'length', \
                    'min_length' and 'max_length' cannot be given beside it",
            },
        }),
    );
}
