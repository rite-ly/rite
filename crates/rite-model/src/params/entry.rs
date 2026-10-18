//! Params for the `enter_value` and `enter_secret` actions.

use schemars::{JsonSchema, Schema};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::FormatSpec;
use super::schema::add_rule;

/// Params for the `enter_value` and `enter_secret` actions.
///
/// The shape fields are turned into one rule by
/// [`EntryShape`](super::EntryShape), which is also what
/// `rite check` applies to them.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = one_rule)]
#[non_exhaustive]
pub struct EntryParams {
    /// What the person is asked for, shown at the prompt.
    pub message: String,
    /// What kind of value it is: a format name, or `{ pattern: "..." }`.
    /// Text by default. An encoding makes the artifact the decoded bytes.
    #[serde(default)]
    pub format: Option<FormatSpec>,
    /// An exact length, in characters for text and bytes for an encoding.
    #[serde(default)]
    #[schemars(range(min = 1))]
    pub length: Option<usize>,
    /// The fewest units accepted.
    #[serde(default)]
    #[schemars(range(min = 1))]
    pub min_length: Option<usize>,
    /// The most units accepted.
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
