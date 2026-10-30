//! Params for the secret sharing actions.

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::schema::{add_rule, names, property};
use crate::{RevealFormat, SharingScheme, bip39};

/// The `with` block of `reveal`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = phrase_lengths)]
#[non_exhaustive]
pub struct RevealParams {
    /// The heading shown above the value and printed on the worksheet.
    pub message: String,
    /// The format used to display the value. Defaults to `paper32`.
    #[serde(default)]
    pub format: Option<RevealFormat>,
    /// A note printed on the worksheet, such as where the value goes or who
    /// keeps it.
    #[serde(default)]
    pub note: Option<String>,
    /// The value's exact length. The unit is words for `bip39` and bytes
    /// otherwise. For a share, include its three-byte header in this length.
    #[serde(default)]
    #[schemars(range(min = 1))]
    pub length: Option<u64>,
}

/// A `length:` in words holds a phrase length.
fn phrase_lengths(schema: &mut Schema) {
    let format = RevealFormat::Bip39;
    add_rule(
        schema,
        json!({
            "if": {
                "properties": { "format": { "const": format.as_str() } },
                "required": ["format"],
            },
            "then": {
                "properties": {
                    "length": {
                        "enum": bip39::phrase_lengths().collect::<Vec<_>>(),
                        "x-message": format!(
                            "'length' counts words for '{format}', and a phrase has {} words",
                            bip39::PHRASE_LENGTHS
                        ),
                    }
                }
            },
        }),
    );
}

/// The `with` block of `enter_share`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = longer_than_a_header)]
#[non_exhaustive]
pub struct EnterShareParams {
    /// The heading shown above the share's rows.
    pub message: String,
    /// The format used to enter the share. Defaults to `paper32`.
    #[serde(default)]
    #[schemars(schema_with = "share_formats")]
    pub format: Option<RevealFormat>,
    /// A note shown with the share's rows, such as where the worksheet came
    /// from.
    #[serde(default)]
    pub note: Option<String>,
    /// The share's exact length in bytes, including its three-byte header.
    #[serde(default)]
    pub length: Option<u64>,
}

/// A share is bytes, so it is never written in words. Naming a words format
/// is told why; any other name gets the list.
fn share_formats(_: &mut SchemaGenerator) -> Schema {
    let (words, bytes): (Vec<RevealFormat>, Vec<RevealFormat>) = RevealFormat::ALL
        .iter()
        .partition(|format| format.is_words());
    let mut schema = names(bytes.iter().map(|format| format.as_str()));
    let words: Vec<&str> = words.iter().map(|format| format.as_str()).collect();
    schema.insert(
        "allOf".to_string(),
        json!([{
            "not": { "enum": words },
            "x-message": format!(
                "a share is written in {}; words are for the secret the shares combine into",
                crate::types::either(bytes.iter().map(|format| format.as_str()))
            ),
        }]),
    );
    schema
}

/// A share is its secret plus a header, so it is longer than the header.
fn longer_than_a_header(schema: &mut Schema) {
    let header = SharingScheme::RiteSssV1.header_len();
    // The message is the minimum's alone, beside the bounds the type sets.
    property(schema, "length").insert(
        "allOf".to_string(),
        json!([{
            "minimum": header.saturating_add(1),
            "x-message": format!(
                "'length' is a share's secret plus {header} header bytes, so it is longer \
                 than {header}"
            ),
        }]),
    );
}

/// The `with` block of `split_secret`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = share_limits)]
#[non_exhaustive]
pub struct SplitSecretParams {
    /// The secret-sharing scheme to use. Defaults to `rite-sss/v1`.
    #[serde(default)]
    pub scheme: Option<SharingScheme>,
    /// The number of shares required to recover the secret.
    //
    // One share is not a split.
    #[schemars(range(min = 2))]
    pub threshold: u8,
    /// The number of shares to create. It must be at least the threshold. A
    /// split with more than 100,000 threshold-sized subsets is refused when the
    /// step runs.
    #[schemars(range(min = 2))]
    pub shares: u8,
}

/// The default scheme when a step names none.
const DEFAULT_SHARING_SCHEME: SharingScheme = SharingScheme::RiteSssV1;

/// Each scheme's limit on the counts, for a step naming it; the default
/// scheme's for a step naming none. Above the largest limit, no scheme takes
/// the counts, which holds while `scheme` is an expression `rite check`
/// cannot read.
fn share_limits(schema: &mut Schema) {
    let largest = SharingScheme::ALL
        .iter()
        .map(|scheme| scheme.max_shares())
        .max()
        .unwrap_or(u8::MAX);
    add_rule(
        schema,
        json!({
            "properties": {
                "threshold": { "maximum": largest },
                "shares": { "maximum": largest },
            }
        }),
    );
    for &scheme in SharingScheme::ALL {
        let max = scheme.max_shares();
        let names_it = if scheme == DEFAULT_SHARING_SCHEME {
            json!({ "properties": { "scheme": { "const": scheme.as_str() } } })
        } else {
            json!({
                "properties": { "scheme": { "const": scheme.as_str() } },
                "required": ["scheme"],
            })
        };
        add_rule(
            schema,
            json!({
                "if": names_it,
                "then": {
                    "properties": {
                        "threshold": { "maximum": max },
                        "shares": { "maximum": max },
                    }
                },
            }),
        );
    }
}

impl Default for SplitSecretParams {
    fn default() -> Self {
        Self {
            scheme: None,
            threshold: 2,
            shares: 2,
        }
    }
}
