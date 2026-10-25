//! Params for the secret sharing actions.

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::schema::{add_rule, names, property};
use crate::{RevealFormat, SharingScheme, bip39};

/// Params for `reveal` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = phrase_lengths)]
#[non_exhaustive]
pub struct RevealParams {
    /// What the value is and what to do with it, shown above it and
    /// printed on the sheet.
    pub message: String,
    /// The encoding: `paper32` (the default), `hex`, or `bip39` for a
    /// wallet's recovery phrase.
    #[serde(default)]
    pub format: Option<RevealFormat>,
    /// Text printed on the sheet: where it goes, who keeps it.
    #[serde(default)]
    pub note: Option<String>,
    /// The value's length in the format's unit, words for `bip39` and
    /// bytes otherwise, when the author knows it, so the sheet has exactly
    /// the right number of rows; a value of another size is refused. A
    /// share counts the three header bytes in front of its secret.
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

/// Params for `enter_share` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = longer_than_a_header)]
#[non_exhaustive]
pub struct EnterShareParams {
    /// What the share is, shown above the rows: the sheet's heading.
    pub message: String,
    /// The encoding the sheet was written in: `paper32` (the default) or
    /// `hex`.
    #[serde(default)]
    #[schemars(schema_with = "share_formats")]
    pub format: Option<RevealFormat>,
    /// Shown with the rows: where the sheet came from, who types it.
    #[serde(default)]
    pub note: Option<String>,
    /// The share's length in bytes, its secret's plus three header bytes,
    /// when the author knows it, so the prompt asks for exactly the right
    /// rows; a share of another size is refused.
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

/// Params for `split_secret` action.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = share_limits)]
#[non_exhaustive]
pub struct SplitSecretParams {
    /// The sharing scheme, defaulting to `rite-sss/v1`, the only one this
    /// build implements. Named so the transcript says which one was used.
    #[serde(default)]
    pub scheme: Option<SharingScheme>,
    /// How many shares reconstruct the secret, from 2 to the scheme's limit.
    //
    // One share is not a split.
    #[schemars(range(min = 2))]
    pub threshold: u8,
    /// How many shares to make, from `threshold` to the scheme's limit, 100
    /// for `rite-sss/v1`. Every subset of `threshold` shares is checked
    /// before the step completes, so a split with more than 100,000 such
    /// subsets is refused as well.
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
