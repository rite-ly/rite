//! The params type of each action, and the rules over a step's `with:`
//! values that hold in every build.
//!
//! The types generate the schema of each action's `with:` block (see
//! [`with_schema`]), which says what keys it takes and what each value may
//! be. [`cross_field`] holds the few rules a schema cannot say. Both live in
//! the model so the resolver, the runtime and an editor read the same ones,
//! since the language server links the model and the resolver but no
//! backend.
//!
//! Only rules that travel with the document belong here. `RSA-9999` is not a
//! key algorithm on any machine, so rejecting it is portable. Whether *this*
//! binary can generate an ML-DSA key is a property of the build doing the
//! checking, and that question is answered by the action handler instead, at
//! the point where a backend exists to ask.

mod attestation;
mod crypto;
mod entropy;
mod entry;
mod piv;
mod pki;
mod schema;
mod sharing;
mod verification;

pub use attestation::AttestParams;
pub use crypto::{
    EncryptDataParams, GenerateKeyParams, ImportKeyParams, KeyPolicyParams, KeyUsage,
    SignDataParams, UnwrapKeyParams, VerifySignatureParams, WrapKeyParams,
};
pub use entropy::GatherEntropyParams;
pub use entry::EntryParams;
pub use piv::{
    AttestSlotParams, PIV_SIGN_ALGORITHMS, PIV_SLOT, PivReadCertificateParams, PivSignParams,
};
pub use pki::{GenerateCsrParams, IssueCertificateParams};
pub(crate) use schema::names;
pub use schema::{KEYWORDS, generator, with_schema};
pub use sharing::{EnterShareParams, RevealParams, SplitSecretParams};
pub use verification::{
    CheckValueParams, ClockCheckParams, ConfirmParams, MachineInfoParams, OralReadbackParams,
    ReadbackFormat,
};

use serde::{Deserialize, Serialize};

use crate::transcript::{Format, ValidatorSpec, compile_pattern};
use crate::types::ActionType;

/// A `with:` value an action cannot accept.
///
/// The message names the field it is about, so a reader with no span still
/// knows where to look.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamError {
    /// What is wrong, phrased for the ceremony author.
    pub message: String,
}

/// The rules over a step's `with:` values that a schema cannot say: one
/// value compared with another, and a pattern that must compile in the
/// dialect the runtime uses.
///
/// At `rite check`, `with` is the literal part of a block, as
/// [`literal_expr_value`](crate::expression::literal_expr_value) projects it:
/// a field whose value is an expression is absent, and a rule is checked over
/// what is known. When the step runs, it is the evaluated block. A field
/// that is absent or of the wrong type is skipped, since the schema reports
/// it. The messages quote no value, since an evaluated one may be a secret
/// an expression copied in, except a pattern that does not compile, which
/// the step's prompt would record anyway.
#[must_use]
pub fn cross_field(action: ActionType, with: &serde_json::Value) -> Vec<ParamError> {
    match action {
        ActionType::SplitSecret => share_counts(with),
        ActionType::EnterValue | ActionType::EnterSecret => entry_shape(with),

        ActionType::ClockCheck
        | ActionType::Confirm
        | ActionType::CheckValue
        | ActionType::OralReadback
        | ActionType::Reveal
        | ActionType::MachineInfo
        | ActionType::GenerateKey
        | ActionType::WrapKey
        | ActionType::UnwrapKey
        | ActionType::ImportKey
        | ActionType::EncryptData
        | ActionType::DecryptData
        | ActionType::CombineShares
        | ActionType::EnterShare
        | ActionType::ExportPublic
        | ActionType::SignData
        | ActionType::VerifySignature
        | ActionType::Attest
        | ActionType::GatherEntropy
        | ActionType::TpmAttest
        | ActionType::PivReadCertificate
        | ActionType::PivSign
        | ActionType::YubikeyAttestSlot
        | ActionType::IssueCertificate
        | ActionType::GenerateCsr => Vec::new(),
    }
}

/// Fewer shares than the threshold could never reconstruct the secret.
fn share_counts(with: &serde_json::Value) -> Vec<ParamError> {
    let count = |field| with.get(field).and_then(serde_json::Value::as_u64);
    match (count("threshold"), count("shares")) {
        (Some(threshold), Some(shares)) if shares < threshold => vec![ParamError {
            message: "'shares' is below 'threshold', and fewer shares than the threshold \
                      could never reconstruct the secret"
                .to_string(),
        }],
        _ => Vec::new(),
    }
}

/// The shape an `enter_value` or `enter_secret` step gives the value it asks
/// for, built the way the step will build it.
fn entry_shape(with: &serde_json::Value) -> Vec<ParamError> {
    let length = |field| {
        with.get(field)
            .and_then(serde_json::Value::as_u64)
            .and_then(|n| usize::try_from(n).ok())
    };
    let shape = EntryShape {
        format: with
            .get("format")
            .and_then(|format| serde_json::from_value(format.clone()).ok()),
        length: length("length"),
        min_length: length("min_length"),
        max_length: length("max_length"),
    };
    shape
        .validator()
        .err()
        .map(|message| ParamError { message })
        .into_iter()
        .collect()
}

/// `format:` as a step writes it: the name of a [`Format`], or a pattern.
///
/// A pattern is a format too, one whose argument is the expression, so it is
/// written under the same key rather than beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FormatSpec {
    /// `format: hex`
    Named(Format),
    /// `format: { pattern: "..." }`
    Pattern {
        /// A regular expression the whole value must match.
        pattern: String,
    },
}

/// A format name, or an object holding only a pattern.
impl schemars::JsonSchema for FormatSpec {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "FormatSpec".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let named = generator.subschema_for::<Format>();
        schemars::json_schema!({
            "oneOf": [
                named,
                {
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "A regular expression the whole value must match.",
                        }
                    },
                    "required": ["pattern"],
                    "additionalProperties": false,
                }
            ],
            "x-message": format!(
                "'format' must name a format ({}) or be {{ pattern: \"...\" }}",
                Format::ALL
                    .iter()
                    .map(|format| format.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        })
    }
}

/// What an `enter_value` or `enter_secret` step says about the value it asks
/// for, as the `with:` fields spell it.
///
/// One place turns these into a [`ValidatorSpec`], so `rite check` and the
/// running step cannot disagree about which combinations mean something.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EntryShape {
    /// `format:`, what kind of value it is.
    pub format: Option<FormatSpec>,
    /// `length:`, an exact length.
    pub length: Option<usize>,
    /// `min_length:`.
    pub min_length: Option<usize>,
    /// `max_length:`.
    pub max_length: Option<usize>,
}

impl EntryShape {
    /// The rule these fields describe.
    ///
    /// Nothing given asks only for a non-empty value. A pattern says the
    /// whole shape, so a length beside it is refused rather than combined
    /// with it in a way the author would have to guess at. Lengths count the
    /// format's own units: characters for text, bytes for an encoding.
    ///
    /// # Errors
    ///
    /// Returns why the fields do not describe one rule, phrased for the
    /// ceremony author.
    pub fn validator(&self) -> Result<ValidatorSpec, String> {
        let bounded =
            self.length.is_some() || self.min_length.is_some() || self.max_length.is_some();
        let format = match &self.format {
            Some(FormatSpec::Pattern { pattern }) => {
                if bounded {
                    return Err("a pattern says the whole shape of the value, so 'length', \
                         'min_length' and 'max_length' cannot be given beside it"
                        .to_string());
                }
                compile_pattern(pattern)?;
                return Ok(ValidatorSpec::Regex(pattern.clone()));
            }
            Some(FormatSpec::Named(format)) => Some(*format),
            None => None,
        };
        let (min_length, max_length) = match (self.length, self.min_length, self.max_length) {
            (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
                return Err(
                    "'length' is exact, so 'min_length' and 'max_length' cannot be given \
                     beside it"
                        .to_string(),
                );
            }
            (Some(length), None, None) => (Some(length), Some(length)),
            (None, min, max) => (min, max),
        };
        if let (Some(min), Some(max)) = (min_length, max_length)
            && min > max
        {
            return Err("'min_length' is above 'max_length', so no value fits".to_string());
        }
        // Bounds that hold no phrase length describe no phrase.
        if format == Some(Format::Bip39)
            && !crate::bip39::phrase_lengths().any(|n| {
                min_length.is_none_or(|min| n >= min) && max_length.is_none_or(|max| n <= max)
            })
        {
            return Err(format!(
                "a BIP-39 phrase has {} words, and the length given holds none of them",
                crate::bip39::PHRASE_LENGTHS
            ));
        }
        match format {
            None if !bounded => Ok(ValidatorSpec::NonEmpty),
            format => Ok(ValidatorSpec::Format {
                format: format.unwrap_or(Format::Text),
                min_length,
                max_length,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sole(action: ActionType, with: &serde_json::Value) -> String {
        let errors = cross_field(action, with);
        let [error] = errors.as_slice() else {
            panic!("expected exactly one error, got {errors:?}");
        };
        error.message.clone()
    }

    #[test]
    fn a_split_needs_at_least_as_many_shares_as_its_threshold() {
        assert!(
            sole(
                ActionType::SplitSecret,
                &json!({"threshold": 4, "shares": 3})
            )
            .contains("fewer shares than the threshold")
        );
        assert!(
            cross_field(
                ActionType::SplitSecret,
                &json!({"threshold": 3, "shares": 3})
            )
            .is_empty()
        );
        // A `${param}` threshold is absent from the literal projection.
        assert!(cross_field(ActionType::SplitSecret, &json!({"shares": 3})).is_empty());
    }

    /// One rule from the shape fields, the same one the step will apply.
    #[test]
    fn an_entry_shape_becomes_one_rule() {
        let shape = EntryShape {
            format: Some(FormatSpec::Named(Format::Digits)),
            length: Some(6),
            ..EntryShape::default()
        };
        assert!(matches!(
            shape.validator(),
            Ok(ValidatorSpec::Format {
                format: Format::Digits,
                min_length: Some(6),
                max_length: Some(6),
            })
        ));

        // Bounds alone: the format is text.
        let shape = EntryShape {
            max_length: Some(8),
            ..EntryShape::default()
        };
        assert!(matches!(
            shape.validator(),
            Ok(ValidatorSpec::Format {
                format: Format::Text,
                min_length: None,
                max_length: Some(8),
            })
        ));

        assert!(matches!(
            EntryShape::default().validator(),
            Ok(ValidatorSpec::NonEmpty)
        ));
        assert!(matches!(
            EntryShape {
                format: Some(FormatSpec::Pattern {
                    pattern: "[a-z]+".to_string()
                }),
                ..EntryShape::default()
            }
            .validator(),
            Ok(ValidatorSpec::Regex(_))
        ));
    }

    #[test]
    fn rejects_an_entry_shape_no_value_fits() {
        assert!(
            sole(
                ActionType::EnterSecret,
                &json!({"min_length": 8, "max_length": 6})
            )
            .contains("no value fits")
        );
        assert!(
            sole(
                ActionType::EnterSecret,
                &json!({"format": {"pattern": "[0-9"}})
            )
            .contains("invalid pattern")
        );
        assert!(
            sole(
                ActionType::EnterSecret,
                &json!({"format": "bip39", "length": 32})
            )
            .contains("12, 15, 18, 21 or 24")
        );
        assert!(
            sole(
                ActionType::EnterSecret,
                &json!({"format": "bip39", "min_length": 13, "max_length": 14})
            )
            .contains("12, 15, 18, 21 or 24")
        );
        for with in [
            json!({"format": "bip39", "length": 24}),
            json!({"format": "bip39", "min_length": 12, "max_length": 24}),
            json!({"message": "Key", "format": "hex", "length": 32}),
            json!({"message": "PIN"}),
        ] {
            assert!(
                cross_field(ActionType::EnterSecret, &with).is_empty(),
                "{with}"
            );
        }
    }
}

#[cfg(test)]
mod schema_tests {
    use super::*;
    use crate::ActionType;
    use serde_json::Value;

    /// Every keyword a generated schema uses is one [`KEYWORDS`] names, so a
    /// validator for that set alone checks every schema.
    #[test]
    fn every_schema_keeps_to_the_keywords() {
        fn walk(value: &Value, path: &str, found: &mut Vec<String>) {
            let Value::Object(object) = value else {
                return;
            };
            // The message lookup starts where a keyword is written, which for
            // a referenced type is its definition, so a message beside a
            // `$ref` would never be read.
            if object.contains_key("$ref") && object.contains_key("x-message") {
                found.push(format!("{path}: x-message beside $ref"));
            }
            for (key, child) in object {
                if !KEYWORDS.contains(&key.as_str()) {
                    found.push(format!("{path}/{key}"));
                }
                let here = format!("{path}/{key}");
                match (key.as_str(), child) {
                    // Names map to schemas.
                    ("properties" | "$defs", Value::Object(map)) => {
                        for (name, schema) in map {
                            walk(schema, &format!("{here}/{name}"), found);
                        }
                    }
                    // Lists of schemas.
                    ("allOf" | "oneOf", Value::Array(items)) => {
                        for (index, item) in items.iter().enumerate() {
                            walk(item, &format!("{here}/{index}"), found);
                        }
                    }
                    // One schema.
                    ("items" | "if" | "then" | "not" | "additionalProperties", _) => {
                        walk(child, &here, found);
                    }
                    // Values and annotations hold data, not schemas.
                    _ => {}
                }
            }
        }
        for &action in ActionType::ALL {
            let mut found = Vec::new();
            walk(&with_schema(action).to_value(), "", &mut found);
            assert!(found.is_empty(), "{action} uses {found:?}");
        }
    }
}
