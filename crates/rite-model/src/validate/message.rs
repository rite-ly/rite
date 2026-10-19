//! The schema of each action's `with:` block, compiled once, and what a
//! violation of it says to the ceremony author.
//!
//! One renderer, worded per keyword. Where a generic sentence would lose
//! meaning, the schema carries an `x-message` and that is the message: the
//! one on the schema object that owns the failing keyword, or on an object
//! reaching it through `allOf`, `oneOf`, `if`/`then` or `not` only, never
//! through `properties` or `items`, so a message never captures errors about
//! another field.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde_json::Value;

use super::{Keyword, Matched, Pointer, SchemaError, Validator, Violation};
use crate::ActionType;
use crate::params::with_schema;

/// The compiled schema of one action's `with:` block.
pub struct ParamsCheck {
    validator: Validator,
    schema: Value,
}

/// The check for `action`, compiled on first use and kept for the process.
///
/// # Errors
///
/// Returns why the generated schema did not compile, which is a mistake in
/// the generator; a test compiles every action's schema.
pub fn params_check(action: ActionType) -> Result<&'static ParamsCheck, &'static SchemaError> {
    static CHECKS: OnceLock<HashMap<ActionType, Result<ParamsCheck, SchemaError>>> =
        OnceLock::new();
    let checks = CHECKS.get_or_init(|| {
        ActionType::ALL
            .iter()
            .map(|&action| {
                let schema = with_schema(action).to_value();
                let check =
                    Validator::new(&schema).map(|validator| ParamsCheck { validator, schema });
                (action, check)
            })
            .collect()
    });
    match checks.get(&action) {
        Some(Ok(check)) => Ok(check),
        Some(Err(error)) => Err(error),
        // Every action is in `ALL`, which a test holds to the enum.
        None => {
            static MISSING: OnceLock<SchemaError> = OnceLock::new();
            Err(MISSING.get_or_init(|| SchemaError(format!("no schema for '{action}'"))))
        }
    }
}

/// Where a diagnostic about a violation points: at a key, or at a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anchor {
    /// The key of the entry at the pointer.
    Key,
    /// The value at the pointer.
    Value,
}

impl Violation {
    /// What a diagnostic about this violation underlines: the offending key
    /// for an unexpected one, the key of the object missing a field for a
    /// missing one, and the value for everything else.
    #[must_use]
    pub fn anchor(&self) -> (Pointer, Anchor) {
        match &self.keyword {
            Keyword::AdditionalProperties { unexpected } => match unexpected.as_slice() {
                [key] => (self.instance_path.join(key), Anchor::Key),
                _ => (self.instance_path.clone(), Anchor::Value),
            },
            Keyword::Required { .. } => (self.instance_path.clone(), Anchor::Key),
            _ => (self.instance_path.clone(), Anchor::Value),
        }
    }
}

impl ParamsCheck {
    /// Every way `with` fails the action's schema. An object with several
    /// unexpected keys gives one violation per key, so each can point at its
    /// own key.
    #[must_use]
    pub fn validate(&self, with: &Value) -> Vec<Violation> {
        self.validator
            .validate(with)
            .into_iter()
            .flat_map(|violation| match &violation.keyword {
                Keyword::AdditionalProperties { unexpected } if unexpected.len() > 1 => unexpected
                    .iter()
                    .map(|key| Violation {
                        keyword: Keyword::AdditionalProperties {
                            unexpected: vec![key.clone()],
                        },
                        ..violation.clone()
                    })
                    .collect(),
                _ => vec![violation],
            })
            .collect()
    }

    /// The violation in words, for the author of the step holding `with`.
    #[must_use]
    pub fn message(&self, action: ActionType, with: &Value, violation: &Violation) -> String {
        let at = &violation.instance_path;
        let field = field_name(at);
        let value = at.lookup(with);
        match &violation.keyword {
            Keyword::AdditionalProperties { unexpected } => {
                let accepted = self.accepted(&violation.schema_path);
                let keys = unexpected.join("', '");
                if at.segments().is_empty() {
                    if accepted.is_empty() {
                        format!("action '{action}' takes no 'with:' parameters, found '{keys}'")
                    } else {
                        format!(
                            "action '{action}' has no '{keys}' parameter. Accepted: {}",
                            accepted.join(", ")
                        )
                    }
                } else {
                    format!(
                        "'{field}' has no '{keys}' field. Accepted: {}",
                        accepted.join(", ")
                    )
                }
            }
            Keyword::Required { property } => {
                if at.segments().is_empty() {
                    format!("action '{action}' requires 'with.{property}'")
                } else {
                    format!("'{field}' requires '{property}'")
                }
            }
            keyword => {
                // A `oneOf` of constants is an enumeration whose values each
                // carry a description, and reads as one.
                let keyword = &self
                    .constants(&violation.schema_path)
                    .filter(|_| matches!(keyword, Keyword::OneOf { .. }))
                    .map_or_else(|| keyword.clone(), |options| Keyword::Enum { options });
                let sentence = x_message(&self.schema, &violation.schema_path)
                    .map_or_else(|| sentence(keyword, &field, value), str::to_string);
                match value {
                    Some(value) if is_scalar(value) && !mentions_value(keyword) => {
                        format!("{sentence}, found {}", shown(value))
                    }
                    _ => sentence,
                }
            }
        }
    }

    /// The values of the `oneOf` at `keyword`, when every alternative is a
    /// `const`.
    fn constants(&self, keyword: &Pointer) -> Option<Vec<Value>> {
        keyword
            .lookup(&self.schema)?
            .as_array()?
            .iter()
            .map(|alternative| alternative.get("const").cloned())
            .collect()
    }

    /// The keys the object whose `additionalProperties` is at `keyword`
    /// accepts.
    fn accepted(&self, keyword: &Pointer) -> Vec<String> {
        keyword
            .parent()
            .and_then(|object| object.join("properties").lookup(&self.schema))
            .and_then(Value::as_object)
            .map(|properties| properties.keys().cloned().collect())
            .unwrap_or_default()
    }
}

/// The generic sentence for a keyword, before any `found`.
fn sentence(keyword: &Keyword, field: &str, value: Option<&Value>) -> String {
    let value = value.map_or_else(|| "absent".to_string(), shown);
    match keyword {
        Keyword::Type { expected } => {
            let types: Vec<&str> = expected.iter().map(|t| type_name(t)).collect();
            format!("'{field}' must be {}", types.join(" or "))
        }
        Keyword::Enum { options } => match options.as_slice() {
            [only] => format!("'{field}' must be {}", shown(only)),
            _ => format!(
                "'{field}' is {value}; expected one of: {}",
                options.iter().map(plain).collect::<Vec<_>>().join(", ")
            ),
        },
        Keyword::Const { expected } => format!("'{field}' must be {}", shown(expected)),
        Keyword::Pattern { pattern } => format!("'{field}' must match {pattern}"),
        Keyword::Minimum { limit } => format!("'{field}' is {value}; the least is {limit}"),
        Keyword::Maximum { limit } => format!("'{field}' is {value}; the most is {limit}"),
        Keyword::MinItems { limit } => format!("'{field}' needs at least {limit} entries"),
        Keyword::OneOf {
            matched: Matched::None,
        } => format!("'{field}' takes none of the forms it can have"),
        Keyword::OneOf {
            matched: Matched::Several,
        } => format!("'{field}' takes more than one of the forms it can have"),
        Keyword::Not | Keyword::False => format!("'{field}' is not accepted here"),
        Keyword::Unsupported { keyword } => format!(
            "'{field}' fails the schema keyword '{keyword}', which this version does not check"
        ),
        Keyword::Required { property } => format!("'{field}' requires '{property}'"),
        Keyword::AdditionalProperties { unexpected } => {
            format!("'{field}' has no '{}' field", unexpected.join("', '"))
        }
    }
}

/// Whether the generic sentence already shows the value, so `found` would
/// repeat it.
fn mentions_value(keyword: &Keyword) -> bool {
    match keyword {
        Keyword::Enum { options } => options.len() > 1,
        Keyword::Minimum { .. } | Keyword::Maximum { .. } => true,
        _ => false,
    }
}

/// The `x-message` for the keyword at `keyword`: on the object that owns it,
/// or on one reaching that object through applicators only.
fn x_message<'a>(schema: &'a Value, keyword: &Pointer) -> Option<&'a str> {
    let mut at = keyword.parent()?;
    loop {
        if let Some(message) = at
            .lookup(schema)
            .and_then(|object| object.get("x-message"))
            .and_then(Value::as_str)
        {
            return Some(message);
        }
        let segments = at.segments();
        at = match segments {
            [.., applicator, index]
                if matches!(applicator.as_str(), "allOf" | "oneOf")
                    && index.parse::<usize>().is_ok() =>
            {
                at.parent()?.parent()?
            }
            [.., applicator] if matches!(applicator.as_str(), "if" | "then" | "not") => {
                at.parent()?
            }
            _ => return None,
        };
    }
}

/// `with.policy.usages[0]` for the pointer `/policy/usages/0`.
fn field_name(at: &Pointer) -> String {
    let mut name = "with".to_string();
    for segment in at.segments() {
        if segment.parse::<usize>().is_ok() {
            name.push('[');
            name.push_str(segment);
            name.push(']');
        } else {
            name.push('.');
            name.push_str(segment);
        }
    }
    name
}

fn type_name(name: &str) -> &str {
    match name {
        "string" => "a string",
        "integer" => "an integer",
        "number" => "a number",
        "boolean" => "true or false",
        "array" => "a list",
        "object" => "a map",
        "null" => "empty",
        other => other,
    }
}

fn is_scalar(value: &Value) -> bool {
    !matches!(value, Value::Object(_) | Value::Array(_))
}

/// A value as a message quotes it: a string in single quotes, anything else
/// as JSON.
fn shown(value: &Value) -> String {
    match value {
        Value::String(text) => format!("'{text}'"),
        other => other.to_string(),
    }
}

/// A value in a list of alternatives, unquoted.
fn plain(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn messages(action: ActionType, with: &Value) -> Vec<String> {
        let check = params_check(action).unwrap();
        check
            .validate(with)
            .iter()
            .map(|violation| check.message(action, with, violation))
            .collect()
    }

    fn sole(action: ActionType, with: &Value) -> String {
        let found = messages(action, with);
        let [message] = found.as_slice() else {
            panic!("expected one message, got {found:?}");
        };
        message.clone()
    }

    #[test]
    fn each_keyword_has_its_sentence() {
        assert_eq!(
            sole(ActionType::GenerateKey, &json!({"algorithm": "RSA-9999"})),
            "'with.algorithm' is 'RSA-9999'; expected one of: RSA-2048, RSA-4096, ECDSA-P256, \
             ECDSA-P384, Ed25519, ML-DSA-44, ML-DSA-65, ML-DSA-87, ML-KEM-512, ML-KEM-768, \
             ML-KEM-1024, AES-128, AES-256"
        );
        assert_eq!(
            sole(ActionType::EncryptData, &json!({"scheme": "AES-256-KW"})),
            "'with.scheme' must be 'CMS-AES-256-GCM', found 'AES-256-KW'"
        );
        assert_eq!(
            sole(
                ActionType::IssueCertificate,
                &json!({"validity_days": "ten"})
            ),
            "'with.validity_days' must be an integer, found 'ten'"
        );
        assert_eq!(
            sole(
                ActionType::SplitSecret,
                &json!({"threshold": 2, "shares": 101})
            ),
            "'with.shares' is 101; the most is 100"
        );
        assert_eq!(
            sole(ActionType::CheckValue, &json!({"actual": "x"})),
            "action 'check_value' requires 'with.expected'"
        );
        assert_eq!(
            sole(ActionType::Confirm, &json!({"statement": "x"})),
            "action 'confirm' has no 'statement' parameter. Accepted: message"
        );
        assert_eq!(
            sole(ActionType::ExportPublic, &json!({"x": 1})),
            "action 'export_public' takes no 'with:' parameters, found 'x'"
        );
        assert_eq!(
            sole(
                ActionType::GenerateKey,
                &json!({"policy": {"usages": ["sign", "fly"]}})
            ),
            "'with.policy.usages[1]' is 'fly'; expected one of: sign, verify, encrypt, decrypt, \
             wrap, unwrap, derive"
        );
        assert!(
            sole(
                ActionType::GenerateKey,
                &json!({"policy": {"extractible": true}})
            )
            .starts_with("'with.policy' has no 'extractible' field. Accepted: ")
        );
    }

    #[test]
    fn an_x_message_replaces_the_generic_sentence() {
        assert_eq!(
            sole(
                ActionType::WrapKey,
                &json!({"expect_recipient": "deadbeef"})
            ),
            "'expect_recipient' must be a fingerprint of the form \
             'sha256:<64 lowercase hex digits>', found 'deadbeef'"
        );
        assert_eq!(
            sole(
                ActionType::EnterSecret,
                &json!({"message": "m", "length": 4, "min_length": 2})
            ),
            "'length' is exact, so 'min_length' and 'max_length' cannot be given beside it"
        );
        assert!(
            sole(
                ActionType::EnterValue,
                &json!({"message": "m", "format": "paper32"})
            )
            .contains("use enter_secret")
        );
        assert!(
            sole(
                ActionType::EnterShare,
                &json!({"message": "m", "format": "bip39"})
            )
            .starts_with("a share is written in paper32 or hex")
        );
        assert!(
            sole(
                ActionType::EnterSecret,
                &json!({"message": "m", "format": "wibble"})
            )
            .starts_with("'format' must name a format (text, digits")
        );
    }

    /// Several unknown keys are several diagnostics, each at its own key.
    #[test]
    fn each_unexpected_key_is_its_own_violation() {
        let check = params_check(ActionType::Confirm).unwrap();
        let found = check.validate(&json!({"a": 1, "b": 2}));
        let anchors: Vec<_> = found.iter().map(Violation::anchor).collect();
        assert_eq!(
            anchors,
            [
                (Pointer::parse("/a"), Anchor::Key),
                (Pointer::parse("/b"), Anchor::Key)
            ]
        );
    }

    /// What the schema refuses and accepts, case by case: each refusal fails
    /// in the room if it reaches it, after keys exist.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn the_schema_refuses_values_wrong_in_every_build() {
        for (action, with, says) in [
            (
                ActionType::SignData,
                json!({"algorithm": "RSA-PSS-SHA1"}),
                "expected one of",
            ),
            (
                ActionType::IssueCertificate,
                json!({"profile": "wildcard"}),
                "expected one of",
            ),
            (
                ActionType::UnwrapKey,
                json!({"algorithm": "AES-192"}),
                "expected one of",
            ),
            (
                ActionType::WrapKey,
                json!({"scheme": "CMS-RSA-CBC"}),
                "expected one of",
            ),
            (
                ActionType::EncryptData,
                json!({"scheme": "CMS-RSA-CBC"}),
                "must be",
            ),
            (
                ActionType::GenerateKey,
                json!({"algorithm": 4096}),
                "must be a string",
            ),
            // The runtime renders every fingerprint in lowercase, so an
            // uppercase one would never match the key it names.
            (
                ActionType::WrapKey,
                json!({"expect_recipient": format!("sha256:{}", "AB".repeat(32))}),
                "lowercase",
            ),
            (
                ActionType::UnwrapKey,
                json!({"expect_key": "cmac-aes:763CBC"}),
                "lowercase",
            ),
            // A check value is three bytes, so a fingerprint's length under
            // the check value's prefix is not one.
            (
                ActionType::UnwrapKey,
                json!({"expect_key": format!("cmac-aes:{}", "ab".repeat(32))}),
                "6 lowercase hex digits",
            ),
            (
                ActionType::UnwrapKey,
                json!({"expect_key": "763cbc"}),
                "cmac-aes:",
            ),
            (
                ActionType::Reveal,
                json!({"message": "m", "format": "words"}),
                "expected one of",
            ),
            (
                ActionType::Reveal,
                json!({"message": "m", "length": 0}),
                "the least is 1",
            ),
            (
                ActionType::Reveal,
                json!({"message": "m", "format": "bip39", "length": 32}),
                "counts words",
            ),
            (
                ActionType::EnterShare,
                json!({"message": "m", "length": 3}),
                "longer than 3",
            ),
            (
                ActionType::SplitSecret,
                json!({"threshold": 1, "shares": 3}),
                "the least is 2",
            ),
            (
                ActionType::SplitSecret,
                json!({"threshold": "two", "shares": 3}),
                "an integer",
            ),
            (
                ActionType::SplitSecret,
                json!({"scheme": "sss/v9", "threshold": 2, "shares": 3}),
                "rite-sss/v1",
            ),
            (
                ActionType::EnterValue,
                json!({"message": "m", "format": {"pattern": "[0-9]+"}, "length": 6}),
                "a pattern says the whole shape",
            ),
            (
                ActionType::EnterSecret,
                json!({"message": "m", "format": "emoji"}),
                "must name a format",
            ),
            (
                ActionType::EnterSecret,
                json!({"message": "m", "format": {"regex": "[0-9]+"}}),
                "must name a format",
            ),
            (
                ActionType::EnterSecret,
                json!({"message": "m", "length": "six"}),
                "an integer",
            ),
            (
                ActionType::EnterValue,
                json!({"message": "m", "format": "bip39"}),
                "enter_secret",
            ),
            (
                ActionType::OralReadback,
                json!({"format": "nato_phonetik"}),
                "expected one of",
            ),
            (
                ActionType::PivSign,
                json!({"algorithm": "Ed25519"}),
                "expected one of",
            ),
            (
                ActionType::PivReadCertificate,
                json!({"slot": "9b"}),
                "PIV slot",
            ),
            (
                ActionType::IssueCertificate,
                json!({"path_len": 300}),
                "the most is 255",
            ),
            (
                ActionType::GenerateKey,
                json!({"policy": {"extractable": "yes"}}),
                "true or false",
            ),
        ] {
            let found = messages(action, &with);
            assert!(
                found.iter().any(|message| message.contains(says)),
                "{action} {with}: {found:?}"
            );
        }
    }

    /// The values the old checks accepted, the schema accepts.
    #[test]
    fn the_schema_accepts_the_vocabulary() {
        let fingerprint = format!("sha256:{}", "ab".repeat(32));
        for (action, with) in [
            (ActionType::GenerateKey, json!({"algorithm": "RSA-4096"})),
            (ActionType::SignData, json!({"algorithm": "RSA-PSS-SHA256"})),
            (ActionType::IssueCertificate, json!({"profile": "root_ca"})),
            (
                ActionType::IssueCertificate,
                json!({"profile": "intermediate_ca"}),
            ),
            (ActionType::WrapKey, json!({"scheme": "AES-256-KW"})),
            (
                ActionType::WrapKey,
                json!({"expect_recipient": fingerprint.clone()}),
            ),
            (
                ActionType::EncryptData,
                json!({"scheme": "CMS-AES-256-GCM"}),
            ),
            (ActionType::UnwrapKey, json!({"expect_key": fingerprint})),
            (
                ActionType::UnwrapKey,
                json!({"algorithm": "AES-256", "expect_key": "cmac-aes:763cbc"}),
            ),
            (
                ActionType::GenerateKey,
                json!({"policy": {"usages": ["sign", "verify", "wrap", "unwrap", "derive"]}}),
            ),
            (
                ActionType::Reveal,
                json!({"message": "m", "format": "paper32", "length": 32}),
            ),
            (
                ActionType::Reveal,
                json!({"message": "m", "format": "bip39", "length": 24}),
            ),
            (
                ActionType::EnterShare,
                json!({"message": "m", "length": 35}),
            ),
            (
                ActionType::SplitSecret,
                json!({"threshold": 2, "shares": 100}),
            ),
            (
                ActionType::EnterSecret,
                json!({"message": "m", "format": "paper32", "length": 32}),
            ),
            (ActionType::OralReadback, json!({"format": "nato"})),
            (
                ActionType::PivSign,
                json!({"slot": "piv:9d", "algorithm": "ECDSA-SHA384"}),
            ),
            (ActionType::PivReadCertificate, json!({"slot": "8a"})),
        ] {
            assert_eq!(
                messages(action, &with),
                Vec::<String>::new(),
                "{action} {with}"
            );
        }
    }

    #[test]
    fn every_action_has_a_check() {
        for &action in ActionType::ALL {
            assert!(params_check(action).is_ok(), "{action}");
        }
    }
}
