//! The schema of each action's `with:` block, compiled once, and what a
//! violation of it says to the ceremony author.
//!
//! One renderer, worded per keyword. A violation about a value reads as the
//! rule, then the value found: `'with.shares' must be at most 100, found
//! 101`. Where a generic rule would lose meaning, the schema carries an
//! `x-message` and that is the rule: the
//! one on the schema object that owns the failing keyword, or on an object
//! reaching it through `allOf`, `oneOf`, `if`/`then` or `not` only, never
//! through `properties` or `items`, so a message never captures errors about
//! another field.

use std::collections::{HashMap, HashSet};
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
pub fn params_check(action: ActionType) -> Result<&'static ParamsCheck, SchemaError> {
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
        Some(Err(error)) => Err(error.clone()),
        // Every action is in `ALL`, which a test holds to the enum.
        None => Err(SchemaError(format!("no schema for '{action}'"))),
    }
}

/// Where a diagnostic about a violation points: at a key, or at a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Anchor {
    /// The key of the entry at the pointer.
    Key,
    /// The value at the pointer.
    Value,
}

/// Whether a message may quote the value it is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Values {
    /// Quote it: the value is as the definition writes it.
    Shown,
    /// Leave it out: the value was evaluated, and an expression may have
    /// copied a secret into it.
    Withheld,
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
            Keyword::Type { .. }
            | Keyword::Enum { .. }
            | Keyword::Const { .. }
            | Keyword::Pattern { .. }
            | Keyword::Minimum { .. }
            | Keyword::Maximum { .. }
            | Keyword::MinItems { .. }
            | Keyword::OneOf { .. }
            | Keyword::Not
            | Keyword::False => (self.instance_path.clone(), Anchor::Value),
        }
    }
}

impl ParamsCheck {
    /// Every way `with` fails the action's schema, one violation per thing
    /// to fix.
    ///
    /// An object with several unexpected keys gives one violation per key, so
    /// each can point at its own key. A value of the wrong type gives that
    /// violation alone: the rules about its value do not apply to it.
    /// Otherwise, of the rules one value breaks, those with an `x-message`
    /// say more than the generic ones and are the ones kept, and of two
    /// bounds on the same side only the tighter is.
    #[must_use]
    pub fn validate(&self, with: &Value) -> Vec<Violation> {
        let violations = self.validator.validate(with);
        let mut mistyped: HashSet<Pointer> = HashSet::new();
        let mut explained: HashSet<Pointer> = HashSet::new();
        let mut lowest_maximum: HashMap<Pointer, f64> = HashMap::new();
        let mut highest_minimum: HashMap<Pointer, f64> = HashMap::new();
        for violation in &violations {
            let at = violation.instance_path.clone();
            match &violation.keyword {
                Keyword::Type { .. } => {
                    mistyped.insert(at);
                }
                Keyword::Maximum { limit } => {
                    let limit = limit.as_f64().unwrap_or(f64::INFINITY);
                    let lowest = lowest_maximum.entry(at.clone()).or_insert(limit);
                    *lowest = lowest.min(limit);
                }
                Keyword::Minimum { limit } => {
                    let limit = limit.as_f64().unwrap_or(f64::NEG_INFINITY);
                    let highest = highest_minimum.entry(at.clone()).or_insert(limit);
                    *highest = highest.max(limit);
                }
                Keyword::Enum { .. }
                | Keyword::Const { .. }
                | Keyword::Pattern { .. }
                | Keyword::MinItems { .. }
                | Keyword::Required { .. }
                | Keyword::AdditionalProperties { .. }
                | Keyword::OneOf { .. }
                | Keyword::Not
                | Keyword::False => {}
            }
            if self.explains(violation) {
                explained.insert(violation.instance_path.clone());
            }
        }
        // Two rules can set the same bound; it is reported once.
        let mut bounded: HashSet<(Pointer, bool)> = HashSet::new();
        let kept = |violation: &Violation| {
            let at = &violation.instance_path;
            let tightest = |limits: &HashMap<Pointer, f64>, limit: &Value| {
                limits.get(at).copied() == limit.as_f64()
            };
            // A type error, and each key, is reported on its own.
            if is_about_type_or_key(&violation.keyword) {
                return true;
            }
            if mistyped.contains(at) {
                return false;
            }
            if explained.contains(at) {
                return self.explains(violation);
            }
            match &violation.keyword {
                Keyword::Maximum { limit } => {
                    tightest(&lowest_maximum, limit) && bounded.insert((at.clone(), true))
                }
                Keyword::Minimum { limit } => {
                    tightest(&highest_minimum, limit) && bounded.insert((at.clone(), false))
                }
                Keyword::Type { .. }
                | Keyword::Required { .. }
                | Keyword::AdditionalProperties { .. }
                | Keyword::Enum { .. }
                | Keyword::Const { .. }
                | Keyword::Pattern { .. }
                | Keyword::MinItems { .. }
                | Keyword::OneOf { .. }
                | Keyword::Not
                | Keyword::False => true,
            }
        };
        violations
            .into_iter()
            .filter(kept)
            .flat_map(|violation| {
                if let Keyword::AdditionalProperties { unexpected } = &violation.keyword
                    && unexpected.len() > 1
                {
                    return unexpected
                        .iter()
                        .map(|key| Violation {
                            keyword: Keyword::AdditionalProperties {
                                unexpected: vec![key.clone()],
                            },
                            ..violation.clone()
                        })
                        .collect();
                }
                vec![violation]
            })
            .collect()
    }

    /// Whether the schema words this violation with an `x-message`. A type
    /// error or a key never is: see [`message`](Self::message).
    fn explains(&self, violation: &Violation) -> bool {
        !is_about_type_or_key(&violation.keyword)
            && x_message(&self.schema, &violation.schema_path).is_some()
    }

    /// The violation in words, for the author of the step holding `with`.
    ///
    /// A violation about a value reads as the rule, then the value found when
    /// `values` allows it. Keys are always named: they are the definition's,
    /// never a secret.
    #[must_use]
    pub fn message(
        &self,
        action: ActionType,
        with: &Value,
        violation: &Violation,
        values: Values,
    ) -> String {
        let at = &violation.instance_path;
        let field = field_name(at);
        match &violation.keyword {
            Keyword::AdditionalProperties { unexpected } => {
                let accepted = self.accepted(&violation.schema_path);
                let keys = unexpected.join("', '");
                if !at.segments().is_empty() {
                    format!(
                        "'{field}' has no '{keys}' field. Accepted: {}",
                        accepted.join(", ")
                    )
                } else if accepted.is_empty() {
                    format!("action '{action}' takes no 'with:' parameters, found '{keys}'")
                } else {
                    format!(
                        "action '{action}' has no '{keys}' parameter. Accepted: {}",
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
            // A value of the wrong type has not reached the rule an
            // `x-message` explains, so it reads the same everywhere.
            keyword @ Keyword::Type { .. } => found(
                self.rule(keyword, &violation.schema_path, &field),
                values,
                at.lookup(with),
            ),
            keyword @ (Keyword::Enum { .. }
            | Keyword::Const { .. }
            | Keyword::Pattern { .. }
            | Keyword::Minimum { .. }
            | Keyword::Maximum { .. }
            | Keyword::MinItems { .. }
            | Keyword::OneOf { .. }
            | Keyword::Not
            | Keyword::False) => {
                let rule = x_message(&self.schema, &violation.schema_path).map_or_else(
                    || self.rule(keyword, &violation.schema_path, &field),
                    str::to_string,
                );
                found(rule, values, at.lookup(with))
            }
        }
    }

    /// What a keyword about a value asks of `field`, in words.
    fn rule(&self, keyword: &Keyword, keyword_at: &Pointer, field: &str) -> String {
        let options = match keyword {
            Keyword::Enum { options } => Some(options.clone()),
            // A `oneOf` of constants is an enumeration whose values each
            // carry a description, and reads as one.
            Keyword::OneOf { .. } => self.constants(keyword_at),
            Keyword::Type { .. }
            | Keyword::Const { .. }
            | Keyword::Pattern { .. }
            | Keyword::Minimum { .. }
            | Keyword::Maximum { .. }
            | Keyword::MinItems { .. }
            | Keyword::Required { .. }
            | Keyword::AdditionalProperties { .. }
            | Keyword::Not
            | Keyword::False => None,
        };
        if let Some(options) = options {
            return match options.as_slice() {
                [only] => format!("'{field}' must be {}", shown(only)),
                _ => format!(
                    "'{field}' must be one of: {}",
                    options.iter().map(plain).collect::<Vec<_>>().join(", ")
                ),
            };
        }
        match keyword {
            Keyword::Type { expected } => {
                let types: Vec<&str> = expected.iter().map(|t| type_name(t)).collect();
                format!("'{field}' must be {}", types.join(" or "))
            }
            Keyword::Const { expected } => format!("'{field}' must be {}", shown(expected)),
            Keyword::Pattern { pattern } => format!("'{field}' must match {pattern}"),
            Keyword::Minimum { limit } => format!("'{field}' must be at least {limit}"),
            Keyword::Maximum { limit } => format!("'{field}' must be at most {limit}"),
            Keyword::MinItems { limit } => format!("'{field}' needs at least {limit} entries"),
            Keyword::OneOf {
                matched: Matched::None,
            } => format!("'{field}' takes none of the forms it can have"),
            Keyword::OneOf {
                matched: Matched::Several,
            } => format!("'{field}' takes more than one of the forms it can have"),
            Keyword::Not | Keyword::False => format!("'{field}' is not accepted here"),
            // Worded by `message`, which names the keys involved; and an
            // enumeration is worded above.
            Keyword::Enum { .. }
            | Keyword::Required { .. }
            | Keyword::AdditionalProperties { .. } => format!("'{field}' is not accepted"),
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

/// Whether `keyword` is about the value's type or about a key, which the
/// messages word themselves, rather than about the value.
fn is_about_type_or_key(keyword: &Keyword) -> bool {
    match keyword {
        Keyword::Type { .. } | Keyword::Required { .. } | Keyword::AdditionalProperties { .. } => {
            true
        }
        Keyword::Enum { .. }
        | Keyword::Const { .. }
        | Keyword::Pattern { .. }
        | Keyword::Minimum { .. }
        | Keyword::Maximum { .. }
        | Keyword::MinItems { .. }
        | Keyword::OneOf { .. }
        | Keyword::Not
        | Keyword::False => false,
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

/// `rule`, followed by the scalar `value` it is about when `values` allows.
fn found(rule: String, values: Values, value: Option<&Value>) -> String {
    match (values, value) {
        (Values::Shown, Some(value)) if is_scalar(value) => {
            format!("{rule}, found {}", shown(value))
        }
        (Values::Shown | Values::Withheld, _) => rule,
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
            .map(|violation| check.message(action, with, violation, Values::Shown))
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
            "'with.algorithm' must be one of: RSA-2048, RSA-4096, ECDSA-P256, ECDSA-P384, \
             Ed25519, ML-DSA-44, ML-DSA-65, ML-DSA-87, ML-KEM-512, ML-KEM-768, ML-KEM-1024, \
             AES-128, AES-256, found 'RSA-9999'"
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
            "'with.shares' must be at most 100, found 101"
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
            "'with.policy.usages[1]' must be one of: sign, verify, encrypt, decrypt, wrap, \
             unwrap, derive, found 'fly'"
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
                "must be one of",
            ),
            (
                ActionType::IssueCertificate,
                json!({"profile": "wildcard"}),
                "must be one of",
            ),
            (
                ActionType::UnwrapKey,
                json!({"algorithm": "AES-192"}),
                "must be one of",
            ),
            (
                ActionType::WrapKey,
                json!({"scheme": "CMS-RSA-CBC"}),
                "must be one of",
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
                "must be one of",
            ),
            (
                ActionType::Reveal,
                json!({"message": "m", "length": 0}),
                "at least 1",
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
                "at least 2",
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
                "must be one of",
            ),
            (
                ActionType::PivSign,
                json!({"algorithm": "Ed25519"}),
                "must be one of",
            ),
            (
                ActionType::PivReadCertificate,
                json!({"slot": "9b"}),
                "PIV slot",
            ),
            (
                ActionType::IssueCertificate,
                json!({"path_len": 300}),
                "at most 255",
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

    /// An `x-message` says the rule; the value found follows it as it
    /// follows a generic one.
    #[test]
    fn an_x_message_is_followed_by_the_value_found() {
        assert_eq!(
            sole(
                ActionType::Reveal,
                &json!({"message": "m", "format": "bip39", "length": 32})
            ),
            "'length' counts words for 'bip39', and a phrase has 12, 15, 18, 21 or 24 words, \
             found 32"
        );
    }

    /// A value of the wrong type is told so, in the same words everywhere,
    /// and once: the `x-message` and the names that a string may take are
    /// about values of the right type.
    #[test]
    fn a_wrong_type_is_one_message_in_plain_words() {
        // Unquoted, so YAML reads it as a number.
        assert_eq!(
            sole(ActionType::PivReadCertificate, &json!({"slot": 82})),
            "'with.slot' must be a string, found 82"
        );
        assert_eq!(
            sole(
                ActionType::EnterShare,
                &json!({"message": "m", "length": "35"})
            ),
            "'with.length' must be an integer, found '35'"
        );
        assert_eq!(
            sole(ActionType::EncryptData, &json!({"scheme": 5})),
            "'with.scheme' must be a string, found 5"
        );
    }

    /// A value breaking several rules gets the one that says most: an
    /// `x-message` over a generic rule, the tighter of two bounds. And an
    /// `x-message` speaks only for the rule it explains.
    #[test]
    fn one_value_gets_the_message_that_says_most() {
        // The u8 bound is 255; the scheme's limit is tighter.
        assert_eq!(
            sole(
                ActionType::SplitSecret,
                &json!({"threshold": 2, "shares": 300})
            ),
            "'with.shares' must be at most 100, found 300"
        );
        // Below the type's bound and outside the phrase lengths.
        assert_eq!(
            sole(
                ActionType::Reveal,
                &json!({"message": "m", "format": "bip39", "length": 0})
            ),
            "'length' counts words for 'bip39', and a phrase has 12, 15, 18, 21 or 24 words, \
             found 0"
        );
        // A share is never words; a typo is just not a format.
        assert_eq!(
            sole(
                ActionType::EnterShare,
                &json!({"message": "m", "format": "bip39"})
            ),
            "a share is written in paper32 or hex; words are for the secret the shares \
             combine into, found 'bip39'"
        );
        assert_eq!(
            sole(
                ActionType::EnterShare,
                &json!({"message": "m", "format": "hexx"})
            ),
            "'with.format' must be one of: paper32, hex, found 'hexx'"
        );
        // The header message is the minimum's, not the type's bound.
        assert_eq!(
            sole(
                ActionType::EnterShare,
                &json!({"message": "m", "length": 2})
            ),
            "'length' is a share's secret plus 3 header bytes, so it is longer than 3, found 2"
        );
        assert!(
            sole(
                ActionType::EnterShare,
                &json!({"message": "m", "length": 9_007_199_254_740_992_u64})
            )
            .starts_with("'with.length' must be at most ")
        );
    }

    /// An evaluated value may hold a secret an expression copied in, so a
    /// message about it names the field and the rule only.
    #[test]
    fn a_withheld_value_is_never_quoted() {
        let check = params_check(ActionType::UnwrapKey).unwrap();
        for with in [
            json!({"expect_key": "c2VjcmV0LWtleS1tYXRlcmlhbA=="}),
            json!({"algorithm": "c2VjcmV0LWtleS1tYXRlcmlhbA=="}),
            json!({"label": 1_234_567}),
        ] {
            let found = check.validate(&with);
            assert!(!found.is_empty(), "{with}");
            for violation in &found {
                let message =
                    check.message(ActionType::UnwrapKey, &with, violation, Values::Withheld);
                assert!(
                    !message.contains("c2Vj") && !message.contains("1234567"),
                    "{message}"
                );
                assert!(!message.contains("found"), "{message}");
            }
        }
    }

    #[test]
    fn every_action_has_a_check() {
        for &action in ActionType::ALL {
            assert!(params_check(action).is_ok(), "{action}");
        }
    }
}
