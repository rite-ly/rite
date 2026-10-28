//! Check a JSON value against a generated schema.
//!
//! The engine is behind this module: nothing outside it sees how a schema is
//! held, only [`Violation`]s. Generated schemas keep to
//! [`params::KEYWORDS`](crate::params::KEYWORDS), the engine checks those
//! keywords alone, and [`Keyword`] has a variant for each that can reject a
//! value.

use std::fmt;

use serde_json::Value;

mod engine;
mod message;

pub use message::{Anchor, Check, Values, params_check};

/// A compiled schema.
pub struct Validator {
    engine: engine::Engine,
}

/// A schema the engine could not compile, which is a mistake in the
/// generator rather than in a ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaError(String);

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid schema: {}", self.0)
    }
}

impl std::error::Error for SchemaError {}

impl Validator {
    /// Compile a draft 2020-12 schema that keeps to
    /// [`params::KEYWORDS`](crate::params::KEYWORDS).
    ///
    /// # Errors
    ///
    /// Returns where the schema is not one, or uses a keyword outside that
    /// set.
    pub fn new(schema: &Value) -> Result<Self, SchemaError> {
        engine::Engine::new(schema).map(|engine| Validator { engine })
    }

    /// Every way `instance` fails the schema, in the order the engine finds
    /// them. Empty when it passes.
    #[must_use]
    pub fn validate(&self, instance: &Value) -> Vec<Violation> {
        self.engine.validate(instance)
    }
}

/// One way a value fails a schema.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Violation {
    /// Where in the value: the value that failed, or for `required` and
    /// `additionalProperties` the object holding the keys.
    pub instance_path: Pointer,
    /// The keyword that rejected it, as a location in the schema document.
    /// A keyword inside a definition is located there, not where it was
    /// referenced from.
    pub schema_path: Pointer,
    /// The keyword and what it asked for.
    pub keyword: Keyword,
}

/// A keyword that rejected a value, and what it asked for.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Keyword {
    /// `type`: the value is none of these types.
    Type {
        /// The JSON types accepted, as JSON Schema names them.
        expected: Vec<String>,
    },
    /// `enum`: the value is none of these.
    Enum {
        /// The values accepted.
        options: Vec<Value>,
    },
    /// `const`: the value is not this one.
    Const {
        /// The value accepted.
        expected: Value,
    },
    /// `pattern`: the string does not match.
    Pattern {
        /// The regular expression.
        pattern: String,
    },
    /// `minimum`: the number is smaller.
    Minimum {
        /// The smallest accepted.
        limit: Value,
    },
    /// `maximum`: the number is larger.
    Maximum {
        /// The largest accepted.
        limit: Value,
    },
    /// `minItems`: the list is shorter.
    MinItems {
        /// The fewest items accepted.
        limit: u64,
    },
    /// `required`: the object lacks this key.
    Required {
        /// The missing key.
        property: String,
    },
    /// `additionalProperties`: the object has keys the schema does not name.
    AdditionalProperties {
        /// The keys, in the order the object holds them.
        unexpected: Vec<String>,
    },
    /// `oneOf`: the value matched none of the alternatives, or several.
    OneOf {
        /// Which of the two.
        matched: Matched,
    },
    /// `not`: the value matched what it must not.
    Not,
    /// A `false` schema: no value is accepted here.
    False,
}

/// How many of a `oneOf`'s alternatives a value matched, when it was not
/// exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Matched {
    /// None of them.
    None,
    /// More than one.
    Several,
}

impl Keyword {
    /// The JSON Schema name of the keyword, a stable code for machine
    /// output.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Keyword::Type { .. } => "type",
            Keyword::Enum { .. } => "enum",
            Keyword::Const { .. } => "const",
            Keyword::Pattern { .. } => "pattern",
            Keyword::Minimum { .. } => "minimum",
            Keyword::Maximum { .. } => "maximum",
            Keyword::MinItems { .. } => "minItems",
            Keyword::Required { .. } => "required",
            Keyword::AdditionalProperties { .. } => "additionalProperties",
            Keyword::OneOf { .. } => "oneOf",
            Keyword::Not => "not",
            Keyword::False => "false",
        }
    }
}

/// A JSON pointer (RFC 6901), held as its segments.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pointer(Vec<String>);

impl Pointer {
    /// The pointer to the whole document.
    #[must_use]
    pub fn root() -> Self {
        Pointer(Vec::new())
    }

    /// Read a pointer such as `/with/san/0`. The empty string is the root.
    #[must_use]
    pub fn parse(pointer: &str) -> Self {
        Pointer(
            pointer
                .split('/')
                .skip(1)
                .map(|segment| segment.replace("~1", "/").replace("~0", "~"))
                .collect(),
        )
    }

    /// The keys and indexes from the root, in order.
    #[must_use]
    pub fn segments(&self) -> &[String] {
        &self.0
    }

    /// This pointer with one more segment.
    #[must_use]
    pub fn join(&self, segment: &str) -> Self {
        let mut segments = self.0.clone();
        segments.push(segment.to_string());
        Pointer(segments)
    }

    /// The pointer one segment up, or `None` at the root.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        let (_, parent) = self.0.split_last()?;
        Some(Pointer(parent.to_vec()))
    }

    /// Whether `self` is `other` or inside it.
    #[must_use]
    pub fn starts_with(&self, other: &Pointer) -> bool {
        self.0.starts_with(&other.0)
    }

    /// The value this pointer names in `document`, if there is one.
    #[must_use]
    pub fn lookup<'a>(&self, document: &'a Value) -> Option<&'a Value> {
        self.0
            .iter()
            .try_fold(document, |value, segment| match value {
                Value::Object(object) => object.get(segment),
                Value::Array(items) => segment.parse::<usize>().ok().and_then(|i| items.get(i)),
                _ => None,
            })
    }
}

impl fmt::Display for Pointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for segment in &self.0 {
            write!(f, "/{}", segment.replace('~', "~0").replace('/', "~1"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ActionType;
    use crate::params::with_schema;
    use serde_json::json;

    fn violations(action: ActionType, with: &Value) -> Vec<Violation> {
        Validator::new(&with_schema(action).to_value())
            .unwrap()
            .validate(with)
    }

    fn keywords(action: ActionType, with: &Value) -> Vec<(String, Keyword)> {
        violations(action, with)
            .into_iter()
            .map(|v| (v.instance_path.to_string(), v.keyword))
            .collect()
    }

    #[test]
    fn every_action_schema_compiles() {
        for &action in ActionType::ALL {
            Validator::new(&with_schema(action).to_value())
                .unwrap_or_else(|e| panic!("{action}: {e}"));
        }
    }

    #[test]
    fn a_valid_block_has_no_violations() {
        assert!(
            violations(ActionType::GenerateKey, &json!({"algorithm": "ECDSA-P256"})).is_empty()
        );
        assert!(violations(ActionType::Confirm, &json!({})).is_empty());
        assert!(violations(ActionType::ExportPublic, &json!({})).is_empty());
    }

    #[test]
    fn each_keyword_is_reported_as_itself() {
        let found = keywords(ActionType::GenerateKey, &json!({"algorithm": "RSA-9999"}));
        assert!(matches!(found.as_slice(), [(path, Keyword::Enum { .. })] if path == "/algorithm"));

        let found = keywords(
            ActionType::IssueCertificate,
            &json!({"validity_days": "ten"}),
        );
        assert_eq!(
            found,
            [(
                "/validity_days".to_string(),
                Keyword::Type {
                    expected: vec!["integer".to_string()]
                }
            )]
        );

        let found = keywords(ActionType::CheckValue, &json!({"actual": "x"}));
        assert_eq!(
            found,
            [(
                String::new(),
                Keyword::Required {
                    property: "expected".to_string()
                }
            )]
        );

        let found = keywords(ActionType::Confirm, &json!({"statement": "x"}));
        assert_eq!(
            found,
            [(
                String::new(),
                Keyword::AdditionalProperties {
                    unexpected: vec!["statement".to_string()]
                }
            )]
        );

        let found = keywords(
            ActionType::WrapKey,
            &json!({"expect_recipient": "deadbeef"}),
        );
        assert!(
            matches!(found.as_slice(), [(path, Keyword::Pattern { .. })] if path == "/expect_recipient")
        );

        // The cap over every scheme and the default scheme's limit are both
        // 100, and the engine reports each rule.
        let found = keywords(
            ActionType::SplitSecret,
            &json!({"threshold": 2, "shares": 101}),
        );
        let maximum = (
            "/shares".to_string(),
            Keyword::Maximum { limit: json!(100) },
        );
        assert_eq!(found, [maximum.clone(), maximum]);

        let found = keywords(
            ActionType::EnterSecret,
            &json!({"message": "m", "format": "wibble"}),
        );
        assert_eq!(
            found,
            [(
                "/format".to_string(),
                Keyword::OneOf {
                    matched: Matched::None
                }
            )]
        );

        let found = keywords(
            ActionType::EnterSecret,
            &json!({"message": "m", "length": 4, "min_length": 2}),
        );
        assert_eq!(found, [(String::new(), Keyword::Not)]);
    }

    /// A keyword inside a definition is located in the definition, which is
    /// where its annotations are.
    #[test]
    fn the_schema_path_is_where_the_keyword_is_written() {
        let [violation] = violations(ActionType::GenerateKey, &json!({"algorithm": "RSA-9999"}))
            .try_into()
            .unwrap();
        assert_eq!(
            violation.schema_path.to_string(),
            "/$defs/KeyAlgorithm/enum"
        );
    }

    #[test]
    fn a_pointer_round_trips_and_escapes() {
        for text in ["", "/with", "/with/san/0", "/a~1b/c~0d"] {
            assert_eq!(Pointer::parse(text).to_string(), text);
        }
        assert_eq!(Pointer::parse("/a~1b").segments(), ["a/b"]);
        let document = json!({"with": {"san": ["DNS:x"]}});
        assert_eq!(
            Pointer::parse("/with/san/0").lookup(&document),
            Some(&json!("DNS:x"))
        );
        assert!(Pointer::parse("/with/san/0").starts_with(&Pointer::parse("/with")));
        assert!(!Pointer::parse("/without").starts_with(&Pointer::parse("/with")));
    }
}
