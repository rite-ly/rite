//! Canonical JSON (RFC 8785, JCS) for the values the transcript commits to.
//!
//! A fact is committed as the SHA-256 of its canonical form, so any
//! implementation that canonicalises the same value gets the same bytes. The
//! transcript holds no floating-point numbers, and integers stay within the
//! range JavaScript represents exactly, so this writer covers that subset and
//! refuses anything else rather than guess at the number formatting RFC 8785
//! borrows from ECMAScript.

use std::fmt;
use std::fmt::Write as _;

use serde_json::{Number, Value};

/// Largest integer magnitude written: `2^53 - 1`, the edge of the range an
/// IEEE 754 double represents exactly.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// A value outside the subset the transcript's canonical form covers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CanonicalJsonError {
    /// A number that is not an integer.
    NotAnInteger(String),
    /// An integer beyond `±(2^53 - 1)`.
    IntegerOutOfRange(String),
}

impl fmt::Display for CanonicalJsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanonicalJsonError::NotAnInteger(n) => {
                write!(
                    f,
                    "{n} is not an integer; the transcript records integers only"
                )
            }
            CanonicalJsonError::IntegerOutOfRange(n) => {
                write!(f, "{n} is beyond the integer range the transcript records")
            }
        }
    }
}

impl std::error::Error for CanonicalJsonError {}

/// The RFC 8785 canonical form of `value`.
///
/// Members are sorted by their UTF-16 code units and written without
/// whitespace, so any implementation that reads the same value writes the
/// same bytes.
///
/// ```
/// use rite_model::canonical_json;
/// use serde_json::json;
///
/// let value = json!({ "b": 2, "a": [true, null, "x"] });
/// assert_eq!(canonical_json(&value)?, r#"{"a":[true,null,"x"],"b":2}"#);
/// assert!(canonical_json(&json!({ "ratio": 1.5 })).is_err());
/// # Ok::<(), rite_model::CanonicalJsonError>(())
/// ```
///
/// # Errors
///
/// Returns [`CanonicalJsonError`] for a non-integer number or an integer
/// beyond `±(2^53 - 1)`.
pub fn canonical_json(value: &Value) -> Result<String, CanonicalJsonError> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

/// Checks that every number in `value` is one the canonical form writes.
///
/// A ceremony checks its values with this before a run, so a number the
/// transcript cannot record is refused by `rite check` rather than mid-run.
///
/// # Errors
///
/// Returns [`CanonicalJsonError`] for the first number that is not an integer
/// or is beyond `±(2^53 - 1)`.
pub fn check_numbers(value: &Value) -> Result<(), CanonicalJsonError> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(n) => check_number(n),
        Value::Array(items) => items.iter().try_for_each(check_numbers),
        Value::Object(members) => members.values().try_for_each(check_numbers),
    }
}

fn check_number(n: &Number) -> Result<(), CanonicalJsonError> {
    let magnitude = if let Some(i) = n.as_i64() {
        i.unsigned_abs()
    } else if let Some(u) = n.as_u64() {
        u
    } else {
        return Err(CanonicalJsonError::NotAnInteger(n.to_string()));
    };
    if magnitude > MAX_SAFE_INTEGER {
        return Err(CanonicalJsonError::IntegerOutOfRange(n.to_string()));
    }
    Ok(())
}

fn write_value(value: &Value, out: &mut String) -> Result<(), CanonicalJsonError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            check_number(n)?;
            out.push_str(&n.to_string());
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // RFC 8785 orders members by the UTF-16 code units of their
            // names, which differs from byte order for characters above
            // U+FFFF.
            let mut members: Vec<(&String, &Value)> = map.iter().collect();
            members.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push('{');
            for (i, (name, member)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(name, out);
                out.push(':');
                write_value(member, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// A string in RFC 8785 form: `"` and `\` escaped, the five short control
/// escapes, other control characters as lowercase `\u00xx`, everything else
/// as itself.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0C}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if c < ' ' => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn members_are_ordered_by_utf16_code_units() {
        // The ordering example from RFC 8785 section 3.2.3.
        let value: Value = serde_json::from_str(
            r#"{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}"#,
        )
        .expect("parse");
        // The emoji (a surrogate pair from 0xD83D) sorts before U+FB33,
        // though its UTF-8 bytes sort after.
        let expected = concat!(
            r#"{"\r":"Carriage Return","1":"One","#,
            "\"\u{80}\":\"Control\",",
            "\"\u{f6}\":\"Latin Small Letter O With Diaeresis\",",
            "\"\u{20ac}\":\"Euro Sign\",",
            "\"\u{1f600}\":\"Emoji: Grinning Face\",",
            "\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}",
        );
        assert_eq!(canonical_json(&value).expect("canonical"), expected);
    }

    #[test]
    fn strings_use_the_rfc_escapes() {
        // The string example from RFC 8785 section 3.2.2.2.
        let value: Value =
            serde_json::from_str(r#""\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/""#)
                .expect("parse");
        assert_eq!(
            canonical_json(&value).expect("canonical"),
            r#""€$\u000f\nA'B\"\\\\\"/""#
        );
    }

    #[test]
    fn nesting_and_literals() {
        let value = json!({ "b": [true, null, -3, {"z": 1, "a": "x"}], "a": 0 });
        assert_eq!(
            canonical_json(&value).expect("canonical"),
            r#"{"a":0,"b":[true,null,-3,{"a":"x","z":1}]}"#
        );
    }

    #[test]
    fn floats_and_large_integers_are_refused() {
        assert!(matches!(
            canonical_json(&json!(1.5)),
            Err(CanonicalJsonError::NotAnInteger(_))
        ));
        assert!(matches!(
            canonical_json(&json!(1_u64 << 53)),
            Err(CanonicalJsonError::IntegerOutOfRange(_))
        ));
        assert!(canonical_json(&json!(MAX_SAFE_INTEGER)).is_ok());
        assert!(canonical_json(&json!(-(1_i64 << 53) + 1)).is_ok());
    }

    #[test]
    fn check_numbers_walks_nested_values() {
        assert!(check_numbers(&json!({ "a": [1, "x", { "b": -2 }] })).is_ok());
        assert!(matches!(
            check_numbers(&json!({ "a": [1, { "b": 0.5 }] })),
            Err(CanonicalJsonError::NotAnInteger(_))
        ));
        assert!(matches!(
            check_numbers(&json!([u64::MAX])),
            Err(CanonicalJsonError::IntegerOutOfRange(_))
        ));
    }
}
