//! Shared display helpers for Rite view models.

/// Convert a JSON value to a display string.
///
/// Unwraps strings (no surrounding quotes) and renders `null` as an en-dash;
/// other variants use their `Display` impl.
pub(crate) fn json_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "\u{2013}".to_string(),
        other => other.to_string(),
    }
}

/// Capitalize first letter of each word.
pub(crate) fn capitalize_words(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for word in s.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
        }
    }
    out
}
