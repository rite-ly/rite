//! Shared HTML helper functions for Rite document generators.

#![allow(clippy::format_push_string)]

use rite_model::{Ceremony, PostCeremonyDuty};

/// Escape HTML special characters.
pub(crate) fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

/// Convert a JSON value to a display string.
///
/// Unwraps strings (no surrounding quotes) and renders `null` as an em-dash;
/// other variants use their `Display` impl.
pub(crate) fn json_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "\u{2014}".to_string(),
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

/// Render a single post-ceremony duty as HTML.
///
/// Used by both ceremony scripts and post-ceremony reports.
pub(crate) fn render_duty(duty: &PostCeremonyDuty, resolved: &Ceremony) -> String {
    let mut html = String::new();

    let heading = if let Some(role_id) = &duty.role {
        let role_name = resolved
            .roles
            .get(role_id)
            .map_or_else(|| role_id.as_str(), |r| r.name.as_str());
        format!("{} \u{2014} {}", duty.kind.display_name(), role_name)
    } else {
        duty.kind.display_name().to_string()
    };

    html.push_str(&format!(
        "  <div class=\"duty\">\n    <h3 class=\"duty-heading\">{}</h3>\n",
        escape_html(&heading)
    ));

    let prose = duty
        .description
        .as_deref()
        .or_else(|| duty.kind.built_in_prose());
    if let Some(prose) = prose {
        html.push_str(&format!(
            "    <p class=\"duty-prose\">{}</p>\n",
            escape_html(prose)
        ));
    }

    let has_items = !duty.items.is_empty();
    let has_extra = duty.recipient.is_some() || duty.location.is_some();

    if has_items || has_extra {
        html.push_str("    <ul class=\"duty-items\">\n");
        for item in &duty.items {
            html.push_str(&format!("      <li>{}</li>\n", escape_html(item)));
        }
        if let Some(recipient) = &duty.recipient {
            html.push_str(&format!(
                "      <li><strong>Recipient:</strong> {}</li>\n",
                escape_html(recipient)
            ));
        }
        if let Some(location) = &duty.location {
            html.push_str(&format!(
                "      <li><strong>Location:</strong> {}</li>\n",
                escape_html(location)
            ));
        }
        html.push_str("    </ul>\n");
    }

    html.push_str("  </div>\n");
    html
}
