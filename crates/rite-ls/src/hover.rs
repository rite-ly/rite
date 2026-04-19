//! Hover logic for ceremony YAML.
//!
//! Two layers, tried in order:
//!
//! 1. **Reference hover**: uses `SpanMap::find_target_at` (the same mechanism as
//!    go-to-definition) to detect when the cursor is over a `section:`, `role:`, or
//!    `act:` value. If the resolved ceremony is available, shows the declaration's
//!    name, description, and other metadata as Markdown.
//!
//! 2. **Action hover**: falls back to extracting the word at the cursor and looking
//!    it up in the static action table. This is intentionally a fallback: it only fires
//!    when the cursor is not on a known reference value.

use crate::actions;
use rite_model::{Ceremony, MaterialKind};
use rite_resolver::{ReferenceTarget, SpanMap};
use tower_lsp_server::ls_types::{Hover, HoverContents, MarkupContent, MarkupKind, Position};

/// Return hover content for the cursor position, if anything is known.
pub fn hover_at(
    text: &str,
    span_map: &SpanMap,
    resolved: Option<&Ceremony>,
    pos: Position,
) -> Option<Hover> {
    let line = pos.line as usize + 1; // 1-indexed
    let col = pos.character as usize + 1;

    span_map
        .find_target_at(line, col)
        .and_then(|t| hover_for_target(t, resolved))
        .map(markdown_hover)
        .or_else(|| {
            let word = crate::convert::word_at_position(text, pos)?;
            Some(markdown_hover(
                actions::hover_description(&word)?.to_string(),
            ))
        })
}

/// Build Markdown hover content for a resolved reference target.
///
/// Returns `None` if the target can't be found in the resolved ceremony
/// (e.g., the file has errors and resolution failed).
fn hover_for_target(target: &ReferenceTarget, resolved: Option<&Ceremony>) -> Option<String> {
    let resolved = resolved?;
    match target {
        ReferenceTarget::Section(id) => {
            let section = resolved.sections.get(id)?;
            let mut md = format!("**Section** `{}`", id);
            if let Some(name) = &section.name {
                md.push_str(&format!("\n\n{name}"));
            }
            if let Some(desc) = &section.description {
                md.push_str(&format!("\n\n{desc}"));
            }
            if let Some(act_id) = &section.act {
                md.push_str(&format!("\n\n*Act: `{act_id}`*"));
            }
            Some(md)
        }
        ReferenceTarget::Role(id) => {
            let role = resolved.roles.get(id)?;
            let mut md = format!("**Role** `{}`", id);
            if role.name != id.as_str() {
                md.push_str(&format!(", {}", role.name));
            }
            if role.role_type != id.as_str() {
                md.push_str(&format!("\n\nType: `{}`", role.role_type));
            }
            if let Some(person) = &role.person {
                md.push_str(&format!("\n\nPerson: {person}"));
            }
            Some(md)
        }
        ReferenceTarget::Act(id) => {
            let act = resolved.acts.get(id)?;
            let mut md = format!("**Act** `{}`", id);
            if let Some(name) = &act.name {
                md.push_str(&format!("\n\n{name}"));
            }
            if let Some(desc) = &act.description {
                md.push_str(&format!("\n\n{desc}"));
            }
            Some(md)
        }
        ReferenceTarget::Param(id) => {
            let param = resolved.parameters.get(id)?;
            let mut md = format!("**param** · `{}`", param.declared_type);
            if let Some(desc) = &param.description {
                md.push_str(&format!("\n\n{desc}"));
            }
            Some(md)
        }
        ReferenceTarget::Material(id) => {
            let material = resolved.materials.get(id)?;
            let kind_str = match &material.kind {
                MaterialKind::Digital { .. } => "digital",
                MaterialKind::Physical { .. } => "physical",
            };
            let mut md = format!("**material** · `{kind_str}`");
            if let Some(title) = &material.title {
                md.push_str(&format!("\n\n{title}"));
            }
            if let Some(desc) = &material.description {
                md.push_str(&format!("\n\n{desc}"));
            }
            Some(md)
        }
        ReferenceTarget::Backend(name) => {
            let backend = resolved.backends.get(name.as_str())?;
            Some(format!(
                "**backend** `{name}` · provider: `{}`",
                backend.provider
            ))
        }
    }
}

fn markdown_hover(value: String) -> Hover {
    Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::Markdown,
            value,
        }),
        range: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_word_at_middle() {
        let text = "    action: confirm\n";
        let pos = Position {
            line: 0,
            character: 14,
        };
        assert_eq!(
            crate::convert::word_at_position(text, pos).as_deref(),
            Some("confirm")
        );
    }

    #[test]
    fn action_hover_via_fallback() {
        let span_map = SpanMap::default();
        let text = "    action: confirm\n";
        let pos = Position {
            line: 0,
            character: 14,
        };
        assert!(hover_at(text, &span_map, None, pos).is_some());
    }

    #[test]
    fn returns_none_for_unknown_word() {
        let span_map = SpanMap::default();
        let text = "    action: unknown_action\n";
        let pos = Position {
            line: 0,
            character: 14,
        };
        assert!(hover_at(text, &span_map, None, pos).is_none());
    }
}
