//! Hover logic for ceremony YAML.
//!
//! Two layers, tried in order:
//!
//! 1. **Reference hover**: `SpanMap::find_target_at` returns whichever
//!    [`ReferenceTarget`] kind covers the cursor (section, role, act, param,
//!    material, backend, artifact). If the resolved ceremony is available, the
//!    target's metadata is rendered as Markdown.
//!
//! 2. **Action hover**: falls back to extracting the word at the cursor and looking
//!    it up in the static action table. Only fires when the cursor is not on a
//!    known reference value.

use crate::actions;
use rite_model::{ArtifactId, Ceremony, MaterialId, MaterialKind};
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
        .and_then(|t| hover_for_target(t, span_map, resolved))
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
/// (e.g., the file has errors and resolution failed). Artifacts are handled
/// separately because their hover content can be derived from `span_map` alone
/// when the ceremony is unresolved.
fn hover_for_target(
    target: &ReferenceTarget,
    span_map: &SpanMap,
    resolved: Option<&Ceremony>,
) -> Option<String> {
    if let ReferenceTarget::Artifact(id) = target {
        return Some(artifact_hover(id, span_map, resolved));
    }

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
        // ReferenceTarget is `#[non_exhaustive]`; Artifact is handled by the
        // early-return above, so no other variant currently reaches this arm.
        _ => None,
    }
}

/// Render hover content for an artifact reference, using `span_map` to
/// distinguish a `creates:`-produced artifact from a material-backed one.
/// Falls back to the bare ID when no metadata is available — never returns
/// `None`, so the action-table fallback in `hover_at` doesn't fire on the
/// same word.
fn artifact_hover(id: &ArtifactId, span_map: &SpanMap, resolved: Option<&Ceremony>) -> String {
    if span_map.artifacts.contains_key(id) {
        // TODO: name the producing step (`produced by step \`gen_step\``) once a
        // `creates_by_step: HashMap<ArtifactId, StepId>` lives on `SpanMap`.
        return format!("**artifact** `{id}` · produced upstream");
    }
    if let Some(ceremony) = resolved
        && let Some(material) = ceremony.materials.get(&MaterialId::new(id.as_str()))
    {
        let kind_str = match &material.kind {
            MaterialKind::Digital { .. } => "digital",
            MaterialKind::Physical { .. } => "physical",
        };
        let mut md = format!("**artifact** `{id}` · material · `{kind_str}`");
        if let Some(title) = &material.title {
            md.push_str(&format!("\n\n{title}"));
        }
        if let Some(desc) = &material.description {
            md.push_str(&format!("\n\n{desc}"));
        }
        return md;
    }
    format!("**artifact** `{id}`")
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
    use rite_model::{ArtifactId, StepId};
    use rite_resolver::{ReferenceContext, ReferenceEntry, Span};

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

    #[test]
    fn artifact_hover_says_produced_when_creates_site_present() {
        let mut span_map = SpanMap::default();
        span_map.artifacts.insert(
            ArtifactId::new("keypair"),
            Span {
                line: 5,
                column: 7,
                length: Some(20),
            },
        );
        span_map.references.push(ReferenceEntry {
            span: Span {
                line: 12,
                column: 14,
                length: Some(20),
            },
            target: ReferenceTarget::Artifact(ArtifactId::new("keypair")),
            context: ReferenceContext::Step(StepId::new("use_step")),
            value: "${artifact.keypair}".to_string(),
        });

        let pos = Position {
            line: 11,
            character: 14,
        };
        let hover = hover_at("", &span_map, None, pos).expect("hover");
        if let HoverContents::Markup(MarkupContent { value, .. }) = hover.contents {
            assert!(value.contains("produced"), "got: {value}");
            assert!(value.contains("keypair"), "got: {value}");
        } else {
            panic!("expected markup hover");
        }
    }

    #[test]
    fn artifact_hover_falls_through_to_basic_when_no_metadata() {
        // No `creates:` site recorded and no resolved ceremony to look up
        // material details — should still produce a basic artifact hover so
        // the action-table fallback doesn't misfire on the same word.
        let mut span_map = SpanMap::default();
        span_map.references.push(ReferenceEntry {
            span: Span {
                line: 12,
                column: 14,
                length: Some(15),
            },
            target: ReferenceTarget::Artifact(ArtifactId::new("ghost")),
            context: ReferenceContext::Step(StepId::new("use_step")),
            value: "${artifact.ghost}".to_string(),
        });

        let pos = Position {
            line: 11,
            character: 14,
        };
        let hover = hover_at("", &span_map, None, pos).expect("hover");
        if let HoverContents::Markup(MarkupContent { value, .. }) = hover.contents {
            assert!(value.contains("ghost"), "got: {value}");
            assert!(!value.contains("produced"), "got: {value}");
        } else {
            panic!("expected markup hover");
        }
    }
}
