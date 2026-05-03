//! Find-references for ceremony YAML.
//!
//! Given a cursor position, identifies the declaration target under the cursor
//! (whether the cursor is on a reference value or a declaration key) and returns
//! all `Location`s in the document that reference that same target.

use crate::convert;
use rite_model::{ActId, MaterialId, ParamId, RoleId, SectionId};
use rite_resolver::{ReferenceTarget, Span, SpanMap};
use tower_lsp_server::ls_types::{Location, Position, Uri};

/// Return all reference sites for the target at the cursor position.
///
/// Works in two cases:
/// 1. Cursor is on a **reference value** (e.g. the `main` in `section: main`):
///    `find_target_at` identifies the target directly.
/// 2. Cursor is on a **declaration key** (e.g. the `main` in `- id: main` under
///    `sections:`): the word under the cursor is matched against declaration maps.
///
/// When `include_declaration` is true (matching `ReferenceContext.include_declaration` from the
/// LSP client), the declaration site is prepended to the returned list.
///
/// Returns an empty vec if no known target is under the cursor.
pub fn find_references_at(
    span_map: &SpanMap,
    text: &str,
    pos: Position,
    uri: &Uri,
    include_declaration: bool,
) -> Vec<Location> {
    // LSP is 0-indexed; SpanMap is 1-indexed.
    let line_1 = pos.line as usize + 1;
    let col_1 = pos.character as usize + 1;

    // Try: cursor is on a reference value.
    let target = if let Some(t) = span_map.find_target_at(line_1, col_1) {
        t.clone()
    } else {
        // Try: cursor is on a declaration.
        let word = crate::convert::word_at_position(text, pos).unwrap_or_default();
        if word.is_empty() {
            return vec![];
        }
        if let Some(target) = declaration_target(span_map, &word) {
            target
        } else {
            return vec![];
        }
    };

    let mut locs: Vec<Location> = Vec::new();

    // Prepend the declaration site when the client requests it.
    if include_declaration && let Some(decl_span) = decl_span_for_target(span_map, &target) {
        locs.push(Location {
            uri: uri.clone(),
            range: convert::point_range(convert::span_to_position(decl_span)),
        });
    }

    locs.extend(
        span_map
            .references
            .iter()
            .filter(|e| e.target == target)
            .map(|e| Location {
                uri: uri.clone(),
                range: convert::span_to_range(e.span),
            }),
    );

    locs
}

/// Look up the declaration span for a resolved reference target.
fn decl_span_for_target(span_map: &SpanMap, target: &ReferenceTarget) -> Option<Span> {
    match target {
        ReferenceTarget::Section(id) => span_map.sections.get(id).copied(),
        ReferenceTarget::Role(id) => span_map.roles.get(id).copied(),
        ReferenceTarget::Act(id) => span_map.acts.get(id).copied(),
        ReferenceTarget::Param(id) => span_map.params.get(id).copied(),
        ReferenceTarget::Material(id) => span_map.materials.get(id).copied(),
        ReferenceTarget::Backend(name) => span_map.backends.get(name.as_str()).copied(),
    }
}

/// Identify a declaration target if `word` matches a known declaration ID.
///
/// Checks all declaration maps and returns the first match found.
fn declaration_target(span_map: &SpanMap, word: &str) -> Option<ReferenceTarget> {
    let section_id = SectionId::new(word);
    if span_map.sections.contains_key(&section_id) {
        return Some(ReferenceTarget::Section(section_id));
    }
    let role_id = RoleId::new(word);
    if span_map.roles.contains_key(&role_id) {
        return Some(ReferenceTarget::Role(role_id));
    }
    let act_id = ActId::new(word);
    if span_map.acts.contains_key(&act_id) {
        return Some(ReferenceTarget::Act(act_id));
    }
    let param_id = ParamId::new(word);
    if span_map.params.contains_key(&param_id) {
        return Some(ReferenceTarget::Param(param_id));
    }
    let material_id = MaterialId::new(word);
    if span_map.materials.contains_key(&material_id) {
        return Some(ReferenceTarget::Material(material_id));
    }
    if span_map.backends.contains_key(word) {
        return Some(ReferenceTarget::Backend(word.to_string()));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rite_model::StepId;
    use rite_resolver::{ReferenceContext, ReferenceEntry, Span};

    fn make_uri() -> Uri {
        "file:///test.yaml".parse().unwrap()
    }

    fn span(line: usize, column: usize) -> Span {
        Span {
            line,
            column,
            length: None,
        }
    }

    #[test]
    fn finds_references_when_cursor_on_reference_value() {
        let mut span_map = SpanMap::default();
        span_map.sections.insert(SectionId::new("main"), span(5, 7));
        span_map.references.push(ReferenceEntry {
            span: Span {
                length: Some(4),
                ..span(10, 14)
            },
            target: ReferenceTarget::Section(SectionId::new("main")),
            context: ReferenceContext::Step(StepId::new("test")),
        });
        span_map.references.push(ReferenceEntry {
            span: Span {
                length: Some(4),
                ..span(20, 14)
            },
            target: ReferenceTarget::Section(SectionId::new("main")),
            context: ReferenceContext::Step(StepId::new("test")),
        });
        span_map.references.push(ReferenceEntry {
            span: Span {
                length: Some(5),
                ..span(30, 14)
            },
            target: ReferenceTarget::Section(SectionId::new("other")),
            context: ReferenceContext::Step(StepId::new("test")),
        });

        // Cursor on the first reference value (line 10, col 15 → 0-indexed: 9, 14).
        let pos = Position {
            line: 9,
            character: 14,
        };
        let locs = find_references_at(&span_map, "", pos, &make_uri(), false);
        assert_eq!(locs.len(), 2, "should find both 'main' references");
        assert_eq!(locs[0].range.start.line, 9); // span line 10 → 0-indexed 9
        assert_eq!(locs[1].range.start.line, 19);
    }

    #[test]
    fn finds_references_when_cursor_on_declaration() {
        let mut span_map = SpanMap::default();
        span_map
            .sections
            .insert(SectionId::new("setup"), span(3, 7));
        span_map.references.push(ReferenceEntry {
            span: Span {
                length: Some(5),
                ..span(15, 14)
            },
            target: ReferenceTarget::Section(SectionId::new("setup")),
            context: ReferenceContext::Step(StepId::new("test")),
        });

        // Cursor on the declaration itself (not a reference), word = "setup".
        let text = "    - id: setup\n";
        let pos = Position {
            line: 0,
            character: 11,
        };
        let locs = find_references_at(&span_map, text, pos, &make_uri(), false);
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].range.start.line, 14); // span line 15 → 0-indexed 14
    }

    #[test]
    fn returns_empty_when_no_target() {
        let span_map = SpanMap::default();
        let text = "  action: confirm\n";
        let pos = Position {
            line: 0,
            character: 12,
        };
        assert!(find_references_at(&span_map, text, pos, &make_uri(), false).is_empty());
    }

    #[test]
    fn include_declaration_prepends_decl_site() {
        let mut span_map = SpanMap::default();
        span_map.sections.insert(SectionId::new("main"), span(5, 7));
        span_map.references.push(ReferenceEntry {
            span: Span {
                length: Some(4),
                ..span(10, 14)
            },
            target: ReferenceTarget::Section(SectionId::new("main")),
            context: ReferenceContext::Step(StepId::new("test")),
        });

        // Cursor on the reference value.
        let pos = Position {
            line: 9,
            character: 14,
        };
        let locs = find_references_at(&span_map, "", pos, &make_uri(), true);
        assert_eq!(locs.len(), 2);
        // Declaration site (span line 5 → 0-indexed 4) comes first.
        assert_eq!(locs[0].range.start.line, 4);
        assert_eq!(locs[1].range.start.line, 9);
    }
}
