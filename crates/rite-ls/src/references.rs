//! Find-references for ceremony YAML.
//!
//! Identifies the declaration target under the cursor (whether the cursor is
//! on a reference value or a declaration key) and returns every `Location`
//! that references that target. Lookups delegate to `SpanMap`. See
//! [`rite_resolver::SpanMap`] for the reference-collection model.

use crate::convert;
use rite_resolver::SpanMap;
use tower_lsp_server::ls_types::{Location, Position, Uri};

/// Return all reference sites for the target at the cursor position.
///
/// Works in two cases:
/// 1. Cursor is on a **reference value** (e.g. the `main` in `section: main`):
///    `find_target_at` identifies the target directly.
/// 2. Cursor is on a **declaration key** (e.g. the `main` in `sections.main:`):
///    the word under the cursor is matched against declaration maps via
///    `SpanMap::declaration_target_for_word`.
///
/// When `include_declaration` is true the declaration site is prepended to the
/// returned list (matching the LSP `ReferenceContext.includeDeclaration` flag).
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

    let target = if let Some(t) = span_map.find_target_at(line_1, col_1) {
        t.clone()
    } else {
        let word = crate::convert::word_at_position(text, pos).unwrap_or_default();
        if word.is_empty() {
            return vec![];
        }
        let Some(target) = span_map.declaration_target_for_word(&word) else {
            return vec![];
        };
        target
    };

    let mut locs: Vec<Location> = Vec::new();

    if include_declaration && let Some(decl_span) = span_map.declaration_span(&target) {
        locs.push(Location {
            uri: uri.clone(),
            range: convert::point_range(convert::span_to_position(decl_span)),
        });
    }

    locs.extend(span_map.references_for_target(&target).map(|e| Location {
        uri: uri.clone(),
        range: convert::span_to_range(e.span),
    }));

    locs
}

#[cfg(test)]
mod tests {
    use super::*;
    use rite_model::{ArtifactId, SectionId, StepId};
    use rite_resolver::{ReferenceContext, ReferenceEntry, ReferenceTarget, Span};

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
            value: "main".to_string(),
        });
        span_map.references.push(ReferenceEntry {
            span: Span {
                length: Some(4),
                ..span(20, 14)
            },
            target: ReferenceTarget::Section(SectionId::new("main")),
            context: ReferenceContext::Step(StepId::new("test")),
            value: "main".to_string(),
        });
        span_map.references.push(ReferenceEntry {
            span: Span {
                length: Some(5),
                ..span(30, 14)
            },
            target: ReferenceTarget::Section(SectionId::new("other")),
            context: ReferenceContext::Step(StepId::new("test")),
            value: "other".to_string(),
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
            value: "setup".to_string(),
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
            value: "main".to_string(),
        });

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

    #[test]
    fn finds_artifact_references_from_creates_or_reads() {
        // Cursor on the `${artifact.keypair}` value in a `reads:` block should
        // find both the producing `creates:` site (when include_declaration is
        // on) and every `reads:` use.
        let mut span_map = SpanMap::default();
        let creates_span = Span {
            line: 5,
            column: 7,
            length: Some(20),
        };
        span_map
            .artifacts
            .insert(ArtifactId::new("keypair"), creates_span);
        // `creates:` reference entry.
        span_map.references.push(ReferenceEntry {
            span: creates_span,
            target: ReferenceTarget::Artifact(ArtifactId::new("keypair")),
            context: ReferenceContext::Step(StepId::new("gen_step")),
            value: "${artifact.keypair}".to_string(),
        });
        // `reads:` reference entry — cursor lands here.
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
        let locs = find_references_at(&span_map, "", pos, &make_uri(), true);
        // 1 declaration + 2 reference entries (creates: and reads:).
        assert_eq!(locs.len(), 3);
        assert_eq!(locs[0].range.start.line, 4); // declaration at line 5
    }
}
