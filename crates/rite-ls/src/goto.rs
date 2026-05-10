//! Go-to-definition for ceremony YAML.
//!
//! Maps the LSP cursor (0-indexed) to the resolver's 1-indexed coordinates,
//! looks up the target via [`SpanMap::find_target_at`], then resolves it back
//! to its declaration span via [`SpanMap::declaration_span`]. See
//! [`rite_resolver::SpanMap`] for the reference-collection model.

use crate::convert;
use rite_resolver::SpanMap;
use tower_lsp_server::ls_types::{GotoDefinitionResponse, Location, Position, Uri};

/// Return a go-to-definition response for the cursor position, if applicable.
pub fn goto_definition_at(
    span_map: &SpanMap,
    pos: Position,
    uri: &Uri,
) -> Option<GotoDefinitionResponse> {
    // LSP positions are 0-indexed; SpanMap uses 1-indexed (from marked-yaml).
    let line = pos.line as usize + 1;
    let col = pos.character as usize + 1;

    let target = span_map.find_target_at(line, col)?;
    let decl_span = span_map.declaration_span(target)?;

    let target_pos = convert::span_to_position(decl_span);
    Some(GotoDefinitionResponse::Scalar(Location {
        uri: uri.clone(),
        range: convert::point_range(target_pos),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rite_model::{ArtifactId, StepId};
    use rite_resolver::{ReferenceContext, ReferenceEntry, ReferenceTarget, Span};

    fn make_uri() -> Uri {
        "file:///test.yaml".parse().unwrap()
    }

    #[test]
    fn artifact_reference_resolves_to_creates_site() {
        let mut span_map = SpanMap::default();
        // `creates:` site at line 5 col 7.
        let creates_span = Span {
            line: 5,
            column: 7,
            length: Some(20),
        };
        span_map
            .artifacts
            .insert(ArtifactId::new("keypair"), creates_span);
        // `reads:` reference at line 12 col 14 — cursor lands here.
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
            line: 11, // 0-indexed → 12
            character: 14,
        };
        let resp = goto_definition_at(&span_map, pos, &make_uri())
            .expect("should resolve artifact reference");
        let GotoDefinitionResponse::Scalar(loc) = resp else {
            panic!("expected Scalar response");
        };
        assert_eq!(loc.range.start.line, 4); // span line 5 → 0-indexed 4
    }
}
