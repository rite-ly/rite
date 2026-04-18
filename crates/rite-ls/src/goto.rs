//! Go-to-definition for ceremony YAML.
//!
//! During `walk_spans`, the resolver collects a `ReferenceEntry` for every
//! reference-value scalar it encounters (step `section:`, step/section `role:`,
//! section `act:`). Each entry stores the source span of that value scalar plus
//! the resolved declaration target.
//!
//! At request time we convert the LSP cursor (0-indexed) to 1-indexed coordinates,
//! ask `SpanMap::find_target_at` for the matching entry, look up the target
//! declaration's span in the same `SpanMap`, and return a `Location`.

use crate::convert;
use rite_resolver::{ReferenceTarget, SpanMap};
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

    let decl_span = match target {
        ReferenceTarget::Section(id) => span_map.sections.get(id).copied(),
        ReferenceTarget::Role(id) => span_map.roles.get(id).copied(),
        ReferenceTarget::Act(id) => span_map.acts.get(id).copied(),
        ReferenceTarget::Param(id) => span_map.params.get(id).copied(),
        ReferenceTarget::Material(id) => span_map.materials.get(id).copied(),
        ReferenceTarget::Backend(name) => span_map.backends.get(name).copied(),
    }?;

    let target_pos = convert::span_to_position(decl_span);
    Some(GotoDefinitionResponse::Scalar(Location {
        uri: uri.clone(),
        range: convert::point_range(target_pos),
    }))
}
