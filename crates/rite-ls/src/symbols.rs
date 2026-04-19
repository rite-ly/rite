//! Document symbols for ceremony YAML.
//!
//! Produces a nested symbol tree for editor outline/breadcrumb navigation:
//!
//! - Acts (Module)
//!   - Sections belonging to that act (Namespace)
//! - Roles (Variable)
//! - Parameters (Constant)
//! - Materials (Object)
//!
//! Sections not assigned to any act appear as top-level Namespace symbols.

use crate::convert;
use rite_model::{ActId, Ceremony};
use rite_resolver::SpanMap;
use std::collections::HashMap;
use tower_lsp_server::ls_types::{DocumentSymbol, Range, SymbolKind};

/// Build the document symbol tree for a ceremony.
pub fn document_symbols(span_map: &SpanMap, resolved: &Ceremony) -> Vec<DocumentSymbol> {
    let mut symbols: Vec<DocumentSymbol> = Vec::new();

    // Single pass over sections: group by act or collect as orphans.
    let mut sections_by_act: HashMap<&ActId, Vec<DocumentSymbol>> = HashMap::new();
    let mut orphan_sections: Vec<DocumentSymbol> = Vec::new();
    for (sec_id, sec) in resolved.sections.iter() {
        let sec_range = span_map
            .sections
            .get(sec_id)
            .map(|s| convert::point_range(convert::span_to_position(*s)))
            .unwrap_or_default();
        let sym = make_symbol(
            sec_id.as_str(),
            sec.name.as_deref(),
            SymbolKind::NAMESPACE,
            sec_range,
            None,
        );
        match &sec.act {
            Some(act_id) => sections_by_act.entry(act_id).or_default().push(sym),
            None => orphan_sections.push(sym),
        }
    }

    // Acts with their pre-grouped section children.
    for (act_id, act) in resolved.acts.iter() {
        let act_range = span_map
            .acts
            .get(act_id)
            .map(|s| convert::point_range(convert::span_to_position(*s)))
            .unwrap_or_default();
        let children = sections_by_act.remove(act_id);
        let detail = act.name.clone().or_else(|| act.description.clone());
        symbols.push(make_symbol(
            act_id.as_str(),
            detail.as_deref(),
            SymbolKind::MODULE,
            act_range,
            children,
        ));
    }

    // Sections not assigned to any act.
    symbols.extend(orphan_sections);

    // Roles.
    for (role_id, role) in resolved.roles.iter() {
        let range = span_map
            .roles
            .get(role_id)
            .map(|s| convert::point_range(convert::span_to_position(*s)))
            .unwrap_or_default();
        let detail = if role.name != role_id.as_str() {
            Some(role.name.as_str())
        } else {
            None
        };
        symbols.push(make_symbol(
            role_id.as_str(),
            detail,
            SymbolKind::VARIABLE,
            range,
            None,
        ));
    }

    // Parameters.
    for (param_id, param) in resolved.parameters.iter() {
        let range = span_map
            .params
            .get(param_id)
            .map(|s| convert::point_range(convert::span_to_position(*s)))
            .unwrap_or_default();
        symbols.push(make_symbol(
            param_id.as_str(),
            param.description.as_deref(),
            SymbolKind::CONSTANT,
            range,
            None,
        ));
    }

    // Materials.
    for (mat_id, mat) in resolved.materials.iter() {
        let range = span_map
            .materials
            .get(mat_id)
            .map(|s| convert::point_range(convert::span_to_position(*s)))
            .unwrap_or_default();
        symbols.push(make_symbol(
            mat_id.as_str(),
            mat.title.as_deref(),
            SymbolKind::OBJECT,
            range,
            None,
        ));
    }

    symbols
}

#[allow(deprecated)]
fn make_symbol(
    name: &str,
    detail: Option<&str>,
    kind: SymbolKind,
    range: Range,
    children: Option<Vec<DocumentSymbol>>,
) -> DocumentSymbol {
    DocumentSymbol {
        name: name.to_string(),
        detail: detail.map(str::to_string),
        kind,
        range,
        selection_range: range,
        children,
        tags: None,
        deprecated: None,
    }
}
