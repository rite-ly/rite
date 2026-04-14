//! YAML lowering: parse the Node tree, extract source spans, and deserialize ceremony types.

use crate::diagnostic::{Diagnostic, ReferenceEntry, ReferenceTarget, Severity, Span, SpanMap};
use crate::error::ResolveError;
use crate::schema::Ceremony;
use marked_yaml::Node;
use marked_yaml::types::MarkedScalarNode;
use rite_model::{ActId, MaterialId, ParamId, RoleId, SectionId, StepId};
use std::path::Path;

/// Parse ceremony YAML, build a `SpanMap`, and return structured diagnostics.
///
/// Always returns whatever spans could be collected even if deserialization fails.
pub(crate) fn lower_ceremony(
    path: Option<&Path>,
    yaml: &str,
) -> (Option<Ceremony>, SpanMap, Vec<Diagnostic>) {
    let mut diags = Vec::new();

    // Step A: parse YAML into a Node tree.
    let node = match marked_yaml::parse_yaml(0, yaml) {
        Ok(n) => n,
        Err(load_err) => {
            diags.push(load_error_to_diagnostic(path, &load_err));
            return (None, SpanMap::default(), diags);
        }
    };

    // Step B: walk spans — always runs, even if Step C fails.
    let (span_map, structural_diags) = walk_spans(path, &node);
    diags.extend(structural_diags);

    // Step C: serde deserialization from the same Node tree.
    let ceremony_opt = match marked_yaml::from_node::<Ceremony>(&node) {
        Ok(mut c) => {
            coerce_ceremony_json_scalars(&mut c);
            Some(c)
        }
        Err(from_node_err) => {
            let span = from_node_err.start_mark().map(|m| Span {
                line: m.line(),
                column: m.column(),
            });
            diags.push(Diagnostic {
                path: path.map(Path::to_owned),
                span,
                severity: Severity::Error,
                message: from_node_err.to_string(),
            });
            None
        }
    };

    (ceremony_opt, span_map, diags)
}

/// Extract span information from all ceremony element IDs in the Node tree.
#[allow(clippy::too_many_lines)]
fn walk_spans(path: Option<&Path>, node: &Node) -> (SpanMap, Vec<Diagnostic>) {
    const KNOWN_KEYS: &[&str] = &[
        "version",
        "name",
        "description",
        "backends",
        "roles",
        "acts",
        "sections",
        "parameters",
        "materials",
        "prerequisites",
        "output",
        "after",
    ];

    let mut span_map = SpanMap::default();
    let mut diags = Vec::new();

    let Some(mapping) = node.as_mapping() else {
        return (span_map, diags);
    };

    // Sections: mapping where keys are section IDs; each section contains nested steps.
    if let Some(sections_map) = mapping.get_mapping("sections") {
        for (section_id_scalar, section_node) in sections_map.iter() {
            if let Some(span) = scalar_to_span(section_id_scalar) {
                span_map
                    .sections
                    .insert(SectionId::new(section_id_scalar.as_str()), span);
            }

            let Some(section_map) = section_node.as_mapping() else {
                continue;
            };

            // Collect section-level reference spans.
            if let Some(val) = section_map.get_scalar("act") {
                push_reference(
                    &mut span_map,
                    val,
                    ReferenceTarget::Act(ActId::new(val.as_str())),
                );
            }
            if let Some(val) = section_map.get_scalar("role") {
                push_reference(
                    &mut span_map,
                    val,
                    ReferenceTarget::Role(RoleId::new(val.as_str())),
                );
            }
            if let Some(desc) = section_map.get_scalar("description") {
                scan_expression_refs(&mut span_map, desc);
            }

            // Steps: mapping where keys are step IDs.
            if let Some(steps_map) = section_map.get_mapping("steps") {
                for (step_id_scalar, step_node) in steps_map.iter() {
                    if let Some(span) = scalar_to_span(step_id_scalar) {
                        span_map
                            .steps
                            .insert(StepId::new(step_id_scalar.as_str()), span);
                    }

                    let Some(step_map) = step_node.as_mapping() else {
                        continue;
                    };

                    // Validate required field.
                    if !mapping_has_key(step_map, "action") {
                        diags.push(Diagnostic {
                            path: path.map(Path::to_owned),
                            span: node_to_span(step_node),
                            severity: Severity::Error,
                            message: format!(
                                "Step '{}' is missing required field 'action'",
                                step_id_scalar.as_str()
                            ),
                        });
                    }

                    // Collect step reference spans.
                    if let Some(val) = step_map.get_scalar("role") {
                        push_reference(
                            &mut span_map,
                            val,
                            ReferenceTarget::Role(RoleId::new(extract_role_id(val.as_str()))),
                        );
                    }
                    if let Some(val) = step_map.get_scalar("backend") {
                        push_reference(
                            &mut span_map,
                            val,
                            ReferenceTarget::Backend(val.as_str().to_string()),
                        );
                    }
                    if let Some(desc) = step_map.get_scalar("description") {
                        scan_expression_refs(&mut span_map, desc);
                    }
                    if let Some(with_map) = step_map.get_mapping("with") {
                        for (_, val_node) in with_map.iter() {
                            if let Some(scalar) = val_node.as_scalar() {
                                scan_expression_refs(&mut span_map, scalar);
                            }
                        }
                    }
                }
            }
        }
    }

    // Roles: mapping where keys are role IDs.
    if let Some(roles_map) = mapping.get_mapping("roles") {
        for (key_scalar, _) in roles_map.iter() {
            if let Some(span) = scalar_to_span(key_scalar) {
                span_map
                    .roles
                    .insert(RoleId::new(key_scalar.as_str()), span);
            }
        }
    }

    // Acts: sequence of mappings, each with an "id" scalar.
    if let Some(acts_seq) = mapping.get_sequence("acts") {
        for act_node in acts_seq.iter() {
            if let Some(act_map) = act_node.as_mapping() {
                if !mapping_has_key(act_map, "id") {
                    diags.push(Diagnostic {
                        path: path.map(Path::to_owned),
                        span: node_to_span(act_node),
                        severity: Severity::Error,
                        message: "Act is missing required field 'id'".to_string(),
                    });
                }
                if let Some(id_scalar) = act_map.get_scalar("id")
                    && let Some(span) = node_to_span(act_node)
                {
                    span_map.acts.insert(ActId::new(id_scalar.as_str()), span);
                }
            }
        }
    }

    // Parameters: mapping where keys are param IDs.
    if let Some(params_map) = mapping.get_mapping("parameters") {
        for (key_scalar, _) in params_map.iter() {
            if let Some(span) = scalar_to_span(key_scalar) {
                span_map
                    .params
                    .insert(ParamId::new(key_scalar.as_str()), span);
            }
        }
    }

    // Materials: mapping where keys are material IDs.
    if let Some(materials_map) = mapping.get_mapping("materials") {
        for (key_scalar, _) in materials_map.iter() {
            if let Some(span) = scalar_to_span(key_scalar) {
                span_map
                    .materials
                    .insert(MaterialId::new(key_scalar.as_str()), span);
            }
        }
    }

    // Backends: mapping where keys are backend names.
    if let Some(backends_map) = mapping.get_mapping("backends") {
        for (key_scalar, _) in backends_map.iter() {
            if let Some(span) = scalar_to_span(key_scalar) {
                span_map
                    .backends
                    .insert(key_scalar.as_str().to_string(), span);
            }
        }
    }

    // Unknown top-level key detection.
    for (key_scalar, _) in mapping.iter() {
        if !KNOWN_KEYS.contains(&key_scalar.as_str()) {
            diags.push(Diagnostic {
                path: path.map(Path::to_owned),
                span: scalar_to_span(key_scalar),
                severity: Severity::Warning,
                message: format!("unknown top-level key: '{}'", key_scalar.as_str()),
            });
        }
    }

    (span_map, diags)
}

/// Check whether a mapping node contains a key with the given name (any value type).
fn mapping_has_key(map: &marked_yaml::types::MarkedMappingNode, key: &str) -> bool {
    map.iter().any(|(k, _)| k.as_str() == key)
}

/// Extract a plain role ID from either `"${role.id}"` expression syntax or a bare ID.
fn extract_role_id(raw: &str) -> &str {
    raw.strip_prefix("${role.")
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(raw)
}

/// Scan a scalar value for `${param.X}` and `${material.X}` expression references.
///
/// For each match, a `ReferenceEntry` is pushed into `span_map.references` with the
/// span pointing at the `$` of the expression and `value_len` covering the full `${...}`.
/// This enables go-to-definition when the cursor is anywhere within an expression.
///
/// Uses simple string scanning rather than the expression parser because `material`
/// is not a valid `RefType` in the expression model — it's resolved as an artifact
/// at the IR level. The LSP needs to navigate from `${material.x}` to the material
/// declaration, so we handle it at the raw string level here.
#[allow(clippy::arithmetic_side_effects)]
fn scan_expression_refs(span_map: &mut SpanMap, scalar: &MarkedScalarNode) {
    let Some(base_span) = scalar_to_span(scalar) else {
        return;
    };
    let text = scalar.as_str();
    let mut search_from = 0;
    while let Some(rel_start) = text.get(search_from..).and_then(|s| s.find("${")) {
        let abs_start = search_from + rel_start;
        let after_open = abs_start + 2; // skip "${"
        let Some(close_offset) = text.get(after_open..).and_then(|s| s.find('}')) else {
            break;
        };
        let Some(expr_content) = text.get(after_open..after_open + close_offset) else {
            break;
        };
        let full_len = 2 + close_offset + 1; // "${" + content + "}"

        if let Some(dot_pos) = expr_content.find('.') {
            let prefix = &expr_content[..dot_pos];
            let name = &expr_content[dot_pos + 1..];
            // Only handle simple names (no nested dots like artifact.keypair.private).
            if !name.is_empty() && !name.contains('.') {
                let target = match prefix {
                    "param" => Some(ReferenceTarget::Param(ParamId::new(name))),
                    "material" => Some(ReferenceTarget::Material(MaterialId::new(name))),
                    _ => None,
                };
                if let Some(target) = target {
                    // Column is 1-indexed; abs_start is a byte offset from scalar start.
                    let col = base_span.column + abs_start;
                    span_map.references.push(ReferenceEntry {
                        span: Span {
                            line: base_span.line,
                            column: col,
                        },
                        value_len: full_len,
                        target,
                    });
                }
            }
        }
        search_from = abs_start + full_len;
    }
}

/// Push a reference entry into `span_map.references` for the given scalar value node.
fn push_reference(span_map: &mut SpanMap, val: &MarkedScalarNode, target: ReferenceTarget) {
    if let Some(span) = scalar_to_span(val) {
        span_map.references.push(ReferenceEntry {
            span,
            value_len: val.as_str().len(),
            target,
        });
    }
}

fn node_to_span(node: &Node) -> Option<Span> {
    node.span().start().map(|m| Span {
        line: m.line(),
        column: m.column(),
    })
}

fn scalar_to_span(scalar: &MarkedScalarNode) -> Option<Span> {
    scalar.span().start().map(|m| Span {
        line: m.line(),
        column: m.column(),
    })
}

fn load_error_to_diagnostic(path: Option<&Path>, err: &marked_yaml::LoadError) -> Diagnostic {
    let location = extract_load_error_location(err);
    Diagnostic {
        path: path.map(Path::to_owned),
        span: location.map(|(line, column)| Span { line, column }),
        severity: Severity::Error,
        message: err.to_string(),
    }
}

fn extract_load_error_location(err: &marked_yaml::LoadError) -> Option<(usize, usize)> {
    use marked_yaml::LoadError;
    match err {
        LoadError::TopLevelMustBeMapping(m)
        | LoadError::TopLevelMustBeSequence(m)
        | LoadError::UnexpectedAnchor(m)
        | LoadError::MappingKeyMustBeScalar(m)
        | LoadError::UnexpectedTag(m)
        | LoadError::ScanError(m, _) => Some((m.line(), m.column())),
        LoadError::DuplicateKey(_) => None,
    }
}

/// Apply YAML core schema type coercion to all `serde_json::Value` fields in a ceremony.
///
/// `marked-yaml` deserializes all YAML scalars as strings. Fields typed as `serde_json::Value`
/// (`with`, `reads`, parameter defaults) need integer/boolean/null values coerced from their
/// string representations, mirroring what `serde_yaml` did automatically via YAML core schema.
fn coerce_ceremony_json_scalars(ceremony: &mut Ceremony) {
    for section in ceremony.sections.values_mut() {
        for step in section.steps.values_mut() {
            if let Some(ref mut with) = step.with {
                coerce_yaml_scalars(with);
            }
            if let Some(ref mut reads) = step.reads {
                coerce_yaml_scalars(reads);
            }
        }
    }
    for param in ceremony.parameters.values_mut() {
        if let Some(ref mut default) = param.default {
            coerce_yaml_scalars(default);
        }
    }
}

/// Recursively coerce string scalars in a `serde_json::Value` to their proper types.
fn coerce_yaml_scalars(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) => {
            if let Some(coerced) = coerce_scalar(s) {
                *value = coerced;
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                coerce_yaml_scalars(v);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values_mut() {
                coerce_yaml_scalars(v);
            }
        }
        _ => {}
    }
}

/// Try to coerce a YAML scalar string to its typed JSON equivalent.
/// Follows YAML 1.2 core schema rules.
fn coerce_scalar(s: &str) -> Option<serde_json::Value> {
    if s == "null" || s == "~" {
        return Some(serde_json::Value::Null);
    }
    if matches!(s, "true" | "True" | "TRUE") {
        return Some(serde_json::Value::Bool(true));
    }
    if matches!(s, "false" | "False" | "FALSE") {
        return Some(serde_json::Value::Bool(false));
    }
    if let Ok(n) = s.parse::<i64>() {
        return Some(serde_json::Value::Number(n.into()));
    }
    if let Ok(f) = s.parse::<f64>()
        && let Some(n) = serde_json::Number::from_f64(f)
    {
        return Some(serde_json::Value::Number(n));
    }
    None
}

/// Convert a diagnostic back to a `ResolveError::Yaml` when needed.
pub(crate) fn diagnostic_to_resolve_error(d: Diagnostic) -> ResolveError {
    ResolveError::Yaml {
        message: d.message,
        location: d.span.map(|s| (s.line, s.column)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_CEREMONY: &str = r#"
version: "2.0"
name: "Test Ceremony"
roles: {}
sections: {}
"#;

    #[test]
    fn parses_minimal_ceremony() {
        let (ceremony, _, diags) = lower_ceremony(None, MINIMAL_CEREMONY);
        let ceremony = ceremony.expect("should parse");
        assert_eq!(ceremony.version, "2.0");
        assert_eq!(ceremony.name, "Test Ceremony");
        assert!(diags.iter().all(|d| d.severity != Severity::Error));
    }

    #[test]
    fn parses_step_with_params() {
        let yaml = r#"
version: "2.0"
name: "Test"
roles: {}
sections:
  test_section:
    name: "Test Section"
    steps:
      test_step:
        action: confirm
        with:
          message: "Are you sure?"
"#;
        let (ceremony, _, _) = lower_ceremony(None, yaml);
        let ceremony = ceremony.expect("should parse");
        let section = ceremony
            .sections
            .get("test_section")
            .expect("section exists");
        assert_eq!(section.steps.len(), 1);
        assert!(section.steps.contains_key("test_step"));
        assert!(section.steps["test_step"].with.is_some());
    }

    #[test]
    fn reports_yaml_errors_with_location() {
        let yaml = r#"
version: "2.0"
name: "Test"
  bad_indent
"#;
        let (ceremony, _, diags) = lower_ceremony(None, yaml);
        assert!(ceremony.is_none(), "should fail to parse");
        let has_error = diags.iter().any(|d| d.severity == Severity::Error);
        assert!(has_error, "should have error diagnostic");
        let has_location = diags.iter().any(|d| d.span.is_some());
        assert!(has_location, "should have location info");
    }

    #[test]
    fn extracts_step_spans() {
        let yaml = r#"
version: "2.0"
name: "Test"
roles: {}
sections:
  main:
    name: Main
    steps:
      step_one:
        action: confirm
"#;
        let (_, span_map, _) = lower_ceremony(None, yaml);
        let step_id = StepId::new("step_one");
        assert!(
            span_map.steps.contains_key(&step_id),
            "step_one should be in span map"
        );
        let span = span_map.steps[&step_id];
        assert!(span.line > 0, "span line should be set");
    }

    #[test]
    fn warns_on_unknown_top_level_key() {
        let yaml = r#"
version: "2.0"
name: "Test"
roles: {}
sections: {}
unknown_key: value
"#;
        let (_, _, diags) = lower_ceremony(None, yaml);
        let warning = diags
            .iter()
            .find(|d| d.severity == Severity::Warning && d.message.contains("unknown_key"));
        assert!(warning.is_some(), "should warn about unknown top-level key");
    }
}
