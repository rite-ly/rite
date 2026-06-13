//! YAML lowering: parse the Node tree, extract source spans, and deserialize ceremony types.

use crate::diagnostic::{
    Diagnostic, ReferenceContext, ReferenceEntry, ReferenceTarget, Severity, Span, SpanMap,
};
use crate::error::ResolveError;
use crate::schema::Ceremony;
use marked_yaml::Node;
use marked_yaml::types::MarkedScalarNode;
use rite_model::{ActId, ArtifactId, MaterialId, OutputId, ParamId, RoleId, SectionId, StepId};
use std::path::Path;

/// Maximum nesting depth accepted in ceremony YAML.
///
/// Real ceremony files nest a handful of levels; 64 is far beyond any
/// legitimate document while keeping every recursive walk over the tree
/// (deserialization, scalar coercion, expression parsing) bounded to a
/// stack depth that cannot overflow.
const MAX_YAML_DEPTH: usize = 64;

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

    // Reject pathological nesting before any recursive walk over the tree.
    // `from_node` (Step C), `coerce_yaml_scalars`, and the expression parsing
    // downstream all recurse over this structure; a crafted file with hundreds
    // of nested sequences/mappings would otherwise overflow the stack and
    // abort the process — fatal for `rite-ls`, which re-parses on every
    // keystroke. The check itself recurses, but stops descending at the cap,
    // so its own depth is bounded.
    //
    // Residual limit: `marked_yaml::parse_yaml` above also recurses while
    // building the node tree. Flow-style nesting is stopped by the scanner's
    // own recursion limit (~255 levels, reported as a normal `ScanError`),
    // but block-style nesting only overflows around ~600 levels on a 2 MiB
    // thread stack — an upstream limit this guard runs too late to prevent.
    if exceeds_max_depth(&node, 0) {
        diags.push(Diagnostic {
            path: path.map(Path::to_owned),
            span: None,
            severity: Severity::Error,
            message: format!("YAML nesting exceeds the maximum depth of {MAX_YAML_DEPTH} levels"),
        });
        return (None, SpanMap::default(), diags);
    }

    // Step B: walk spans; always runs, even if Step C fails.
    let (span_map, structural_diags) = Lowerer::new(path, yaml).walk(&node);
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
                length: None,
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

/// Walks the YAML node tree once and accumulates the [`SpanMap`] used by the LSP
/// to enrich diagnostics with source locations and to power go-to-definition.
///
/// Owning `yaml`, `path`, `span_map`, and `diags` together avoids the parameter
/// sprawl that grows every time we add a new walked field.
struct Lowerer<'src> {
    yaml: &'src str,
    path: Option<&'src Path>,
    span_map: SpanMap,
    diags: Vec<Diagnostic>,
}

impl<'src> Lowerer<'src> {
    fn new(path: Option<&'src Path>, yaml: &'src str) -> Self {
        Self {
            yaml,
            path,
            span_map: SpanMap::default(),
            diags: Vec::new(),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn walk(mut self, node: &Node) -> (SpanMap, Vec<Diagnostic>) {
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

        let Some(mapping) = node.as_mapping() else {
            return (self.span_map, self.diags);
        };

        // Sections: mapping where keys are section IDs; each section contains nested steps.
        if let Some(sections_map) = mapping.get_mapping("sections") {
            for (section_id_scalar, section_node) in sections_map.iter() {
                if let Some(span) = self.scalar_to_span(section_id_scalar) {
                    self.span_map
                        .sections
                        .insert(SectionId::new(section_id_scalar.as_str()), span);
                }

                let Some(section_map) = section_node.as_mapping() else {
                    continue;
                };

                let section_context =
                    ReferenceContext::Section(SectionId::new(section_id_scalar.as_str()));
                if let Some(val) = section_map.get_scalar("act") {
                    self.push_reference(
                        val,
                        ReferenceTarget::Act(ActId::new(val.as_str())),
                        &section_context,
                    );
                }
                if let Some(val) = section_map.get_scalar("role") {
                    self.push_reference(
                        val,
                        ReferenceTarget::Role(RoleId::new(extract_role_id(val.as_str()))),
                        &section_context,
                    );
                }
                if let Some(desc) = section_map.get_scalar("description") {
                    self.scan_expression_refs(desc, &section_context);
                }

                if let Some(steps_map) = section_map.get_mapping("steps") {
                    for (step_id_scalar, step_node) in steps_map.iter() {
                        self.walk_step(step_id_scalar, step_node);
                    }
                }
            }
        }

        // Roles: mapping where keys are role IDs.
        if let Some(roles_map) = mapping.get_mapping("roles") {
            for (key_scalar, _) in roles_map.iter() {
                if let Some(span) = self.scalar_to_span(key_scalar) {
                    self.span_map
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
                        self.diags.push(Diagnostic {
                            path: self.path.map(Path::to_owned),
                            span: node_to_span(act_node),
                            severity: Severity::Error,
                            message: "Act is missing required field 'id'".to_string(),
                        });
                    }
                    if let Some(id_scalar) = act_map.get_scalar("id")
                        && let Some(span) = node_to_span(act_node)
                    {
                        self.span_map
                            .acts
                            .insert(ActId::new(id_scalar.as_str()), span);
                    }
                }
            }
        }

        // Parameters: mapping where keys are param IDs.
        if let Some(params_map) = mapping.get_mapping("parameters") {
            for (key_scalar, _) in params_map.iter() {
                if let Some(span) = self.scalar_to_span(key_scalar) {
                    self.span_map
                        .params
                        .insert(ParamId::new(key_scalar.as_str()), span);
                }
            }
        }

        // Materials: mapping where keys are material IDs.
        if let Some(materials_map) = mapping.get_mapping("materials") {
            for (key_scalar, _) in materials_map.iter() {
                if let Some(span) = self.scalar_to_span(key_scalar) {
                    self.span_map
                        .materials
                        .insert(MaterialId::new(key_scalar.as_str()), span);
                }
            }
        }

        // Backends: mapping where keys are backend names.
        if let Some(backends_map) = mapping.get_mapping("backends") {
            for (key_scalar, backend_node) in backends_map.iter() {
                if let Some(span) = self.scalar_to_span(key_scalar) {
                    self.span_map
                        .backends
                        .insert(key_scalar.as_str().to_string(), span);
                }
                if let Some(backend_map) = backend_node.as_mapping() {
                    self.record_enum_value(backend_map, "provider");
                }
            }
        }

        // Outputs: mapping where keys are output IDs.
        if let Some(outputs_map) = mapping.get_mapping("output") {
            for (key_scalar, _) in outputs_map.iter() {
                if let Some(span) = self.scalar_to_span(key_scalar) {
                    self.span_map
                        .outputs
                        .insert(OutputId::new(key_scalar.as_str()), span);
                }
            }
        }

        // Unknown top-level key detection.
        for (key_scalar, _) in mapping.iter() {
            if !KNOWN_KEYS.contains(&key_scalar.as_str()) {
                let span = self.scalar_to_span(key_scalar);
                self.diags.push(Diagnostic {
                    path: self.path.map(Path::to_owned),
                    span,
                    severity: Severity::Warning,
                    message: format!("unknown top-level key: '{}'", key_scalar.as_str()),
                });
            }
        }

        (self.span_map, self.diags)
    }

    fn walk_step(&mut self, step_id_scalar: &MarkedScalarNode, step_node: &Node) {
        if let Some(span) = self.scalar_to_span(step_id_scalar) {
            self.span_map
                .steps
                .insert(StepId::new(step_id_scalar.as_str()), span);
        }

        let Some(step_map) = step_node.as_mapping() else {
            return;
        };

        // Validate required field.
        if !mapping_has_key(step_map, "action") {
            let span = self.scalar_to_span(step_id_scalar);
            self.diags.push(Diagnostic {
                path: self.path.map(Path::to_owned),
                span,
                severity: Severity::Error,
                message: format!(
                    "Step '{}' is missing required field 'action'",
                    step_id_scalar.as_str()
                ),
            });
        }

        self.record_enum_value(step_map, "action");

        let step_context = ReferenceContext::Step(StepId::new(step_id_scalar.as_str()));
        if let Some(val) = step_map.get_scalar("role") {
            self.push_reference(
                val,
                ReferenceTarget::Role(RoleId::new(extract_role_id(val.as_str()))),
                &step_context,
            );
        }
        if let Some(val) = step_map.get_scalar("backend") {
            self.push_reference(
                val,
                ReferenceTarget::Backend(val.as_str().to_string()),
                &step_context,
            );
        }
        if let Some(val) = step_map.get_scalar("creates") {
            let id = ArtifactId::new(extract_artifact_name(val.as_str()));
            if let Some(span) = self.scalar_to_span(val) {
                self.span_map.artifacts.insert(id.clone(), span);
            }
            self.push_reference(val, ReferenceTarget::Artifact(id), &step_context);
        }
        if let Some(reads_node) = step_map.get_node("reads") {
            self.walk_reads(reads_node, &step_context);
        }
        if let Some(desc) = step_map.get_scalar("description") {
            self.scan_expression_refs(desc, &step_context);
        }
        if let Some(with_map) = step_map.get_mapping("with") {
            for (_, val_node) in with_map.iter() {
                if let Some(scalar) = val_node.as_scalar() {
                    self.scan_expression_refs(scalar, &step_context);
                }
            }
        }
    }

    fn walk_reads(&mut self, reads_node: &Node, step_context: &ReferenceContext) {
        if let Some(scalar) = reads_node.as_scalar() {
            // Single artifact reference: `reads: "${artifact.x}"`.
            let id = ArtifactId::new(extract_artifact_name(scalar.as_str()));
            self.push_reference(scalar, ReferenceTarget::Artifact(id), step_context);
        } else if let Some(reads_map) = reads_node.as_mapping() {
            // Named inputs: `reads: { key_to_wrap: "...", wrapping_key: "..." }`.
            for (_, val_node) in reads_map.iter() {
                if let Some(scalar) = val_node.as_scalar() {
                    let id = ArtifactId::new(extract_artifact_name(scalar.as_str()));
                    self.push_reference(scalar, ReferenceTarget::Artifact(id), step_context);
                }
            }
        }
    }

    /// Scan a scalar value for `${prefix.NAME}` expression references and push a
    /// `ReferenceEntry` for each recognized prefix.
    ///
    /// `material` is handled here even though it is not a `RefType` in the model
    /// (it resolves as an artifact at the IR level): the LSP needs to navigate
    /// from `${material.x}` to the material declaration. Nested property paths
    /// like `${artifact.keypair.private}` are intentionally skipped — handle
    /// them at the expression-parser level when richer go-to-definition is needed.
    #[allow(clippy::arithmetic_side_effects)]
    fn scan_expression_refs(&mut self, scalar: &MarkedScalarNode, context: &ReferenceContext) {
        let Some(base) = self.scalar_to_span(scalar) else {
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
                if !name.is_empty() && !name.contains('.') {
                    let target = match prefix {
                        "param" => Some(ReferenceTarget::Param(ParamId::new(name))),
                        "material" => Some(ReferenceTarget::Material(MaterialId::new(name))),
                        "artifact" => Some(ReferenceTarget::Artifact(ArtifactId::new(name))),
                        "role" => Some(ReferenceTarget::Role(RoleId::new(name))),
                        _ => None,
                    };
                    if let Some(target) = target {
                        let value = text
                            .get(abs_start..abs_start + full_len)
                            .unwrap_or("")
                            .to_string();
                        self.span_map.references.push(ReferenceEntry {
                            span: Span {
                                line: base.line,
                                column: base.column + abs_start,
                                length: Some(full_len),
                            },
                            target,
                            context: context.clone(),
                            value,
                        });
                    }
                }
            }
            search_from = abs_start + full_len;
        }
    }

    /// Push a reference entry for a scalar value node (for fields like `role:`,
    /// `backend:`, `act:`, `creates:`, `reads:`).
    fn push_reference(
        &mut self,
        val: &MarkedScalarNode,
        target: ReferenceTarget,
        context: &ReferenceContext,
    ) {
        if let Some(span) = self.scalar_to_span(val) {
            self.span_map.references.push(ReferenceEntry {
                span,
                target,
                context: context.clone(),
                value: val.as_str().to_string(),
            });
        }
    }

    /// Build a `Span` for a scalar value, with column at the first content character
    /// and length covering the scalar text.
    ///
    /// Record the value span of a mapping entry whose value picks from a
    /// fixed enum (currently `action:` and `provider:`). Silently skips
    /// if the key is absent or the value is not a scalar.
    fn record_enum_value(&mut self, map: &marked_yaml::types::MarkedMappingNode, key: &str) {
        if let Some(scalar) = map.get_scalar(key)
            && let Some(span) = self.scalar_to_span(scalar)
        {
            self.span_map.enum_values.push(span);
        }
    }

    /// For quoted scalars `marked_yaml` places the START marker at the opening quote,
    /// but `scalar.as_str()` returns the content without the quotes, so we shift the
    /// column by 1 when the source byte is `"` or `'`. This keeps byte offsets within
    /// `as_str()` aligned with source characters for both quoted and unquoted scalars.
    fn scalar_to_span(&self, scalar: &MarkedScalarNode) -> Option<Span> {
        let m = scalar.span().start()?;
        let is_quoted = self
            .yaml
            .as_bytes()
            .get(m.character())
            .is_some_and(|&b| b == b'"' || b == b'\'');
        let column = if is_quoted {
            m.column().saturating_add(1)
        } else {
            m.column()
        };
        Some(Span {
            line: m.line(),
            column,
            length: Some(scalar.as_str().len()),
        })
    }
}

/// Check whether a mapping node contains a key with the given name (any value type).
fn mapping_has_key(map: &marked_yaml::types::MarkedMappingNode, key: &str) -> bool {
    map.iter().any(|(k, _)| k.as_str() == key)
}

/// Check whether the node tree nests deeper than [`MAX_YAML_DEPTH`].
///
/// Returns as soon as the cap is hit, so the recursion here is bounded to
/// `MAX_YAML_DEPTH` frames regardless of input.
fn exceeds_max_depth(node: &Node, depth: usize) -> bool {
    if depth >= MAX_YAML_DEPTH {
        return true;
    }
    let child_depth = depth.saturating_add(1);
    if let Some(map) = node.as_mapping() {
        map.iter().any(|(_, v)| exceeds_max_depth(v, child_depth))
    } else if let Some(seq) = node.as_sequence() {
        seq.iter().any(|v| exceeds_max_depth(v, child_depth))
    } else {
        false
    }
}

/// Extract a plain role ID from either `"${role.id}"` expression syntax or a bare ID.
fn extract_role_id(raw: &str) -> &str {
    raw.strip_prefix("${role.")
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(raw)
}

/// Extract a plain artifact name from either `"${artifact.name}"` syntax or a bare name.
fn extract_artifact_name(raw: &str) -> &str {
    raw.strip_prefix("${artifact.")
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(raw)
}

fn node_to_span(node: &Node) -> Option<Span> {
    node.span().start().map(|m| Span {
        line: m.line(),
        column: m.column(),
        length: None,
    })
}

fn load_error_to_diagnostic(path: Option<&Path>, err: &marked_yaml::LoadError) -> Diagnostic {
    let location = extract_load_error_location(err);
    Diagnostic {
        path: path.map(Path::to_owned),
        span: location.map(|(line, column)| Span {
            line,
            column,
            length: None,
        }),
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
    coerce_yaml_scalars_at(value, 0);
}

/// Depth-tracking worker for [`coerce_yaml_scalars`].
///
/// The depth guard in `lower_ceremony` already rejects trees nested past
/// [`MAX_YAML_DEPTH`], so the cap here is a defensive backstop: values deeper
/// than the cap are left uncoerced rather than recursed into.
fn coerce_yaml_scalars_at(value: &mut serde_json::Value, depth: usize) {
    if depth >= MAX_YAML_DEPTH {
        return;
    }
    let child_depth = depth.saturating_add(1);
    match value {
        serde_json::Value::String(s) => {
            if let Some(coerced) = coerce_scalar(s) {
                *value = coerced;
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                coerce_yaml_scalars_at(v, child_depth);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values_mut() {
                coerce_yaml_scalars_at(v, child_depth);
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
    use crate::test_helpers::{annotate, span_text};

    #[test]
    fn declaration_spans_cover_full_identifier() {
        // This test verifies that every declaration span carries the token length so
        // that editors underline the full identifier, not just the first character.
        let yaml = r#"
version: "0.2"
name: "Test"
roles:
  alice: {}
parameters:
  my_param:
    type: text
sections:
  main:
    steps:
      my_step:
        action: confirm
"#;
        let (_, span_map, _) = lower_ceremony(None, yaml);

        let alice = *span_map
            .roles
            .get(&RoleId::new("alice"))
            .expect("alice role span");
        assert_eq!(
            annotate(yaml, alice),
            "  alice: {}\n  ^^^^^",
            "role span must cover the full identifier"
        );

        let my_param = *span_map
            .params
            .get(&ParamId::new("my_param"))
            .expect("my_param span");
        assert_eq!(
            annotate(yaml, my_param),
            "  my_param:\n  ^^^^^^^^",
            "parameter span must cover the full identifier"
        );

        let main = *span_map
            .sections
            .get(&SectionId::new("main"))
            .expect("main section span");
        assert_eq!(
            annotate(yaml, main),
            "  main:\n  ^^^^",
            "section span must cover the full identifier"
        );

        let my_step = *span_map
            .steps
            .get(&StepId::new("my_step"))
            .expect("my_step span");
        assert_eq!(
            annotate(yaml, my_step),
            "      my_step:\n      ^^^^^^^",
            "step span must cover the full identifier"
        );
    }

    #[test]
    fn unknown_top_level_key_warning_covers_full_key() {
        let yaml = r#"
version: "0.2"
name: "Test"
roles: {}
sections: {}
unknown_key: value
"#;
        let (_, _, diags) = lower_ceremony(None, yaml);
        let warning = diags
            .iter()
            .find(|d| d.message.contains("unknown_key"))
            .expect("should have unknown key warning");
        let span = warning.span.expect("warning must have a span");
        assert_eq!(
            annotate(yaml, span),
            "unknown_key: value\n^^^^^^^^^^^",
            "unknown key warning must cover the full key name"
        );
    }

    #[test]
    fn expression_param_ref_span_covers_full_expression() {
        let yaml = r#"
version: "0.2"
name: "Test"
roles: {}
parameters:
  x:
    type: text
sections:
  main:
    steps:
      my_step:
        action: confirm
        description: "${param.x}"
"#;
        let (_, span_map, _) = lower_ceremony(None, yaml);

        let entry = span_map
            .references
            .iter()
            .find(|e| matches!(&e.target, ReferenceTarget::Param(id) if id.as_str() == "x"))
            .expect("should have a reference entry for param 'x'");

        assert_eq!(
            span_text(yaml, entry.span),
            "${param.x}",
            "expression span must cover the full ${{...}} token"
        );
        assert_eq!(entry.span.length, Some(10));
    }

    #[test]
    fn material_declaration_span_covers_full_identifier() {
        let yaml = r#"
version: "0.2"
name: "Test"
roles: {}
sections: {}
materials:
  my_material:
    type: digital
"#;
        let (_, span_map, _) = lower_ceremony(None, yaml);
        let span = *span_map
            .materials
            .get(&MaterialId::new("my_material"))
            .expect("my_material span");
        assert_eq!(
            annotate(yaml, span),
            "  my_material:\n  ^^^^^^^^^^^",
            "material span must cover the full identifier"
        );
    }

    #[test]
    fn backend_declaration_span_covers_full_identifier() {
        let yaml = r#"
version: "0.2"
name: "Test"
roles: {}
sections: {}
backends:
  ssl:
    provider: openssl
"#;
        let (_, span_map, _) = lower_ceremony(None, yaml);
        let span = *span_map.backends.get("ssl").expect("ssl backend span");
        assert_eq!(
            annotate(yaml, span),
            "  ssl:\n  ^^^",
            "backend span must cover the full identifier"
        );
    }

    #[test]
    fn output_declaration_span_covers_full_identifier() {
        let yaml = r#"
version: "0.2"
name: "Test"
roles: {}
sections: {}
output:
  signed_cert:
    type: artifact
"#;
        let (_, span_map, _) = lower_ceremony(None, yaml);
        let span = *span_map
            .outputs
            .get(&OutputId::new("signed_cert"))
            .expect("signed_cert output span");
        assert_eq!(
            annotate(yaml, span),
            "  signed_cert:\n  ^^^^^^^^^^^",
            "output span must cover the full identifier"
        );
    }

    #[test]
    fn quoted_declaration_key_span_skips_opening_quote() {
        // Regression: quoted YAML keys used to mis-report column at the `"`,
        // making the underlined slice include the opening quote and miss the
        // last character of the identifier.
        let yaml = "
version: \"0.2\"
name: \"Test\"
roles:
  \"alice\": {}
sections: {}
";
        let (_, span_map, _) = lower_ceremony(None, yaml);
        let span = *span_map
            .roles
            .get(&RoleId::new("alice"))
            .expect("alice role span");
        assert_eq!(
            span_text(yaml, span),
            "alice",
            "quoted role key span must underline the identifier, not the opening quote"
        );
    }

    #[test]
    fn role_field_unquoted_value_records_reference_with_full_span() {
        let yaml = r#"
version: "0.2"
name: "Test"
roles:
  alice: {}
sections:
  main:
    steps:
      my_step:
        action: confirm
        role: "${role.alice}"
"#;
        let (_, span_map, _) = lower_ceremony(None, yaml);
        let entry = span_map
            .references
            .iter()
            .find(|e| matches!(&e.target, ReferenceTarget::Role(id) if id.as_str() == "alice"))
            .expect("should have a Role reference for alice");
        assert_eq!(span_text(yaml, entry.span), "${role.alice}");
        assert_eq!(entry.value, "${role.alice}");
    }

    #[test]
    fn material_expression_ref_span_covers_full_token() {
        let yaml = r#"
version: "0.2"
name: "Test"
roles: {}
materials:
  my_material:
    type: digital
sections:
  main:
    steps:
      my_step:
        action: confirm
        description: "see ${material.my_material} for details"
"#;
        let (_, span_map, _) = lower_ceremony(None, yaml);
        let entry = span_map
            .references
            .iter()
            .find(
                |e| matches!(&e.target, ReferenceTarget::Material(id) if id.as_str() == "my_material"),
            )
            .expect("should have a Material reference entry");
        assert_eq!(span_text(yaml, entry.span), "${material.my_material}");
    }

    #[test]
    fn unterminated_expression_does_not_panic() {
        let yaml = r#"
version: "0.2"
name: "Test"
roles: {}
sections:
  main:
    steps:
      my_step:
        action: confirm
        description: "${param.x"
"#;
        let (_, span_map, _) = lower_ceremony(None, yaml);
        assert!(
            !span_map
                .references
                .iter()
                .any(|e| matches!(e.target, ReferenceTarget::Param(_))),
            "unterminated expression must not produce a reference entry"
        );
    }

    #[test]
    fn creates_field_records_artifact_reference_and_artifact_span() {
        let yaml = r#"
version: "0.2"
name: "Test"
roles: {}
sections:
  main:
    steps:
      gen_step:
        action: confirm
        creates: "${artifact.keypair}"
"#;
        let (_, span_map, _) = lower_ceremony(None, yaml);

        // Reference entry recorded against the step.
        let entry = span_map
            .references
            .iter()
            .find(
                |e| matches!(&e.target, ReferenceTarget::Artifact(id) if id.as_str() == "keypair"),
            )
            .expect("should have an Artifact reference for keypair");
        assert_eq!(span_text(yaml, entry.span), "${artifact.keypair}");

        // Artifact span is recorded so `ArtifactNotOutput` warnings can underline it.
        let artifact_span = *span_map
            .artifacts
            .get(&ArtifactId::new("keypair"))
            .expect("keypair artifact span");
        assert_eq!(span_text(yaml, artifact_span), "${artifact.keypair}");
    }

    #[test]
    fn reads_named_inputs_record_artifact_references() {
        let yaml = r#"
version: "0.2"
name: "Test"
roles: {}
sections:
  main:
    steps:
      use_step:
        action: confirm
        reads:
          first: "${artifact.alpha}"
          second: "${artifact.beta}"
"#;
        let (_, span_map, _) = lower_ceremony(None, yaml);
        let names: Vec<&str> = span_map
            .references
            .iter()
            .filter_map(|e| match &e.target {
                ReferenceTarget::Artifact(id) => Some(id.as_str()),
                _ => None,
            })
            .collect();
        assert!(names.contains(&"alpha"));
        assert!(names.contains(&"beta"));
    }

    #[test]
    fn reads_string_form_records_artifact_reference() {
        let yaml = r#"
version: "0.2"
name: "Test"
roles: {}
sections:
  main:
    steps:
      use_step:
        action: confirm
        reads: "${artifact.alpha}"
"#;
        let (_, span_map, _) = lower_ceremony(None, yaml);
        let entry = span_map
            .references
            .iter()
            .find(|e| matches!(&e.target, ReferenceTarget::Artifact(id) if id.as_str() == "alpha"))
            .expect("should record a single artifact reference for string-form reads");
        assert_eq!(span_text(yaml, entry.span), "${artifact.alpha}");
    }

    #[test]
    fn expression_artifact_ref_in_description_is_recorded() {
        let yaml = r#"
version: "0.2"
name: "Test"
roles: {}
sections:
  main:
    steps:
      my_step:
        action: confirm
        description: "uses ${artifact.foo}"
"#;
        let (_, span_map, _) = lower_ceremony(None, yaml);
        let entry = span_map
            .references
            .iter()
            .find(|e| matches!(&e.target, ReferenceTarget::Artifact(id) if id.as_str() == "foo"))
            .expect("scan_expression_refs must now handle the `artifact` prefix");
        assert_eq!(span_text(yaml, entry.span), "${artifact.foo}");
    }

    const MINIMAL_CEREMONY: &str = r#"
version: "0.2"
name: "Test Ceremony"
roles: {}
sections: {}
"#;

    #[test]
    fn parses_minimal_ceremony() {
        let (ceremony, _, diags) = lower_ceremony(None, MINIMAL_CEREMONY);
        let ceremony = ceremony.expect("should parse");
        assert_eq!(ceremony.version, "0.2");
        assert_eq!(ceremony.name, "Test Ceremony");
        assert!(diags.iter().all(|d| d.severity != Severity::Error));
    }

    #[test]
    fn parses_step_with_params() {
        let yaml = r#"
version: "0.2"
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
        assert!(
            section
                .steps
                .get("test_step")
                .expect("test_step should exist")
                .with
                .is_some()
        );
    }

    #[test]
    fn reports_yaml_errors_with_location() {
        let yaml = r#"
version: "0.2"
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
version: "0.2"
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
        let span = span_map
            .steps
            .get(&step_id)
            .expect("step_one should be in span map");
        assert!(span.line > 0, "span line should be set");
    }

    /// Ceremony YAML with a flow sequence nested `depth` levels under `with:`.
    fn ceremony_with_nested_payload(depth: usize) -> String {
        let nested = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        format!(
            "version: \"0.2\"\n\
             name: \"Test\"\n\
             roles: {{}}\n\
             sections:\n\
            \x20 main:\n\
            \x20   steps:\n\
            \x20     s1:\n\
            \x20       action: confirm\n\
            \x20       with:\n\
            \x20         payload: {nested}\n"
        )
    }

    #[test]
    fn deeply_nested_flow_yaml_is_rejected_with_diagnostic() {
        // 150 levels: beyond our cap (64) but within the marked-yaml scanner's
        // own flow recursion limit (~255), so parsing succeeds and our depth
        // guard must reject the tree instead of letting the recursive walks
        // overflow the stack.
        let yaml = ceremony_with_nested_payload(150);
        let (ceremony, _, diags) = lower_ceremony(None, &yaml);
        assert!(ceremony.is_none(), "deeply nested ceremony must not parse");
        let error = diags
            .iter()
            .find(|d| d.severity == Severity::Error)
            .expect("should have an error diagnostic");
        assert!(
            error.message.contains("nesting exceeds"),
            "diagnostic should mention the depth limit: {}",
            error.message
        );
    }

    #[test]
    fn deeply_nested_block_yaml_is_rejected_with_diagnostic() {
        // Block-style mappings nested 150 levels; the scanner's flow recursion
        // limit does not apply to block style, so the depth guard is the only
        // thing standing between this input and the recursive walks.
        let mut yaml = String::from(
            "version: \"0.2\"\nname: \"Test\"\nroles: {}\nsections:\n  main:\n    steps:\n      s1:\n        action: confirm\n        with:\n",
        );
        for i in 0..150 {
            yaml.push_str(&" ".repeat(10 + i));
            yaml.push_str("k:\n");
        }
        yaml.push_str(&" ".repeat(160));
        yaml.push_str("leaf: 0\n");

        let (ceremony, _, diags) = lower_ceremony(None, &yaml);
        assert!(ceremony.is_none(), "deeply nested ceremony must not parse");
        assert!(
            diags
                .iter()
                .any(|d| d.severity == Severity::Error && d.message.contains("nesting exceeds")),
            "should have a depth-limit error diagnostic"
        );
    }

    #[test]
    fn moderate_nesting_is_accepted() {
        let yaml = ceremony_with_nested_payload(10);
        let (ceremony, _, diags) = lower_ceremony(None, &yaml);
        assert!(ceremony.is_some(), "10 levels of nesting must parse");
        assert!(diags.iter().all(|d| d.severity != Severity::Error));
    }

    #[test]
    fn warns_on_unknown_top_level_key() {
        let yaml = r#"
version: "0.2"
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
