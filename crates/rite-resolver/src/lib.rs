//! Ceremony resolver: parse YAML, validate, and produce IR.
//!
//! This crate transforms ceremony YAML into the [`rite_model::Ceremony`] IR
//! ready for execution. It owns the YAML schema (AST types), the lowering
//! pipeline, and the resolution pass.
//!
//! # Usage
//!
//! ```
//! use rite_resolver::resolve;
//!
//! let ceremony_yaml = r#"
//! version: "0.2"
//! name: "Example Ceremony"
//! roles: {}
//! sections: {}
//! "#;
//!
//! // Resolve from a string (no execution-time inputs).
//! let result = resolve(ceremony_yaml, None);
//! assert!(result.is_ok(), "ceremony should resolve: {:?}", result.errors);
//! ```
//!
//! For a file with rich, span-anchored diagnostics, use [`analyze`]; for a
//! ceremony plus its included files, use [`resolve_files`].

#![warn(missing_docs)]

mod diagnostic;
mod error;
mod lower;
mod resolve;
mod schema;
mod serde_utils;

#[cfg(test)]
pub(crate) mod test_helpers;

pub use diagnostic::{
    Diagnostic, ReferenceContext, ReferenceEntry, ReferenceTarget, Severity, Span, SpanMap,
};
pub use error::{ResolveError, ResolveResult, ResolveWarning};

use rite_model::MaterialSource;
use std::collections::HashMap;
use std::path::Path;

/// External inputs collected from CLI flags (`--param`, `--role`, `--material`)
/// and environment variables (`RITE_PARAM_*`, `RITE_ROLE_*`, `RITE_MATERIAL_*`).
///
/// These are merged with ceremony-level defaults during resolution.
#[derive(Debug, Clone, Default)]
pub struct CeremonyInputs {
    /// Parameter values keyed by parameter name.
    ///
    /// Values arrive as strings from CLI/env and are coerced to the declared
    /// type by the resolver.
    pub parameters: HashMap<String, serde_json::Value>,

    /// Role person assignments: `role_id` → person name.
    pub roles: HashMap<String, String>,

    /// Material sources keyed by material name.
    pub materials: HashMap<String, MaterialSource>,
}

impl CeremonyInputs {
    /// Returns `true` if no parameters, roles, or materials have been provided.
    pub fn is_empty(&self) -> bool {
        self.parameters.is_empty() && self.roles.is_empty() && self.materials.is_empty()
    }
}

/// Resolve `path:` values in digital materials against the ceremony file's directory,
/// confining them to that directory's subtree.
///
/// Called after `lower_ceremony` succeeds. Paths embedded in the ceremony file are
/// untrusted (the file may have been authored elsewhere), so a `path:` that is absolute
/// or climbs out of the ceremony directory via `..` is rejected rather than read.
/// Out-of-tree files are still reachable by passing `--material name=@/path`, which is
/// operator-supplied and resolved relative to CWD in `parse_material_value` — those never
/// reach this function.
///
/// Returns one [`ResolveError::UnsafeMaterialPath`] per rejected path; the caller surfaces
/// them alongside resolution errors.
fn resolve_material_paths(
    ceremony: &mut schema::Ceremony,
    ceremony_path: &Path,
) -> Vec<ResolveError> {
    let dir = ceremony_path.parent().unwrap_or_else(|| Path::new("."));
    let mut errors = Vec::new();
    for (name, material) in &mut ceremony.materials {
        if let schema::Material::Digital {
            path: Some(ref mut p),
            ..
        } = *material
        {
            match rite_model::confine(dir, p) {
                Ok(confined) => *p = confined,
                Err(e) => errors.push(ResolveError::UnsafeMaterialPath {
                    material: rite_model::MaterialId::new(name.as_str()),
                    path: std::mem::take(p),
                    reason: e.to_string(),
                }),
            }
        }
    }
    errors
}

/// Confine material `path:` values, resolve the ceremony, and fold any path
/// errors into the result.
///
/// Shared by [`resolve_files`] and [`analyze`], which both own a lowered
/// ceremony and need its embedded paths confined before resolution. A non-empty
/// set of path errors fails the result, so `value` is cleared alongside.
fn resolve_with_material_paths(
    mut ceremony: schema::Ceremony,
    ceremony_path: &Path,
    inputs: Option<&CeremonyInputs>,
) -> ResolveResult<rite_model::Ceremony> {
    let path_errors = resolve_material_paths(&mut ceremony, ceremony_path);
    let mut result = resolve::resolve_ceremony(ceremony, inputs);
    if !path_errors.is_empty() {
        result.value = None;
        result.errors.extend(path_errors);
    }
    result
}

/// Extract the first error diagnostic as a `ResolveError`, or return a generic parse failure.
fn first_resolve_error(diags: Vec<Diagnostic>) -> ResolveError {
    diags
        .into_iter()
        .find(|d| d.severity == Severity::Error)
        .map_or_else(
            || ResolveError::Yaml {
                message: "Failed to parse ceremony YAML".into(),
                location: None,
            },
            lower::diagnostic_to_resolve_error,
        )
}

/// Parse and resolve a ceremony from a YAML string.
///
/// This is the main entry point for resolution when no file paths are available.
pub fn resolve(
    ceremony_yaml: &str,
    inputs: Option<&CeremonyInputs>,
) -> ResolveResult<rite_model::Ceremony> {
    let (ceremony_opt, _span_map, diags) = lower::lower_ceremony(None, ceremony_yaml);

    let Some(ceremony) = ceremony_opt else {
        return ResolveResult::err(first_resolve_error(diags));
    };

    resolve::resolve_ceremony(ceremony, inputs)
}

/// Parse and resolve a ceremony from a file path.
///
/// Like [`resolve`], but reads YAML from disk and resolves relative `path:`
/// values in digital materials against the ceremony file's directory.
pub fn resolve_files(
    ceremony_path: &Path,
    inputs: Option<&CeremonyInputs>,
) -> ResolveResult<rite_model::Ceremony> {
    let yaml = match std::fs::read_to_string(ceremony_path) {
        Ok(s) => s,
        Err(e) => {
            return ResolveResult::err(ResolveError::Io {
                path: ceremony_path.to_owned(),
                message: e.to_string(),
            });
        }
    };

    let (ceremony_opt, _span_map, diags) = lower::lower_ceremony(Some(ceremony_path), &yaml);

    let Some(ceremony) = ceremony_opt else {
        return ResolveResult::err(first_resolve_error(diags));
    };

    resolve_with_material_paths(ceremony, ceremony_path, inputs)
}

/// Parse and validate ceremony YAML from an in-memory string.
///
/// Returns the resolved ceremony, span map, and diagnostics. Used by the LSP
/// to avoid file I/O and support hover/completion.
pub fn analyze_str(
    path: Option<&Path>,
    yaml: &str,
) -> (Option<rite_model::Ceremony>, SpanMap, Vec<Diagnostic>) {
    let (ceremony_opt, span_map, mut diags) = lower::lower_ceremony(path, yaml);

    let Some(ceremony) = ceremony_opt else {
        return (None, span_map, diags);
    };

    let result = resolve::resolve_ceremony(ceremony, None);

    for e in &result.errors {
        diags.push(span_map.to_diagnostic(path, e));
    }
    for w in &result.warnings {
        diags.push(span_map.warning_to_diagnostic(path, w));
    }

    (result.into_result().ok(), span_map, diags)
}

/// Parse and validate a ceremony file, returning both the resolved ceremony and diagnostics.
///
/// Returns `(Some(resolved), diags)` on success (diags may contain warnings).
/// Returns `(None, diags)` when errors prevent resolution.
///
/// Error diagnostics include `file:line:col: error: message` formatting for display.
pub fn analyze(
    ceremony_path: &Path,
    inputs: Option<&CeremonyInputs>,
) -> (Option<rite_model::Ceremony>, Vec<Diagnostic>) {
    let yaml = match std::fs::read_to_string(ceremony_path) {
        Ok(s) => s,
        Err(e) => {
            return (
                None,
                vec![Diagnostic {
                    path: Some(ceremony_path.to_owned()),
                    span: None,
                    severity: Severity::Error,
                    message: format!("cannot read file: {e}"),
                }],
            );
        }
    };

    let (ceremony_opt, span_map, mut diags) = lower::lower_ceremony(Some(ceremony_path), &yaml);

    let Some(ceremony) = ceremony_opt else {
        return (None, diags);
    };

    let result = resolve_with_material_paths(ceremony, ceremony_path, inputs);

    for e in &result.errors {
        diags.push(span_map.to_diagnostic(Some(ceremony_path), e));
    }
    for w in &result.warnings {
        diags.push(span_map.warning_to_diagnostic(Some(ceremony_path), w));
    }

    let resolved = result.into_result().ok();
    (resolved, diags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::span_text;
    use rite_model::{ParamId, RoleId};

    #[test]
    fn rejects_material_path_escaping_ceremony_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ceremony_path = dir.path().join("c.rite.yaml");
        std::fs::write(
            &ceremony_path,
            r#"
version: "0.2"
name: "Test"
roles: {}
sections: {}
materials:
  leaked:
    type: digital
    path: "../../../../etc/passwd"
"#,
        )
        .expect("write ceremony");

        let result = resolve_files(&ceremony_path, None);
        assert!(result.is_err());
        assert!(
            result
                .errors
                .iter()
                .any(|e| matches!(e, ResolveError::UnsafeMaterialPath { .. })),
            "expected UnsafeMaterialPath, got {:?}",
            result.errors
        );
    }

    #[test]
    fn confines_relative_material_path_to_ceremony_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ceremony_path = dir.path().join("c.rite.yaml");
        std::fs::write(
            &ceremony_path,
            r#"
version: "0.2"
name: "Test"
roles: {}
sections: {}
materials:
  local:
    type: digital
    path: "keys/root.pem"
"#,
        )
        .expect("write ceremony");

        let result = resolve_files(&ceremony_path, None);
        assert!(result.is_ok(), "Errors: {:?}", result.errors);
    }

    #[test]
    fn resolve_minimal_ceremony() {
        let yaml = r#"
version: "0.2"
name: "Test Ceremony"
roles: {}
sections: {}
"#;
        let result = resolve(yaml, None);
        assert!(result.is_ok(), "Errors: {:?}", result.errors);

        let resolved = result.into_result().unwrap();
        assert_eq!(resolved.metadata.name, "Test Ceremony");
        assert!(resolved.execution_plan.is_empty());
    }

    #[test]
    fn resolve_with_roles_and_steps() {
        let yaml = r#"
version: "0.2"
name: "Test"
roles:
  admin:
    name: Administrator
sections:
  main:
    name: Main Section
    steps:
      step1:
        action: confirm
        role: "${role.admin}"
        with:
          message: "Ready?"
"#;
        let result = resolve(yaml, None);
        assert!(result.is_ok(), "Errors: {:?}", result.errors);

        let resolved = result.into_result().unwrap();
        assert_eq!(resolved.roles.len(), 1);
        assert_eq!(resolved.execution_plan.len(), 1);
        assert_eq!(
            resolved
                .execution_plan
                .first()
                .expect("should have first step")
                .role,
            Some(RoleId::new("admin"))
        );
    }

    #[test]
    fn resolve_with_input_parameters() {
        let ceremony = r#"
version: "0.2"
name: "Test"
roles: {}
sections:
  main:
    steps:
      step1:
        action: confirm
parameters:
  ceremony_name:
    type: string
"#;
        let inputs = CeremonyInputs {
            parameters: {
                let mut m = std::collections::HashMap::new();
                m.insert(
                    "ceremony_name".to_string(),
                    serde_json::json!("Production Ceremony"),
                );
                m
            },
            ..Default::default()
        };
        let result = resolve(ceremony, Some(&inputs));
        assert!(result.is_ok(), "Errors: {:?}", result.errors);

        let resolved = result.into_result().unwrap();
        let param = resolved
            .parameters
            .get(&ParamId::new("ceremony_name"))
            .unwrap();
        assert_eq!(param.value, serde_json::json!("Production Ceremony"));
    }

    #[test]
    fn fails_on_missing_required_parameter() {
        let ceremony = r#"
version: "0.2"
name: "Test"
roles: {}
sections: {}
parameters:
  required_param:
    type: string
"#;
        let inputs = CeremonyInputs::default();
        let result = resolve(ceremony, Some(&inputs));
        assert!(result.is_err());
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ResolveError::RequiredParamMissing(id) if id.as_str() == "required_param"
        )));
    }

    #[test]
    fn allows_missing_required_parameter_without_inputs() {
        let ceremony = r#"
version: "0.2"
name: "Test"
roles: {}
sections: {}
parameters:
  required_param:
    type: string
"#;
        let result = resolve(ceremony, None);
        assert!(result.is_ok(), "Errors: {:?}", result.errors);
    }

    #[test]
    fn fails_on_unknown_role_reference() {
        let yaml = r#"
version: "0.2"
name: "Test"
roles: {}
sections:
  main:
    steps:
      step1:
        action: confirm
        role: "${role.nonexistent}"
"#;
        let result = resolve(yaml, None);
        assert!(result.is_err());
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ResolveError::UnknownRole { role, .. } if role.as_str() == "nonexistent"
        )));
    }

    #[test]
    fn invalid_role_ref_diagnostic_spans_the_expression_not_the_step() {
        // When `role: "${xxxx}"` fails to parse as a valid role reference, the
        // diagnostic must underline "${xxxx}" — the expression that is wrong —
        // not the step key "my_step" where the reference happens to live.
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
        role: "${xxxx}"
"#;
        let (_, _, diags) = analyze_str(None, yaml);
        let diag = diags
            .iter()
            .find(|d| d.message.contains("Invalid reference syntax"))
            .expect("should have an InvalidReferenceSyntax diagnostic");
        let span = diag.span.expect("diagnostic must have a span");

        // The span must cover "${xxxx}" (7 chars), not "my_step" or any other token.
        assert_eq!(
            span_text(yaml, span),
            "${xxxx}",
            "diagnostic should underline the bad expression, not the enclosing step key"
        );
    }

    #[test]
    fn unknown_role_diagnostic_spans_the_full_expression() {
        // When `role: "${role.ghost}"` references a role that does not exist,
        // the diagnostic must underline the entire "${role.ghost}" expression.
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
        role: "${role.ghost}"
"#;
        let (_, _, diags) = analyze_str(None, yaml);
        let diag = diags
            .iter()
            .find(|d| d.message.contains("Unknown role") && d.message.contains("ghost"))
            .expect("should have an UnknownRole diagnostic");
        let span = diag.span.expect("diagnostic must have a span");

        // Must cover "${role.ghost}" (13 chars), not just "ghost".
        assert_eq!(
            span_text(yaml, span),
            "${role.ghost}",
            "diagnostic should underline the full expression including the ${{...}} delimiters"
        );
    }

    #[test]
    fn missing_action_diagnostic_spans_step_id_with_full_length() {
        // The "step is missing required field 'action'" diagnostic must point at
        // the step key ("my_step") with its full length, so editors can underline
        // the identifier rather than showing a zero-width squiggly.
        let yaml = r#"
version: "0.2"
name: "Test"
roles: {}
sections:
  main:
    steps:
      my_step:
        description: "hello"
"#;
        let (_, _, diags) = analyze_str(None, yaml);
        let diag = diags
            .iter()
            .find(|d| d.message.contains("missing required field 'action'"))
            .expect("should have a missing-action diagnostic");
        let span = diag.span.expect("diagnostic must have a span");

        // Must cover "my_step" — the step ID key — not "description" or empty.
        assert_eq!(
            span_text(yaml, span),
            "my_step",
            "missing-action diagnostic should underline the step key with its full length"
        );
    }

    #[test]
    fn missing_required_backend_diagnostic_spans_step_id() {
        let yaml = r#"
version: "0.2"
name: "Test"
roles: {}
sections:
  main:
    steps:
      gen:
        action: generate_keypair
"#;
        let (_, _, diags) = analyze_str(None, yaml);
        let diag = diags
            .iter()
            .find(|d| d.message.contains("requires a backend"))
            .expect("should have a missing-backend diagnostic");
        let span = diag.span.expect("diagnostic must have a span");
        assert_eq!(span_text(yaml, span), "gen");
    }

    #[test]
    fn artifact_reference_type_mismatch_diagnostic_spans_the_expression() {
        // Artifact-typed `reads:` field given a role-typed expression. The
        // generic value-span lookup must find the entry pushed by the
        // `reads:` walk and underline the expression — not the step key.
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
        reads: "${role.alice}"
"#;
        let (_, _, diags) = analyze_str(None, yaml);
        let diag = diags
            .iter()
            .find(|d| d.message.contains("Reference type mismatch"))
            .expect("should have a ReferenceTypeMismatch diagnostic");
        let span = diag.span.expect("diagnostic must have a span");
        assert_eq!(span_text(yaml, span), "${role.alice}");
    }

    // ── span_for_error dispatch coverage ──────────────────────────────────────
    //
    // These tests exercise `SpanMap::to_diagnostic` directly so each `ResolveError`
    // variant can be span-checked without having to construct YAML that triggers
    // the variant through resolution. Add a row here whenever a new variant lands.
    //
    // TODO: collapse into a `&[SpanCase { name, make_err, expected }]` table once
    // the variant count grows; pair with the exhaustiveness sentinel in
    // `diagnostic.rs::span_for_error` so missing rows fail fast.

    use crate::diagnostic::{Severity, SpanMap};
    use rite_model::{ActId, ArtifactId, MaterialId, OutputId, SectionId, StepId};

    fn span_map_for(yaml: &str) -> SpanMap {
        let (_, span_map, _) = analyze_str(None, yaml);
        span_map
    }

    fn dispatch_span_text(yaml: &str, span_map: &SpanMap, err: &ResolveError) -> String {
        let diag = span_map.to_diagnostic(None, err);
        assert_eq!(diag.severity, Severity::Error);
        let span = diag
            .span
            .unwrap_or_else(|| panic!("dispatch returned no span for {err:?}"));
        span_text(yaml, span).to_string()
    }

    fn dispatch_warning_span_text(
        yaml: &str,
        span_map: &SpanMap,
        warning: &ResolveWarning,
    ) -> String {
        let diag = span_map.warning_to_diagnostic(None, warning);
        assert_eq!(diag.severity, Severity::Warning);
        let span = diag
            .span
            .unwrap_or_else(|| panic!("dispatch returned no span for {warning:?}"));
        span_text(yaml, span).to_string()
    }

    const DISPATCH_YAML: &str = r#"
version: "0.2"
name: "Test"
roles:
  alice: {}
acts:
  - id: setup
    name: Setup
sections:
  main:
    act: setup
    steps:
      my_step:
        action: confirm
        creates: "${artifact.my_artifact}"
parameters:
  my_param:
    type: string
materials:
  my_material:
    type: digital
backends:
  ssl:
    provider: openssl
output:
  signed_cert:
    type: artifact
"#;

    #[test]
    fn dispatch_duplicate_role_spans_role_id() {
        let span_map = span_map_for(DISPATCH_YAML);
        let text = dispatch_span_text(
            DISPATCH_YAML,
            &span_map,
            &ResolveError::DuplicateRole(RoleId::new("alice")),
        );
        assert_eq!(text, "alice");
    }

    #[test]
    fn dispatch_duplicate_step_spans_step_id() {
        let span_map = span_map_for(DISPATCH_YAML);
        let text = dispatch_span_text(
            DISPATCH_YAML,
            &span_map,
            &ResolveError::DuplicateStep(StepId::new("my_step")),
        );
        assert_eq!(text, "my_step");
    }

    #[test]
    fn dispatch_duplicate_section_spans_section_id() {
        let span_map = span_map_for(DISPATCH_YAML);
        let text = dispatch_span_text(
            DISPATCH_YAML,
            &span_map,
            &ResolveError::DuplicateSection(SectionId::new("main")),
        );
        assert_eq!(text, "main");
    }

    #[test]
    fn dispatch_duplicate_param_spans_param_id() {
        let span_map = span_map_for(DISPATCH_YAML);
        let text = dispatch_span_text(
            DISPATCH_YAML,
            &span_map,
            &ResolveError::DuplicateParam(ParamId::new("my_param")),
        );
        assert_eq!(text, "my_param");
    }

    #[test]
    fn dispatch_duplicate_material_spans_material_id() {
        let span_map = span_map_for(DISPATCH_YAML);
        let text = dispatch_span_text(
            DISPATCH_YAML,
            &span_map,
            &ResolveError::DuplicateMaterial(MaterialId::new("my_material")),
        );
        assert_eq!(text, "my_material");
    }

    #[test]
    fn dispatch_duplicate_act_spans_act_id() {
        let span_map = span_map_for(DISPATCH_YAML);
        let text = dispatch_span_text(
            DISPATCH_YAML,
            &span_map,
            &ResolveError::DuplicateAct(ActId::new("setup")),
        );
        // Acts use node_to_span (the mapping node), not the id scalar — span has
        // no length, so span_text returns "" but the diagnostic still has a span.
        assert!(text.is_empty());
    }

    #[test]
    fn dispatch_required_param_missing_spans_param_declaration() {
        let span_map = span_map_for(DISPATCH_YAML);
        let text = dispatch_span_text(
            DISPATCH_YAML,
            &span_map,
            &ResolveError::RequiredParamMissing(ParamId::new("my_param")),
        );
        assert_eq!(text, "my_param");
    }

    #[test]
    fn dispatch_param_type_mismatch_spans_param_declaration() {
        let span_map = span_map_for(DISPATCH_YAML);
        let text = dispatch_span_text(
            DISPATCH_YAML,
            &span_map,
            &ResolveError::ParamTypeMismatch {
                param: ParamId::new("my_param"),
                expected: rite_model::ParameterType::Integer,
                got: "string".to_string(),
            },
        );
        assert_eq!(text, "my_param");
    }

    #[test]
    fn dispatch_required_material_missing_spans_material_declaration() {
        let span_map = span_map_for(DISPATCH_YAML);
        let text = dispatch_span_text(
            DISPATCH_YAML,
            &span_map,
            &ResolveError::RequiredMaterialMissing(MaterialId::new("my_material")),
        );
        assert_eq!(text, "my_material");
    }

    #[test]
    fn dispatch_duplicate_output_spans_output_id() {
        let span_map = span_map_for(DISPATCH_YAML);
        let text = dispatch_span_text(
            DISPATCH_YAML,
            &span_map,
            &ResolveError::DuplicateOutput(OutputId::new("signed_cert")),
        );
        assert_eq!(text, "signed_cert");
    }

    #[test]
    fn dispatch_unsafe_output_id_spans_output_declaration() {
        let span_map = span_map_for(DISPATCH_YAML);
        let text = dispatch_span_text(
            DISPATCH_YAML,
            &span_map,
            &ResolveError::UnsafeOutputId {
                id: OutputId::new("signed_cert"),
                reason: "name must not contain a path separator ('/' or '\\')".to_string(),
            },
        );
        assert_eq!(text, "signed_cert");
    }

    #[test]
    fn dispatch_unused_output_warning_spans_output_declaration() {
        let span_map = span_map_for(DISPATCH_YAML);
        let text = dispatch_warning_span_text(
            DISPATCH_YAML,
            &span_map,
            &ResolveWarning::UnusedOutput(OutputId::new("signed_cert")),
        );
        assert_eq!(text, "signed_cert");
    }

    #[test]
    fn dispatch_artifact_not_output_warning_spans_creates_value() {
        let span_map = span_map_for(DISPATCH_YAML);
        let text = dispatch_warning_span_text(
            DISPATCH_YAML,
            &span_map,
            &ResolveWarning::ArtifactNotOutput(ArtifactId::new("my_artifact")),
        );
        assert_eq!(text, "${artifact.my_artifact}");
    }
}
