//! Ceremony resolver: parse YAML, validate, and produce IR.
//!
//! This crate transforms ceremony YAML into the [`rite_model::Ceremony`] IR
//! ready for execution. It owns the YAML schema (AST types), the lowering
//! pipeline, and the resolution pass.
//!
//! # Usage
//!
//! ```ignore
//! use rite_resolver::{resolve, resolve_files, analyze, CeremonyInputs};
//!
//! // From a string (no external inputs)
//! let result = resolve(ceremony_yaml, None);
//!
//! // From a file with rich diagnostics
//! let (resolved, diags) = analyze(Path::new("sub_ca.rite.yaml"), None);
//! for d in &diags { eprintln!("{d}"); }
//! ```

#![warn(missing_docs)]

mod diagnostic;
mod error;
mod lower;
mod resolve;
mod schema;
mod serde_utils;

pub use diagnostic::{Diagnostic, ReferenceEntry, ReferenceTarget, Severity, Span, SpanMap};
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

/// Resolve relative `path:` values in digital materials against the ceremony file's directory.
///
/// Called after `lower_ceremony` succeeds. CLI-provided `@path` values are already resolved
/// relative to CWD in `parse_material_value` — those are not touched here.
fn resolve_material_paths(ceremony: &mut schema::Ceremony, ceremony_path: &Path) {
    let dir = ceremony_path.parent().unwrap_or_else(|| Path::new("."));
    for material in ceremony.materials.values_mut() {
        if let schema::Material::Digital {
            path: Some(ref mut p),
            ..
        } = *material
            && p.is_relative()
        {
            *p = dir.join(&*p);
        }
    }
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

    let Some(mut ceremony) = ceremony_opt else {
        return ResolveResult::err(first_resolve_error(diags));
    };

    resolve_material_paths(&mut ceremony, ceremony_path);
    resolve::resolve_ceremony(ceremony, inputs)
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

    let Some(mut ceremony) = ceremony_opt else {
        return (None, diags);
    };

    resolve_material_paths(&mut ceremony, ceremony_path);
    let result = resolve::resolve_ceremony(ceremony, inputs);

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
    use rite_model::{ParamId, RoleId};

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
}
