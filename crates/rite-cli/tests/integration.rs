//! Integration tests for the rite CLI.
//!
//! These tests exercise the resolver pipeline and CLI helpers end-to-end
//! without spawning a subprocess. Full CLI invocation tests (snapshot tests
//! of stdout/stderr) are deferred to Phase 5 beta hardening.

use rite_resolver::{CeremonyInputs, analyze};
use std::path::Path;

const MINIMAL: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/minimal.rite.yaml"
);
const INVALID: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/invalid.rite.yaml"
);

#[test]
fn check_minimal_ceremony_resolves_cleanly() {
    let (resolved, diags) = analyze(Path::new(MINIMAL), None);

    let has_errors = diags
        .iter()
        .any(|d| d.severity == rite_resolver::Severity::Error);

    assert!(!has_errors, "unexpected errors: {diags:?}");
    let resolved = resolved.expect("ceremony resolves");
    assert_eq!(resolved.metadata.name, "Minimal Ceremony");
    assert_eq!(resolved.roles.len(), 1);
    assert_eq!(resolved.execution_plan.len(), 1);
}

#[test]
fn check_invalid_ceremony_produces_errors() {
    let (_resolved, diags) = analyze(Path::new(INVALID), None);

    let has_errors = diags
        .iter()
        .any(|d| d.severity == rite_resolver::Severity::Error);

    assert!(
        has_errors,
        "expected errors for invalid ceremony, got: {diags:?}"
    );
}

#[test]
fn check_with_inputs_passes_parameter_values() {
    let yaml = r#"
version: "2.0"
name: "Parameterized"
roles: {}
sections: {}
parameters:
  ceremony_name:
    type: string
"#;
    let inputs = CeremonyInputs {
        parameters: {
            let mut m = std::collections::HashMap::new();
            m.insert("ceremony_name".to_string(), serde_json::json!("Production"));
            m
        },
        ..Default::default()
    };
    let result = rite_resolver::resolve(yaml, Some(&inputs));
    assert!(result.is_ok(), "errors: {:?}", result.errors);
    let resolved = result.into_result().unwrap();
    let param = resolved
        .parameters
        .get(&rite_model::ParamId::new("ceremony_name"))
        .expect("parameter exists");
    assert_eq!(param.value, serde_json::json!("Production"));
}
