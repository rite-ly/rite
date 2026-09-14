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
const ROOT_CA_SOFTWARE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/root_ca_software.rite.yaml"
);
const ROOT_CA_ECDSA_SOFTWARE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/root_ca_ecdsa_software.rite.yaml"
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
    assert!(
        !resolved.execution_plan.is_empty(),
        "minimal ceremony must lower to at least one step"
    );
}

#[test]
fn check_invalid_ceremony_produces_errors() {
    let yaml = r#"
version: "0.3"
name: "Invalid Ceremony"
roles: {}
sections:
  main:
    steps:
      step1:
        action: confirm
        role: "${role.nonexistent}"
        with:
          message: "Hello"
"#;
    let (_resolved, _spans, diags) = rite_resolver::analyze_str(None, yaml);

    let has_errors = diags
        .iter()
        .any(|d| d.severity == rite_resolver::Severity::Error);

    assert!(
        has_errors,
        "expected errors for invalid ceremony, got: {diags:?}"
    );
}

#[test]
fn check_root_ca_software_resolves_cleanly() {
    let (resolved, diags) = analyze(Path::new(ROOT_CA_SOFTWARE), None);

    let errors: Vec<_> = diags
        .iter()
        .filter(|d| d.severity == rite_resolver::Severity::Error)
        .collect();

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");

    let resolved = resolved.expect("ceremony resolves");
    assert_eq!(resolved.metadata.name, "Test Root CA");
    assert_declared_outputs(&resolved);
}

#[test]
fn check_root_ca_ecdsa_software_resolves_cleanly() {
    let (resolved, diags) = analyze(Path::new(ROOT_CA_ECDSA_SOFTWARE), None);

    let errors: Vec<_> = diags
        .iter()
        .filter(|d| d.severity == rite_resolver::Severity::Error)
        .collect();

    assert!(errors.is_empty(), "unexpected errors: {errors:#?}");

    let resolved = resolved.expect("ceremony resolves");
    assert_eq!(resolved.metadata.name, "Test Root CA (ECDSA)");
    assert_declared_outputs(&resolved);
}

/// Both root-CA fixtures declare the same three outputs. Asserting they are
/// present by name proves lowering kept the output declarations, without
/// pinning brittle element counts that mirror the fixture (see the testing
/// strategy: prefer property assertions over fixture-count mirroring).
fn assert_declared_outputs(resolved: &rite_model::Ceremony) {
    for id in ["root_ca_public_key", "root_ca_cert", "wrapped_root_ca_key"] {
        assert!(
            resolved
                .outputs
                .get(&rite_model::OutputId::new(id))
                .is_some(),
            "output `{id}` must be present after resolution"
        );
    }
}

#[test]
fn check_with_inputs_passes_parameter_values() {
    let yaml = r#"
version: "0.3"
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

/// Resolve a ceremony expected to hold exactly one error, and return it.
///
/// The span is asserted here because every one of these diagnostics has to
/// reach an editor, which it cannot do without one.
fn sole_error(yaml: &str) -> String {
    let (_resolved, _spans, diags) = rite_resolver::analyze_str(None, yaml);
    let errors: Vec<&rite_resolver::Diagnostic> = diags
        .iter()
        .filter(|d| d.severity == rite_resolver::Severity::Error)
        .collect();
    let [error] = errors.as_slice() else {
        panic!("expected exactly one error, got {errors:?}");
    };
    assert!(
        error.span.is_some(),
        "a diagnostic without a span cannot be shown in an editor"
    );
    error.message.clone()
}

/// A `with:` value outside an action's vocabulary is a resolver diagnostic,
/// which is what puts it in front of an editor as well as `rite check`.
#[test]
fn a_bad_with_value_is_reported_by_resolution() {
    let yaml = r#"
version: "0.3"
name: "Unusable declared fingerprint"
roles:
  officer:
    person: "Alice"
backends:
  openssl:
    provider: openssl
sections:
  main:
    role: ${role.officer}
    steps:
      gen:
        action: generate_key
        backend: openssl
        with:
          algorithm: RSA-2048
        creates: key
      wrap:
        action: wrap_key
        backend: openssl
        reads:
          key_to_wrap: ${artifact.key}
          recipient: ${artifact.key}
        with:
          expect_recipient: "deadbeef"
        creates: wrapped
"#;
    let message = sole_error(yaml);
    assert!(
        message.contains("sha256:<64 lowercase hex digits>"),
        "unexpected message: {message}"
    );
}

/// `expect_recipient:` is compared against the recipient a wrap is given, and
/// a wrap under a backend-held key has none. Left to the runtime the declared
/// value would be parsed and never read, so the step would wrap without the
/// guard its author wrote and nothing would say so.
#[test]
fn a_declared_recipient_without_a_recipient_input_is_reported() {
    let yaml = r#"
version: "0.3"
name: "Declared recipient on the wrong custody path"
roles:
  officer:
    person: "Alice"
backends:
  openssl:
    provider: openssl
sections:
  main:
    role: ${role.officer}
    steps:
      gen:
        action: generate_key
        backend: openssl
        with:
          algorithm: RSA-2048
        creates: key
      wrap:
        action: wrap_key
        backend: openssl
        reads:
          key_to_wrap: ${artifact.key}
          wrapping_key: ${artifact.key}
        with:
          expect_recipient: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        creates: wrapped
"#;
    let message = sole_error(yaml);
    assert!(
        message.contains("'expect_recipient' applies only when")
            && message.contains("reads 'recipient'"),
        "unexpected message: {message}"
    );
}

/// A value the checker cannot see is not a value it may reject.
#[test]
fn a_deferred_param_value_is_not_reported() {
    let yaml = r#"
version: "0.3"
name: "Deferred algorithm"
roles:
  officer:
    person: "Alice"
parameters:
  algorithm:
    type: string
backends:
  openssl:
    provider: openssl
sections:
  main:
    role: ${role.officer}
    steps:
      gen:
        action: generate_key
        backend: openssl
        with:
          algorithm: ${param.algorithm}
        creates: key
"#;
    let (resolved, _spans, diags) = rite_resolver::analyze_str(None, yaml);
    assert!(
        !diags
            .iter()
            .any(|d| d.severity == rite_resolver::Severity::Error),
        "an expression has no value until run time, so there is nothing to reject: {diags:?}"
    );
    let resolved = resolved.expect("ceremony resolves");

    assert!(
        rite_stdlib::default_registry()
            .unsupported_step_params(&resolved.execution_plan)
            .is_empty(),
    );
}
