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

/// A ceremony whose one output, `out`, is declared as `kind` and created by
/// `step`, written as YAML under `steps:`.
fn ceremony_with_output(kind: &str, step: &str) -> String {
    format!(
        r#"
version: "0.3"
name: "Output kinds"
roles:
  officer:
    person: "Alice"
backends:
  ssl:
    provider: openssl
output:
  out:
    type: {kind}
sections:
  main:
    role: ${{role.officer}}
    steps:
      gen:
        action: generate_key
        backend: ssl
        with:
          algorithm: ECDSA-P256
        creates: key
      note:
        action: enter_value
        with:
          message: "The note"
        creates: note
{step}"#
    )
}

/// An output declared as a kind its step's action never writes is a
/// definition error, found before the run rather than at the write.
#[test]
fn an_output_of_the_wrong_kind_is_reported_by_resolution() {
    let sign = "      sign:
        action: sign_data
        backend: ssl
        reads:
          key: ${artifact.key}
          data: ${artifact.note}
        creates: out
";
    let message = sole_error(&ceremony_with_output("certificate", sign));
    assert_eq!(
        message,
        "Output 'out' is declared as 'certificate', but step 'sign' ('sign_data') writes \
         'signature'"
    );
    let (_, _, diags) = rite_resolver::analyze_str(None, &ceremony_with_output("signature", sign));
    assert!(diags.is_empty(), "{diags:?}");
}

/// A share set is never written, so declaring one as an output is refused
/// before the run, with where the shares go instead.
#[test]
fn a_share_set_as_an_output_is_reported_by_resolution() {
    let split = "      split:
        action: split_secret
        backend: ssl
        reads:
          secret: ${artifact.note}
        with:
          threshold: 2
          shares: 3
        creates: out
";
    let message = sole_error(&ceremony_with_output("bytes", split));
    assert!(
        message.contains("never written") && message.contains("'reveal'"),
        "unexpected message: {message}"
    );
}

/// A backend key is written as its public half, and `enter_value` without a
/// `format:` keeps the text typed, so these declarations pass.
#[test]
fn outputs_written_as_another_kind_pass() {
    for (kind, created) in [("public_key", "key"), ("text", "note")] {
        let yaml = ceremony_with_output(kind, "")
            .replace(&format!("creates: {created}\n"), "creates: out\n");
        let yaml = yaml.replace("${artifact.key}", "${artifact.out}");
        let (_, _, diags) = rite_resolver::analyze_str(None, &yaml);
        assert!(diags.is_empty(), "{kind}: {diags:?}");
    }
}

/// `enter_value` keeps bytes when its `format:` is an encoding and text
/// otherwise, so a literal `format:` decides which kind the output may be.
#[test]
fn an_entry_format_decides_the_output_kind() {
    let entry = |kind: &str, format: &str| {
        ceremony_with_output(kind, "").replace(
            "        creates: note\n",
            &format!("          format: {format}\n        creates: out\n"),
        )
    };
    let message = sole_error(&entry("text", "hex"));
    assert_eq!(
        message,
        "Output 'out' is declared as 'text', but step 'note' ('enter_value') writes 'bytes'"
    );
    for (kind, format) in [("bytes", "hex"), ("text", "digits")] {
        let (_, _, diags) = rite_resolver::analyze_str(None, &entry(kind, format));
        assert!(diags.is_empty(), "{kind} from {format}: {diags:?}");
    }
}

/// An artifact named by a step whose action makes none would never exist,
/// and a step reading it would fail mid-run.
#[test]
fn creates_on_an_action_that_makes_nothing_is_reported() {
    let confirm = "      ready:
        action: confirm
        with:
          message: \"Ready?\"
        creates: answer
";
    let message =
        sole_error(&ceremony_with_output("text", confirm).replace("creates: note", "creates: out"));
    assert_eq!(
        message,
        "Step 'ready' names 'answer' under 'creates:', but 'confirm' makes no artifact"
    );
}

/// A symmetric key has no public half, so a `public_key` output of the step
/// that makes one is refused before the run, not when the file is written.
#[test]
fn a_public_key_output_of_a_symmetric_key_is_reported() {
    let yaml = ceremony_with_output("public_key", "")
        .replace("algorithm: ECDSA-P256", "algorithm: AES-256")
        .replace("creates: key\n", "creates: out\n");
    assert_eq!(
        sole_error(&yaml),
        "Output 'out' is declared as 'public_key', but step 'gen' makes an AES-256 key, which \
         has no public half to write"
    );
}

/// An output type that went with the kinds is refused with what replaces
/// it.
#[test]
fn a_document_output_is_refused_with_its_replacement() {
    let message = sole_error(&ceremony_with_output("document", ""));
    assert!(
        message.contains("'document' is 'signature', 'bytes' or 'text'"),
        "unexpected message: {message}"
    );
}

/// A file material declares the kind of file it is. `digital`, which said
/// only that it was a file, is refused with what replaces it.
#[test]
fn a_digital_material_is_refused_with_its_replacement() {
    let yaml = |kind: &str| {
        format!(
            r#"
version: "0.3"
name: "Material kinds"
roles:
  officer:
    person: "Alice"
materials:
  manifest:
    type: {kind}
    path: "manifest.txt"
sections:
  main:
    role: ${{role.officer}}
    steps:
      ready:
        action: confirm
        with:
          message: "Ready?"
"#
        )
    };
    let message = sole_error(&yaml("digital"));
    assert!(
        message.contains("'bytes'") && message.contains("'digital'"),
        "unexpected message: {message}"
    );
    for kind in ["bytes", "certificate", "secret"] {
        let (_, _, diags) = rite_resolver::analyze_str(None, &yaml(kind));
        assert!(diags.is_empty(), "{kind}: {diags:?}");
    }
    let physical = yaml("physical");
    assert!(
        sole_error(&physical).contains("path"),
        "a physical material takes no path"
    );
}

/// A provider the language does not know is a definition error, listing the
/// providers it knows, rather than a failure at the first step that uses the
/// backend.
#[test]
fn a_misspelt_provider_is_reported_by_resolution() {
    let yaml = r#"
version: "0.3"
name: "Misspelt provider"
roles:
  officer:
    person: "Alice"
backends:
  ssl:
    provider: opensl
sections:
  main:
    role: ${role.officer}
    steps:
      ready:
        action: confirm
        with:
          message: "Ready?"
"#;
    let message = sole_error(yaml);
    assert!(
        message.contains("opensl") && message.contains("mock, openssl, piv, yubikey"),
        "unexpected message: {message}"
    );
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
        message.contains("'with.expect_recipient' applies only when")
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
