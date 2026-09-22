//! Focused tests for stdlib actions: each executes one action and asserts its
//! single responsibility (its outcome, the fact it records, or the artifact it
//! produces), not that a whole ceremony runs.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;

use rite_model::{
    ArtifactId, ArtifactRef, NamedInput, Prompt, ResponseRecord, StepFact, StepId, StepInputs,
};
use rite_runtime::{
    Action, ArtifactValue, ExecutionState, Response, Share, ShareSet, StepInfo,
    test_support::ReporterHarness,
};
use rite_sdk::{KeyAlgorithm, KeyPolicy, KeySpec, KeyStoreBackend};
use rite_stdlib::sharing::{gf256, wire};
use rite_stdlib::{
    AttestAction, CheckValueAction, ClockCheckAction, CombineSharesAction, ConfirmAction,
    DecryptDataAction, EncryptDataAction, EnterSecretAction, EnterValueAction, ExportPublicAction,
    GatherEntropyAction, ImportKeyAction, MachineInfoAction, MockBackend, OralReadbackAction,
    SplitSecretAction, UnwrapKeyAction, WrapKeyAction,
};
use secrecy::{ExposeSecret, SecretBox, SecretString};

fn make_state() -> ExecutionState {
    ExecutionState::new(HashMap::new(), HashMap::new(), HashMap::new(), false)
}

/// A bare step with no role, backend, output, or inputs, enough for the
/// interactive verification actions, which read only their params.
fn bare_step(id: &str) -> StepInfo {
    StepInfo::new(StepId::new(id), None, None, None, None)
}

// ── interactive verification / attestation ──────────────────────────────────

#[test]
fn confirm_completes_on_yes() {
    let mut harness = ReporterHarness::new();
    harness.enqueue_response(Response::Bool(true));
    let state = make_state();
    let step = bare_step("confirm");

    let result = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        ConfirmAction.execute(&step, &ctx, &serde_json::json!({}), &mut reporter, None)
    };

    result.expect("a yes response completes the confirmation");
}

#[test]
fn clock_check_completes_when_clock_confirmed() {
    let mut harness = ReporterHarness::new();
    harness.enqueue_response(Response::Bool(true));
    let state = make_state();
    let step = bare_step("clock");

    let result = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        ClockCheckAction.execute(&step, &ctx, &serde_json::json!({}), &mut reporter, None)
    };

    result.expect("confirming the clock completes the step");
}

#[test]
fn attest_records_an_attestation_fact() {
    let mut harness = ReporterHarness::new();
    harness.enqueue_response(Response::Text("attest".to_string()));
    let state = make_state();
    let step = bare_step("officer_attest");

    let result = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        AttestAction.execute(&step, &ctx, &serde_json::json!({}), &mut reporter, None)
    };
    result.expect("typing the literal confirmation completes the attestation");

    assert!(
        harness
            .facts()
            .iter()
            .any(|f| matches!(f, StepFact::AttestationRecorded { .. })),
        "attest must record an AttestationRecorded fact"
    );
}

#[test]
fn gather_entropy_completes_with_a_contribution() {
    let mut harness = ReporterHarness::new();
    harness.enqueue_response(Response::Text("3 1 4 1 5 9 2 6".to_string()));
    let state = make_state();
    let step = bare_step("entropy");

    let result = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        GatherEntropyAction.execute(&step, &ctx, &serde_json::json!({}), &mut reporter, None)
    };

    result.expect("a non-empty contribution is folded and the step completes");
}

// ── typed entry ─────────────────────────────────────────────────────────────

/// A step that creates `produces` and reads nothing, as an entry step does.
fn creating_step(id: &str, produces: &str) -> StepInfo {
    StepInfo::new(
        StepId::new(id),
        None,
        None,
        Some(ArtifactId::new(produces)),
        None,
    )
}

#[test]
fn enter_value_records_what_was_typed_as_a_text_artifact() {
    let mut harness = ReporterHarness::new();
    harness.enqueue_response(Response::Text("SN-4471".to_string()));
    let state = make_state();
    let step = creating_step("read_serial", "serial");

    let result = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        EnterValueAction
            .execute(
                &step,
                &ctx,
                &serde_json::json!({ "message": "Serial number on the device" }),
                &mut reporter,
                None,
            )
            .expect("a typed value completes the step")
    };

    assert!(matches!(
        produced(&result.artifacts, "serial"),
        ArtifactValue::Text(value) if value == "SN-4471"
    ));
    // The value is evidence, so the prompt fact carries it.
    assert!(harness.facts().iter().any(|fact| matches!(
        fact,
        StepFact::PromptAnswered {
            response: ResponseRecord::Text { value },
            ..
        } if value == "SN-4471"
    )));
}

#[test]
fn enter_secret_holds_the_secret_and_records_only_that_one_was_entered() {
    let mut harness = ReporterHarness::new();
    harness.enqueue_response(Response::Secret(SecretString::from("correct horse")));
    let state = make_state();
    let step = creating_step("unlock", "escrow_passphrase");

    let result = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        EnterSecretAction
            .execute(
                &step,
                &ctx,
                &serde_json::json!({ "message": "Passphrase for the escrow key" }),
                &mut reporter,
                None,
            )
            .expect("a typed secret completes the step")
    };

    match produced(&result.artifacts, "escrow_passphrase") {
        ArtifactValue::Secret(secret) => {
            assert_eq!(secret.expose_secret(), b"correct horse");
        }
        other => panic!("enter_secret must produce a Secret, got {other:?}"),
    }
    // The fact says a secret was entered, and nothing else about it.
    let recorded = harness
        .facts()
        .iter()
        .find_map(|fact| match fact {
            StepFact::PromptAnswered { response, .. } => Some(response),
            _ => None,
        })
        .expect("the prompt is recorded");
    assert!(matches!(recorded, ResponseRecord::SecretRedacted {}));
    let serialized = serde_json::to_string(harness.facts()).unwrap();
    assert!(!serialized.contains("correct horse"));
}

#[test]
fn enter_secret_refuses_a_step_that_holds_the_secret_nowhere() {
    let mut harness = ReporterHarness::new();
    let state = make_state();
    let step = bare_step("unlock");

    let ctx = state.handler_context();
    let mut reporter = harness.reporter(step.id.clone());
    let error = EnterSecretAction
        .execute(
            &step,
            &ctx,
            &serde_json::json!({ "message": "Passphrase" }),
            &mut reporter,
            None,
        )
        .expect_err("a secret with no artifact to hold it would be typed and thrown away");

    assert!(error.to_string().contains("creates:"), "{error}");
    assert!(
        harness.facts().is_empty(),
        "the refusal comes before the person is asked"
    );
}

/// The shape is stated in the label, so the person reads the rule before
/// typing. Applying it is the reporter's job, tested there.
#[test]
fn entry_states_its_shape_in_the_prompt() {
    let mut harness = ReporterHarness::new();
    harness.enqueue_response(Response::Secret(SecretString::from("123456")));
    let state = make_state();
    let step = creating_step("pin", "pin");

    {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        EnterSecretAction
            .execute(
                &step,
                &ctx,
                &serde_json::json!({ "message": "PIN", "format": "digits", "length": 6 }),
                &mut reporter,
                None,
            )
            .expect("six digits fit the shape");
    }

    let prompt = harness
        .facts()
        .iter()
        .find_map(|fact| match fact {
            StepFact::PromptAnswered { prompt, .. } => Some(prompt),
            _ => None,
        })
        .expect("the prompt is recorded");
    assert!(matches!(
        prompt,
        Prompt::Secret { label, .. } if label == "PIN (6 digits)"
    ));
}

#[test]
fn entry_refuses_a_shape_that_describes_no_rule() {
    let mut harness = ReporterHarness::new();
    let state = make_state();
    let step = creating_step("pin", "pin");

    let ctx = state.handler_context();
    let mut reporter = harness.reporter(step.id.clone());
    let error = EnterValueAction
        .execute(
            &step,
            &ctx,
            &serde_json::json!({ "message": "PIN", "format": { "pattern": "[0-9]+" }, "length": 6 }),
            &mut reporter,
            None,
        )
        .expect_err("a pattern beside a length is two rules");

    assert!(error.to_string().contains("pattern"), "{error}");
}

/// With an encoding the string is transport: the prompt fact keeps what was
/// typed and the artifact keeps what it decodes to.
#[test]
fn enter_value_with_an_encoding_keeps_the_decoded_bytes() {
    let mut harness = ReporterHarness::new();
    harness.enqueue_response(Response::Text("DE AD be ef".to_string()));
    let state = make_state();
    let step = creating_step("read_kcv", "kcv");

    let result = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        EnterValueAction
            .execute(
                &step,
                &ctx,
                &serde_json::json!({ "message": "KCV", "format": "hex", "length": 4 }),
                &mut reporter,
                None,
            )
            .expect("four hex bytes, grouped as typed")
    };

    assert!(matches!(
        produced(&result.artifacts, "kcv"),
        ArtifactValue::Bytes(bytes) if bytes == &[0xde, 0xad, 0xbe, 0xef]
    ));
    assert!(harness.facts().iter().any(|fact| matches!(
        fact,
        StepFact::PromptAnswered {
            response: ResponseRecord::Text { value },
            ..
        } if value == "DE AD be ef"
    )));
}

#[test]
fn enter_secret_with_an_encoding_holds_the_decoded_bytes() {
    let mut harness = ReporterHarness::new();
    harness.enqueue_response(Response::Secret(SecretString::from("00".repeat(32))));
    let state = make_state();
    let step = creating_step("component", "kek_component");

    let result = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        EnterSecretAction
            .execute(
                &step,
                &ctx,
                &serde_json::json!({ "message": "Component", "format": "hex", "length": 32 }),
                &mut reporter,
                None,
            )
            .expect("a 32-byte component as hex")
    };

    match produced(&result.artifacts, "kek_component") {
        ArtifactValue::Secret(secret) => assert_eq!(secret.expose_secret(), &[0u8; 32]),
        other => panic!("enter_secret must produce a Secret, got {other:?}"),
    }
}

#[test]
fn oral_readback_completes_on_confirmation() {
    let mut harness = ReporterHarness::new();
    harness.enqueue_response(Response::Bool(true));
    let state = make_state();
    let step = bare_step("readback");

    let result = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        let params = serde_json::json!({ "value": "ABC123" });
        OralReadbackAction.execute(&step, &ctx, &params, &mut reporter, None)
    };

    result.expect("a confirmed readback completes the step");
}

#[test]
fn machine_info_records_a_snapshot_fact() {
    let mut harness = ReporterHarness::new();
    let state = make_state();
    let step = bare_step("capture_machine");

    let result = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        MachineInfoAction.execute(&step, &ctx, &serde_json::json!({}), &mut reporter, None)
    };
    result.expect("capturing machine info completes");

    assert!(
        harness.facts().iter().any(|f| matches!(
            f,
            StepFact::BackendOperation { kind, .. } if kind == "machine_info"
        )),
        "machine_info must record a machine_info BackendOperation fact"
    );
}

// ── automatic comparison ────────────────────────────────────────────────────

#[test]
fn check_value_passes_on_match_and_fails_on_mismatch() {
    let mut harness = ReporterHarness::new();
    let state = make_state();
    let step = bare_step("check");

    let matched = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        let params = serde_json::json!({ "actual": "abc123", "expected": "abc123" });
        CheckValueAction.execute(&step, &ctx, &params, &mut reporter, None)
    };
    matched.expect("equal values pass");

    let mismatched = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        let params = serde_json::json!({ "actual": "abc123", "expected": "different" });
        CheckValueAction.execute(&step, &ctx, &params, &mut reporter, None)
    };
    assert!(mismatched.is_err(), "unequal values must fail the step");
}

// ── backend crypto ──────────────────────────────────────────────────────────

fn key_spec_with(label: &str, algorithm: KeyAlgorithm, policy: KeyPolicy) -> KeySpec {
    KeySpec {
        algorithm,
        label: label.to_string(),
        policy,
        location_hint: None,
    }
}

/// Generate a key on the mock backend and wrap it as a `BackendKey` artifact,
/// the form the crypto actions resolve their inputs from.
fn backend_key(
    backend: &mut MockBackend,
    id: &str,
    algorithm: KeyAlgorithm,
) -> (ArtifactId, ArtifactValue) {
    backend_key_with(backend, id, algorithm, KeyPolicy::default())
}

/// The same, for a key whose policy has to allow what the test does with it.
fn backend_key_with(
    backend: &mut MockBackend,
    id: &str,
    algorithm: KeyAlgorithm,
    policy: KeyPolicy,
) -> (ArtifactId, ArtifactValue) {
    let meta = backend
        .generate_key(key_spec_with(id, algorithm, policy))
        .unwrap();
    (
        ArtifactId::new(id),
        ArtifactValue::BackendKey {
            backend_name: "mock".to_string(),
            key_id: meta.key_id,
            algorithm: meta.algorithm,
            public_key: meta.public_key,
            check_value: meta.check_value,
        },
    )
}

fn step_single(id: &str, produces: &str, input: ArtifactId) -> StepInfo {
    let inputs = StepInputs::Single(ArtifactRef::Produced {
        id: input,
        property: None,
    });
    StepInfo::new(
        StepId::new(id),
        None,
        Some("mock".to_string()),
        Some(ArtifactId::new(produces)),
        Some(inputs),
    )
}

fn step_named(id: &str, produces: &str, pairs: &[(&str, ArtifactId)]) -> StepInfo {
    let map = pairs
        .iter()
        .map(|(name, id)| {
            (
                (*name).to_string(),
                NamedInput::One(ArtifactRef::Produced {
                    id: id.clone(),
                    property: None,
                }),
            )
        })
        .collect();
    StepInfo::new(
        StepId::new(id),
        None,
        Some("mock".to_string()),
        Some(ArtifactId::new(produces)),
        Some(StepInputs::Named(map)),
    )
}

fn produced<'a>(artifacts: &'a [(ArtifactId, ArtifactValue)], id: &str) -> &'a ArtifactValue {
    artifacts
        .iter()
        .find(|(aid, _)| aid.as_str() == id)
        .map_or_else(|| panic!("artifact `{id}` was not produced"), |(_, v)| v)
}

#[test]
fn export_public_produces_a_public_key_artifact() {
    let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());
    let (key_id, key) = backend_key(&mut backend, "ca_keypair", KeyAlgorithm::Rsa2048);
    let state = make_state().with_material(key_id.clone(), key);
    let step = step_single("export", "ca_public_key", key_id);
    let mut harness = ReporterHarness::new();

    let result = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        ExportPublicAction
            .execute(
                &step,
                &ctx,
                &serde_json::json!({}),
                &mut reporter,
                Some(&mut backend),
            )
            .expect("export_public completes")
    };

    assert!(
        matches!(
            produced(&result.artifacts, "ca_public_key"),
            ArtifactValue::PublicKey { .. }
        ),
        "export_public must produce a PublicKey artifact"
    );
}

#[test]
fn wrap_then_unwrap_round_trips_through_the_actions() {
    let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());
    // The scheme is fixed; an RSA recipient makes it a key-transport wrap.
    let (recipient_id, recipient) = backend_key_with(
        &mut backend,
        "recipient",
        KeyAlgorithm::Rsa4096,
        KeyPolicy {
            usages: rite_sdk::KeyUsages::WRAP | rite_sdk::KeyUsages::UNWRAP,
            ..KeyPolicy::default()
        },
    );
    let (secret_id, secret) = backend_key_with(
        &mut backend,
        "secret_key",
        KeyAlgorithm::Rsa4096,
        KeyPolicy {
            extractable: true,
            ..KeyPolicy::default()
        },
    );
    let state = make_state()
        .with_material(recipient_id.clone(), recipient)
        .with_material(secret_id.clone(), secret);

    let wrap_step = step_named(
        "wrap",
        "wrapped_key",
        &[
            ("key_to_wrap", secret_id),
            ("wrapping_key", recipient_id.clone()),
        ],
    );
    let mut harness = ReporterHarness::new();
    let wrapped = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(wrap_step.id.clone());
        let result = WrapKeyAction
            .execute(
                &wrap_step,
                &ctx,
                &serde_json::json!({}),
                &mut reporter,
                Some(&mut backend),
            )
            .expect("wrap_key completes");
        // ArtifactValue is not Clone, so move the produced value out of the result.
        let value = result
            .artifacts
            .into_iter()
            .find(|(id, _)| id.as_str() == "wrapped_key")
            .map(|(_, v)| v)
            .expect("wrap_key must produce a wrapped_key artifact");
        assert!(
            matches!(value, ArtifactValue::WrappedKey { .. }),
            "wrap_key must produce a WrappedKey artifact"
        );
        value
    };

    let wrapped_id = ArtifactId::new("wrapped_key");
    let state = state.with_material(wrapped_id.clone(), wrapped);
    let unwrap_step = step_named(
        "unwrap",
        "restored_key",
        &[
            ("unwrapping_key", recipient_id),
            ("wrapped_data", wrapped_id),
        ],
    );
    let restored = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(unwrap_step.id.clone());
        UnwrapKeyAction
            .execute(
                &unwrap_step,
                &ctx,
                &serde_json::json!({}),
                &mut reporter,
                Some(&mut backend),
            )
            .expect("unwrap_key completes")
    };

    assert!(
        matches!(
            produced(&restored.artifacts, "restored_key"),
            ArtifactValue::BackendKey { .. }
        ),
        "unwrap_key must produce a BackendKey artifact"
    );
}

// ── import_key ──────────────────────────────────────────────────────────────

/// An all-zero AES-256 key, whose check value is a published quantity: AES-CMAC
/// over a 16-byte zero block gives `9211053c558ae90ec0af4057758c3cec`, so the
/// leftmost three bytes are `921105`. Cross-checked against `openssl mac -macopt
/// cipher:AES-256-CBC CMAC`.
const ZERO_AES_256: [u8; 32] = [0u8; 32];
const ZERO_AES_256_KCV: &str = "cmac-aes:921105";

fn import_step(id: &str, produces: &str, material: ArtifactId) -> StepInfo {
    step_named(id, produces, &[("key_material", material)])
}

#[test]
fn import_key_lifts_bytes_into_a_backend_key_with_its_check_value() {
    let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());
    let material_id = ArtifactId::new("component");
    let state = make_state().with_material(
        material_id.clone(),
        ArtifactValue::Bytes(ZERO_AES_256.to_vec()),
    );
    let step = import_step("import", "kek", material_id);

    let mut harness = ReporterHarness::new();
    let imported = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        ImportKeyAction
            .execute(
                &step,
                &ctx,
                &serde_json::json!({ "algorithm": "AES-256" }),
                &mut reporter,
                Some(&mut backend),
            )
            .expect("import_key completes")
    };

    match produced(&imported.artifacts, "kek") {
        ArtifactValue::BackendKey {
            algorithm,
            public_key,
            check_value,
            ..
        } => {
            assert_eq!(*algorithm, KeyAlgorithm::Aes256);
            assert!(public_key.is_none(), "a symmetric key has no public half");
            assert_eq!(
                check_value
                    .as_ref()
                    .expect("a symmetric key is named by its check value")
                    .to_string(),
                ZERO_AES_256_KCV
            );
        }
        other => panic!("import_key must produce a BackendKey, got {other:?}"),
    }
}

#[test]
fn import_key_refuses_material_that_is_not_the_declared_key() {
    let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());
    let material_id = ArtifactId::new("component");
    let state = make_state().with_material(
        material_id.clone(),
        // Sixteen bytes offered as a 32-byte key.
        ArtifactValue::Bytes(vec![0u8; 16]),
    );
    let step = import_step("import", "kek", material_id);

    let mut harness = ReporterHarness::new();
    let ctx = state.handler_context();
    let mut reporter = harness.reporter(step.id.clone());
    let error = ImportKeyAction
        .execute(
            &step,
            &ctx,
            &serde_json::json!({ "algorithm": "AES-256" }),
            &mut reporter,
            Some(&mut backend),
        )
        .expect_err("a 16-byte value is not an AES-256 key");

    let message = error.to_string();
    assert!(
        message.contains("32") && message.contains("16"),
        "the refusal should name both lengths, got: {message}"
    );
}

#[test]
fn import_key_refuses_a_key_that_is_not_the_one_declared() {
    let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());
    let material_id = ArtifactId::new("component");
    let state = make_state().with_material(
        material_id.clone(),
        ArtifactValue::Bytes(ZERO_AES_256.to_vec()),
    );
    let step = import_step("import", "kek", material_id);

    let mut harness = ReporterHarness::new();
    let ctx = state.handler_context();
    let mut reporter = harness.reporter(step.id.clone());
    let error = ImportKeyAction
        .execute(
            &step,
            &ctx,
            &serde_json::json!({
                "algorithm": "AES-256",
                "expect_key": "cmac-aes:000000",
            }),
            &mut reporter,
            Some(&mut backend),
        )
        .expect_err("the declared check value does not match the material");

    assert!(
        error.to_string().contains(ZERO_AES_256_KCV),
        "the refusal should name what was actually lifted, got: {error}"
    );
}

#[test]
fn import_key_defaults_a_symmetric_key_to_wrap_and_unwrap() {
    let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());
    let material_id = ArtifactId::new("component");
    let state = make_state().with_material(
        material_id.clone(),
        ArtifactValue::Bytes(ZERO_AES_256.to_vec()),
    );
    let step = import_step("import", "kek", material_id);

    let mut harness = ReporterHarness::new();
    {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        ImportKeyAction
            .execute(
                &step,
                &ctx,
                &serde_json::json!({ "algorithm": "AES-256" }),
                &mut reporter,
                Some(&mut backend),
            )
            .expect("import_key completes");
    }

    let usages = harness
        .facts()
        .iter()
        .find_map(|fact| match fact {
            StepFact::BackendOperation { kind, inputs, .. } if kind == "import_key" => {
                inputs.get("policy").and_then(|p| p.get("usages")).cloned()
            }
            _ => None,
        })
        .expect("import_key records a BackendOperation fact");

    assert_eq!(
        usages,
        serde_json::json!(["wrap", "unwrap"]),
        "a symmetric key cannot sign, so the default follows the algorithm"
    );
}

/// A PKCS#8 DER private key, so the asymmetric arm of `import_key` gets the same
/// coverage the symmetric one has. Generated at test time rather than
/// committed, since what matters is the encoding, not the key.
fn pkcs8_der() -> Vec<u8> {
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    openssl::pkey::PKey::from_rsa(rsa)
        .unwrap()
        .private_key_to_pkcs8()
        .unwrap()
}

#[test]
fn import_key_lifts_a_pkcs8_private_key_and_names_it_by_its_public_half() {
    let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());
    let material_id = ArtifactId::new("escrowed");
    let state = make_state().with_material(material_id.clone(), ArtifactValue::Bytes(pkcs8_der()));
    let step = import_step("import", "restored", material_id);

    let mut harness = ReporterHarness::new();
    let imported = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        ImportKeyAction
            .execute(
                &step,
                &ctx,
                &serde_json::json!({ "algorithm": "RSA-2048" }),
                &mut reporter,
                Some(&mut backend),
            )
            .expect("import_key completes for a keypair")
    };

    match produced(&imported.artifacts, "restored") {
        ArtifactValue::BackendKey {
            algorithm,
            public_key,
            check_value,
            ..
        } => {
            assert_eq!(*algorithm, KeyAlgorithm::Rsa2048);
            assert!(
                public_key.is_some(),
                "a keypair is named by its public half"
            );
            assert!(
                check_value.is_none(),
                "a keypair has no check value, which is what a symmetric key uses instead"
            );
        }
        other => panic!("import_key must produce a BackendKey, got {other:?}"),
    }
}

#[test]
fn import_key_accepts_a_pem_private_key() {
    let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let pem = openssl::pkey::PKey::from_rsa(rsa)
        .unwrap()
        .private_key_to_pem_pkcs8()
        .unwrap();
    let material_id = ArtifactId::new("escrowed");
    let state = make_state().with_material(material_id.clone(), ArtifactValue::Bytes(pem));
    let step = import_step("import", "restored", material_id);

    let mut harness = ReporterHarness::new();
    let imported = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        ImportKeyAction
            .execute(
                &step,
                &ctx,
                &serde_json::json!({ "algorithm": "RSA-2048" }),
                &mut reporter,
                Some(&mut backend),
            )
            .expect("PEM is what openssl writes by default, so it is accepted")
    };

    assert!(matches!(
        produced(&imported.artifacts, "restored"),
        ArtifactValue::BackendKey { .. }
    ));
}

/// Both encodings of an encrypted PEM, because they say so in different
/// places: PKCS#8 in the preamble, the traditional format in RFC 1421 headers
/// inside an ordinary one. Missing the second would leave OpenSSL to ask for
/// the passphrase itself, on the terminal, in the middle of a ceremony.
fn encrypted_pems(passphrase: &[u8]) -> Vec<Vec<u8>> {
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let key = openssl::pkey::PKey::from_rsa(rsa).unwrap();
    let cipher = openssl::symm::Cipher::aes_256_cbc();
    let pkcs8 = key
        .private_key_to_pem_pkcs8_passphrase(cipher, passphrase)
        .unwrap();
    let traditional = key
        .rsa()
        .unwrap()
        .private_key_to_pem_passphrase(cipher, passphrase)
        .unwrap();
    assert!(
        traditional.windows(10).any(|w| w == b"Proc-Type:"),
        "the traditional form marks the body, not the preamble"
    );
    vec![pkcs8, traditional]
}

fn secret(text: &str) -> ArtifactValue {
    ArtifactValue::Secret(SecretBox::new(Box::new(text.as_bytes().to_vec())))
}

/// An import step reading `escrowed` as the material and, when given, an
/// artifact as the passphrase.
fn passphrase_import(passphrase: Option<&str>) -> StepInfo {
    let mut reads = vec![("key_material", ArtifactId::new("escrowed"))];
    if let Some(id) = passphrase {
        reads.push(("passphrase", ArtifactId::new(id)));
    }
    step_named("import", "restored", &reads)
}

fn run_import(
    state: &ExecutionState,
    step: &StepInfo,
    harness: &mut ReporterHarness,
) -> Result<rite_runtime::StepResult, rite_runtime::ActionError> {
    let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());
    let ctx = state.handler_context();
    let mut reporter = harness.reporter(step.id.clone());
    ImportKeyAction.execute(
        step,
        &ctx,
        &serde_json::json!({ "algorithm": "RSA-2048" }),
        &mut reporter,
        Some(&mut backend),
    )
}

#[test]
fn import_key_refuses_an_encrypted_pem_by_name() {
    for pem in encrypted_pems(b"secret") {
        let state =
            make_state().with_material(ArtifactId::new("escrowed"), ArtifactValue::Bytes(pem));
        let step = passphrase_import(None);
        let mut harness = ReporterHarness::new();

        let error = run_import(&state, &step, &mut harness)
            .expect_err("the ceremony supplies no passphrase");

        let message = error.to_string();
        assert!(
            message.contains("encrypted PEM") && message.contains("enter_secret"),
            "the refusal should name the encoding and the way out, got: {message}"
        );
    }
}

#[test]
fn import_key_opens_an_encrypted_pem_with_the_secret_a_step_read() {
    for pem in encrypted_pems(b"correct horse") {
        let state = make_state()
            .with_material(ArtifactId::new("escrowed"), ArtifactValue::Bytes(pem))
            .with_material(
                ArtifactId::new("escrow_passphrase"),
                secret("correct horse"),
            );
        let step = passphrase_import(Some("escrow_passphrase"));
        let mut harness = ReporterHarness::new();

        let imported =
            run_import(&state, &step, &mut harness).expect("the passphrase opens the key");

        assert!(matches!(
            produced(&imported.artifacts, "restored"),
            ArtifactValue::BackendKey { .. }
        ));
        // The record names the artifact the passphrase came from and carries
        // nothing of its value.
        let inputs = harness
            .facts()
            .iter()
            .find_map(|fact| match fact {
                StepFact::BackendOperation { inputs, .. } => Some(inputs),
                _ => None,
            })
            .expect("the import is recorded");
        assert_eq!(inputs["passphrase"], "escrow_passphrase");
        assert!(
            !serde_json::to_string(harness.facts())
                .unwrap()
                .contains("correct horse")
        );
    }
}

#[test]
fn import_key_refuses_the_wrong_passphrase_without_naming_it() {
    let pem = encrypted_pems(b"correct horse").swap_remove(0);
    let state = make_state()
        .with_material(ArtifactId::new("escrowed"), ArtifactValue::Bytes(pem))
        .with_material(ArtifactId::new("escrow_passphrase"), secret("wrong horse"));
    let step = passphrase_import(Some("escrow_passphrase"));
    let mut harness = ReporterHarness::new();

    let error = run_import(&state, &step, &mut harness).expect_err("the passphrase is wrong");

    let message = error.to_string();
    assert!(message.contains("does not open"), "{message}");
    assert!(!message.contains("wrong horse"), "{message}");
}

#[test]
fn import_key_refuses_a_passphrase_that_was_never_needed() {
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let pem = openssl::pkey::PKey::from_rsa(rsa)
        .unwrap()
        .private_key_to_pem_pkcs8()
        .unwrap();
    let state = make_state()
        .with_material(ArtifactId::new("escrowed"), ArtifactValue::Bytes(pem))
        .with_material(
            ArtifactId::new("escrow_passphrase"),
            secret("correct horse"),
        );
    let step = passphrase_import(Some("escrow_passphrase"));
    let mut harness = ReporterHarness::new();

    let error = run_import(&state, &step, &mut harness)
        .expect_err("a passphrase the record says was used has to have been used");

    assert!(error.to_string().contains("not encrypted"), "{error}");
}

/// A passphrase that sat on a disk is what reading one at the keyboard
/// exists to avoid, so only a secret artifact is accepted.
#[test]
fn import_key_refuses_a_passphrase_that_is_not_a_secret() {
    let pem = encrypted_pems(b"correct horse").swap_remove(0);
    let state = make_state()
        .with_material(ArtifactId::new("escrowed"), ArtifactValue::Bytes(pem))
        .with_material(
            ArtifactId::new("escrow_passphrase"),
            ArtifactValue::Bytes(b"correct horse".to_vec()),
        );
    let step = passphrase_import(Some("escrow_passphrase"));
    let mut harness = ReporterHarness::new();

    let error = run_import(&state, &step, &mut harness).expect_err("bytes are not a secret");

    let message = error.to_string();
    assert!(message.contains("enter_secret"), "{message}");
    assert!(
        harness.facts().is_empty(),
        "the refusal comes before anything is recorded"
    );

    // A text artifact prints its text, and this message becomes a fact, so
    // the refusal names the kind and nothing more.
    let state = make_state()
        .with_material(
            ArtifactId::new("escrowed"),
            ArtifactValue::Bytes(Vec::new()),
        )
        .with_material(
            ArtifactId::new("escrow_passphrase"),
            ArtifactValue::Text("correct horse".to_string()),
        );
    let error = run_import(&state, &step, &mut harness).expect_err("text is not a secret");
    let message = error.to_string();
    assert!(message.contains("is text"), "{message}");
    assert!(!message.contains("correct horse"), "{message}");
}

/// A secret has no properties, so a reference naming one is a slip that
/// would otherwise supply the whole secret without a word.
#[test]
fn import_key_refuses_a_passphrase_reference_with_a_property() {
    let pem = encrypted_pems(b"correct horse").swap_remove(0);
    let state = make_state()
        .with_material(ArtifactId::new("escrowed"), ArtifactValue::Bytes(pem))
        .with_material(
            ArtifactId::new("escrow_passphrase"),
            secret("correct horse"),
        );
    let reads = vec![
        (
            "key_material".to_string(),
            NamedInput::One(ArtifactRef::Produced {
                id: ArtifactId::new("escrowed"),
                property: None,
            }),
        ),
        (
            "passphrase".to_string(),
            NamedInput::One(ArtifactRef::Produced {
                id: ArtifactId::new("escrow_passphrase"),
                property: Some("value".to_string()),
            }),
        ),
    ]
    .into_iter()
    .collect();
    let step = StepInfo::new(
        StepId::new("import"),
        None,
        Some("mock".to_string()),
        Some(ArtifactId::new("restored")),
        Some(StepInputs::Named(reads)),
    );
    let mut harness = ReporterHarness::new();

    let error = run_import(&state, &step, &mut harness).expect_err("a property on a secret");

    assert!(error.to_string().contains("'.value'"), "{error}");
}

#[test]
fn import_key_refuses_material_that_is_not_the_declared_algorithm() {
    let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());
    let material_id = ArtifactId::new("escrowed");
    let state = make_state().with_material(
        material_id.clone(),
        ArtifactValue::Bytes(
            openssl::pkey::PKey::generate_ed25519()
                .unwrap()
                .private_key_to_pkcs8()
                .unwrap(),
        ),
    );
    let step = import_step("import", "restored", material_id);

    let mut harness = ReporterHarness::new();
    let ctx = state.handler_context();
    let mut reporter = harness.reporter(step.id.clone());
    let error = ImportKeyAction
        .execute(
            &step,
            &ctx,
            &serde_json::json!({ "algorithm": "RSA-2048" }),
            &mut reporter,
            Some(&mut backend),
        )
        .expect_err("storing it as RSA would put that name in the transcript");

    let message = error.to_string();
    assert!(
        message.contains("RSA-2048") && message.contains("Ed25519"),
        "the refusal should name both, got: {message}"
    );
}

// ── encrypt_data / decrypt_data ─────────────────────────────────────────────

/// A key-encryption key, which is what `encrypt_data` addresses a container to.
///
/// The metadata comes back rather than an artifact, because these tests run
/// two steps against one key and an [`ArtifactValue`] is consumed by the store.
fn kek(backend: &mut MockBackend, id: &str) -> (ArtifactId, rite_sdk::KeyMetadata) {
    let meta = backend
        .generate_key(key_spec_with(
            id,
            KeyAlgorithm::Aes256,
            KeyPolicy {
                usages: rite_sdk::KeyUsages::WRAP | rite_sdk::KeyUsages::UNWRAP,
                ..KeyPolicy::default()
            },
        ))
        .unwrap();
    (ArtifactId::new(id), meta)
}

fn key_artifact(meta: &rite_sdk::KeyMetadata) -> ArtifactValue {
    ArtifactValue::BackendKey {
        backend_name: "mock".to_string(),
        key_id: meta.key_id.clone(),
        algorithm: meta.algorithm,
        public_key: meta.public_key.clone(),
        check_value: meta.check_value.clone(),
    }
}

/// Encrypt `payload` to a fresh KEK, returning both so a decrypt can follow.
fn encrypt_to_new_kek(
    backend: &mut MockBackend,
    payload: &[u8],
) -> (ArtifactId, rite_sdk::KeyMetadata, ArtifactValue) {
    let (kek_id, meta) = kek(backend, "transport_kek");
    let content_id = ArtifactId::new("archive");
    let state = make_state()
        .with_material(content_id.clone(), ArtifactValue::Bytes(payload.to_vec()))
        .with_material(kek_id.clone(), key_artifact(&meta));
    let step = step_named(
        "encrypt",
        "sealed",
        &[("data", content_id), ("encryption_key", kek_id.clone())],
    );

    let mut harness = ReporterHarness::new();
    let mut result = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        EncryptDataAction
            .execute(
                &step,
                &ctx,
                &serde_json::json!({}),
                &mut reporter,
                Some(backend),
            )
            .expect("encrypt_data completes")
    };

    let sealed = result
        .artifacts
        .pop()
        .expect("encrypt_data produces one artifact")
        .1;
    assert!(
        matches!(sealed, ArtifactValue::EncryptedData(_)),
        "encrypt_data must produce EncryptedData, got {sealed:?}"
    );
    (kek_id, meta, sealed)
}

#[test]
fn encrypt_data_produces_a_container_addressed_to_the_key() {
    let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());
    let (_, meta, sealed) = encrypt_to_new_kek(&mut backend, b"the recovery phrase");

    let ArtifactValue::EncryptedData(encrypted) = &sealed else {
        panic!("encrypt_data produces EncryptedData")
    };
    let expected = meta
        .check_value
        .as_ref()
        .expect("an AES key has a check value");

    // The container names its recipient, so a holder of the key can tell
    // whether the blob is theirs without decrypting anything.
    let envelope =
        rite_sdk::cms::read_kek_enveloped(encrypted.data()).expect("the container reads back");
    assert_eq!(envelope.key_identifier, expected.as_bytes());
    assert_eq!(encrypted.scheme(), rite_sdk::WrapScheme::CmsAes256Gcm);

    // The ciphertext is not the plaintext, which is the one thing a round trip
    // on its own would not catch.
    assert!(
        !envelope
            .ciphertext
            .windows(8)
            .any(|window| window == b"recovery"),
        "the content must not appear in the container"
    );
}

#[test]
fn decrypt_data_recovers_what_encrypt_data_sealed() {
    let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());
    let (kek_id, meta, sealed) = encrypt_to_new_kek(&mut backend, b"the recovery phrase");

    let sealed_id = ArtifactId::new("sealed");
    let state = make_state()
        .with_material(sealed_id.clone(), sealed)
        .with_material(kek_id.clone(), key_artifact(&meta));
    let step = step_named(
        "decrypt",
        "recovered",
        &[("encrypted_data", sealed_id), ("decryption_key", kek_id)],
    );

    let mut harness = ReporterHarness::new();
    let result = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        DecryptDataAction
            .execute(
                &step,
                &ctx,
                &serde_json::json!({}),
                &mut reporter,
                Some(&mut backend),
            )
            .expect("decrypt_data completes")
    };

    // Opened content is the wiped, redacted variant, not plain bytes. The
    // `Debug` form is what a panic message or a log line would print of it.
    let recovered = produced(&result.artifacts, "recovered");
    assert!(
        !format!("{recovered:?}").contains("recovery"),
        "the debug form must not print opened content: {recovered:?}"
    );
    match recovered {
        ArtifactValue::Secret(bytes) => {
            assert_eq!(bytes.expose_secret().as_slice(), b"the recovery phrase");
        }
        other => panic!("decrypt_data must produce Secret, got {other:?}"),
    }
}

#[test]
fn decrypt_data_refuses_a_container_addressed_to_another_key() {
    let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());
    let (_, _, sealed) = encrypt_to_new_kek(&mut backend, b"the recovery phrase");
    let (other_id, other_meta) = kek(&mut backend, "a_different_kek");

    let sealed_id = ArtifactId::new("sealed");
    let state = make_state()
        .with_material(sealed_id.clone(), sealed)
        .with_material(other_id.clone(), key_artifact(&other_meta));
    let step = step_named(
        "decrypt",
        "recovered",
        &[("encrypted_data", sealed_id), ("decryption_key", other_id)],
    );

    let mut harness = ReporterHarness::new();
    let ctx = state.handler_context();
    let mut reporter = harness.reporter(step.id.clone());
    let error = DecryptDataAction
        .execute(
            &step,
            &ctx,
            &serde_json::json!({}),
            &mut reporter,
            Some(&mut backend),
        )
        .expect_err("a container addressed elsewhere does not open");

    // Named before any decrypt is attempted, so the operator is told which key
    // the blob wants rather than that a tag failed.
    let message = error.to_string();
    assert!(
        message.contains("addressed to the key with check value"),
        "the refusal must name the recipient, got: {message}"
    );
}

#[test]
fn encrypt_data_refuses_a_key_that_is_not_a_256_bit_secret() {
    let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());
    let (key_id, key) = backend_key(&mut backend, "signing_key", KeyAlgorithm::EcdsaP256);
    let content_id = ArtifactId::new("archive");
    let state = make_state()
        .with_material(
            content_id.clone(),
            ArtifactValue::Bytes(b"payload".to_vec()),
        )
        .with_material(key_id.clone(), key);
    let step = step_named(
        "encrypt",
        "sealed",
        &[("data", content_id), ("encryption_key", key_id)],
    );

    let mut harness = ReporterHarness::new();
    let ctx = state.handler_context();
    let mut reporter = harness.reporter(step.id.clone());
    let error = EncryptDataAction
        .execute(
            &step,
            &ctx,
            &serde_json::json!({}),
            &mut reporter,
            Some(&mut backend),
        )
        .expect_err("a keypair is not a recipient this container addresses");

    let message = error.to_string();
    assert!(
        message.contains("256-bit symmetric key") && message.contains("ECDSA-P256"),
        "the refusal must name what was asked for and what was given, got: {message}"
    );
}

#[test]
fn decrypt_data_refuses_a_wrapped_key() {
    let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());
    let (kek_id, meta) = kek(&mut backend, "transport_kek");
    let wrapped_id = ArtifactId::new("wrapped");
    let state = make_state()
        .with_material(wrapped_id.clone(), ArtifactValue::Bytes(vec![0u8; 16]))
        .with_material(kek_id.clone(), key_artifact(&meta));
    let step = step_named(
        "decrypt",
        "recovered",
        &[("encrypted_data", wrapped_id), ("decryption_key", kek_id)],
    );

    let mut harness = ReporterHarness::new();
    let ctx = state.handler_context();
    let mut reporter = harness.reporter(step.id.clone());
    let error = DecryptDataAction
        .execute(
            &step,
            &ctx,
            &serde_json::json!({}),
            &mut reporter,
            Some(&mut backend),
        )
        .expect_err("only an encrypted-data artifact opens here");

    // The two container-bearing artifact types hold the same bytes, so the
    // message points at the step that does handle the other one.
    assert!(
        error.to_string().contains("unwrap_key"),
        "the refusal must name the step that opens a wrapped key, got: {error}"
    );
}

// ── secret sharing ──────────────────────────────────────────────────────────

/// A step whose named inputs are properties of one artifact, the way a drill
/// names `${artifact.shares.share_1}`.
///
/// A `combine_shares` step reading the given shares, each `(artifact, property)`,
/// as its `shares:` list in that order.
fn combine_step(shares: &[(&ArtifactId, Option<&str>)]) -> StepInfo {
    let list = shares
        .iter()
        .map(|(id, property)| ArtifactRef::Produced {
            id: (*id).clone(),
            property: property.map(str::to_string),
        })
        .collect();
    let map = HashMap::from([("shares".to_string(), NamedInput::Many(list))]);
    StepInfo::new(
        StepId::new("combine"),
        None,
        None,
        Some(ArtifactId::new("recovered")),
        Some(StepInputs::Named(map)),
    )
}

fn split(
    backend: &mut MockBackend,
    harness: &mut ReporterHarness,
    secret: &[u8],
    threshold: u8,
    shares: u8,
) -> (ExecutionState, ArtifactValue) {
    let secret_id = ArtifactId::new("seed_entropy");
    let state =
        make_state().with_material(secret_id.clone(), ArtifactValue::Bytes(secret.to_vec()));
    let step = step_named("split", "shares", &[("secret", secret_id)]);
    let made = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        SplitSecretAction
            .execute(
                &step,
                &ctx,
                &serde_json::json!({ "threshold": threshold, "shares": shares }),
                &mut reporter,
                Some(backend),
            )
            .expect("split_secret completes")
    };
    let (_, value) = made.artifacts.into_iter().next().expect("one artifact");
    (state, value)
}

#[test]
fn combine_shares_recovers_what_split_secret_made() {
    let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());
    let mut harness = ReporterHarness::new();
    let secret = b"32 bytes of wallet seed entropy!";
    let (state, shares) = split(&mut backend, &mut harness, secret, 2, 3);

    assert!(
        !format!("{shares:?}").contains("wallet"),
        "the debug form must not print a share: {shares:?}"
    );
    let ArtifactValue::Shares(set) = &shares else {
        panic!("split_secret must produce Shares, got {shares:?}");
    };
    assert_eq!((set.threshold(), set.count()), (2, 3));

    // The fact says how, and nothing of what.
    let inputs = harness
        .facts()
        .iter()
        .find_map(|f| match f {
            StepFact::BackendOperation { kind, inputs, .. } if kind == "split_secret" => {
                Some(inputs.clone())
            }
            _ => None,
        })
        .expect("split_secret records an operation");
    assert_eq!(inputs.get("scheme").unwrap(), "rite-sss/v1");
    assert!(!inputs.to_string().contains("wallet"));
    assert!(!inputs.to_string().contains("32"), "no length: {inputs}");

    // Two of three, out of order, by property.
    let shares_id = ArtifactId::new("shares");
    let state = state.with_material(shares_id.clone(), shares);
    let combine = combine_step(&[(&shares_id, Some("share_3")), (&shares_id, Some("share_1"))]);
    let recovered = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(combine.id.clone());
        CombineSharesAction
            .execute(&combine, &ctx, &serde_json::json!({}), &mut reporter, None)
            .expect("combine_shares completes")
    };
    match produced(&recovered.artifacts, "recovered") {
        ArtifactValue::Secret(bytes) => assert_eq!(bytes.expose_secret().as_slice(), secret),
        other => panic!("combine_shares must produce Secret, got {other:?}"),
    }
}

#[test]
fn combine_shares_refuses_fewer_than_the_threshold() {
    let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());
    let mut harness = ReporterHarness::new();
    let (state, shares) = split(&mut backend, &mut harness, &[7; 16], 3, 4);
    let shares_id = ArtifactId::new("shares");
    let state = state.with_material(shares_id.clone(), shares);
    let combine = combine_step(&[(&shares_id, Some("share_2")), (&shares_id, Some("share_4"))]);
    let ctx = state.handler_context();
    let mut reporter = harness.reporter(combine.id.clone());
    let error = CombineSharesAction
        .execute(&combine, &ctx, &serde_json::json!({}), &mut reporter, None)
        .expect_err("two shares of a 3-of-4 split are not enough");
    assert!(error.to_string().contains("3 needed"), "{error}");
}

/// The drill's shape: two shares come back as bytes, each decoded into a set
/// of one, and `combine_shares` names them without a property.
#[test]
fn shares_that_left_as_bytes_come_back_and_combine() {
    let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());
    let mut harness = ReporterHarness::new();
    let secret = b"32 bytes of wallet seed entropy!";
    let (state, shares) = split(&mut backend, &mut harness, secret, 2, 3);
    let ArtifactValue::Shares(set) = &shares else {
        panic!("split_secret must produce Shares");
    };

    // What leaves the machine, per share: the wire layout of its parts.
    let leave = |index: u8| {
        let share = set.share(index).expect("share exists");
        let math = gf256::Share::new(share.threshold(), share.index(), share.y().to_vec()).unwrap();
        wire::encode(&math)
    };
    let bytes_2 = leave(2);
    let bytes_3 = leave(3);
    assert_eq!(
        bytes_2.get(..3),
        Some(&[1, 2, 2][..]),
        "version, threshold, index"
    );

    // What comes back: each decoded into a set of one, as a typed-back share
    // will arrive.
    let arrive = |bytes: &[u8]| {
        let (threshold, index, y) = wire::decode(bytes).unwrap().into_parts();
        ArtifactValue::Shares(ShareSet::new(threshold, [Share::new(threshold, index, y)]))
    };
    let a = ArtifactId::new("custodian_a");
    let b = ArtifactId::new("custodian_b");
    let state = state
        .with_material(a.clone(), arrive(&bytes_3))
        .with_material(b.clone(), arrive(&bytes_2));
    let combine = combine_step(&[(&a, None), (&b, None)]);

    let recovered = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(combine.id.clone());
        CombineSharesAction
            .execute(&combine, &ctx, &serde_json::json!({}), &mut reporter, None)
            .expect("combine_shares completes")
    };
    match produced(&recovered.artifacts, "recovered") {
        ArtifactValue::Secret(bytes) => assert_eq!(bytes.expose_secret().as_slice(), secret),
        other => panic!("combine_shares must produce Secret, got {other:?}"),
    }
}

#[test]
fn split_secret_refuses_a_split_with_too_many_subsets_to_check() {
    let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());
    let secret_id = ArtifactId::new("s");
    let state = make_state().with_material(secret_id.clone(), ArtifactValue::Bytes(vec![7; 16]));
    let step = step_named("split", "shares", &[("secret", secret_id)]);
    let mut harness = ReporterHarness::new();
    let ctx = state.handler_context();
    let mut reporter = harness.reporter(step.id.clone());
    // 8-of-17 is 24,310 subsets and fine; 9-of-20 is 167,960 and is not.
    let error = SplitSecretAction
        .execute(
            &step,
            &ctx,
            &serde_json::json!({ "threshold": 9, "shares": 20 }),
            &mut reporter,
            Some(&mut backend),
        )
        .expect_err("9-of-20 has more subsets than the step verifies");
    assert!(error.to_string().contains("167960"), "{error}");
    assert!(error.to_string().contains("100000"), "{error}");

    // The share limit is the scheme's, checked before the subsets are counted.
    let mut reporter = harness.reporter(step.id.clone());
    let error = SplitSecretAction
        .execute(
            &step,
            &ctx,
            &serde_json::json!({ "threshold": 2, "shares": 101 }),
            &mut reporter,
            Some(&mut backend),
        )
        .expect_err("rite-sss/v1 makes at most 100 shares");
    assert!(error.to_string().contains("at most 100"), "{error}");
}
