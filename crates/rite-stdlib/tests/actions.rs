//! Focused tests for stdlib actions: each executes one action and asserts its
//! single responsibility (its outcome, the fact it records, or the artifact it
//! produces), not that a whole ceremony runs.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;

use rite_model::{ArtifactId, ArtifactRef, StepFact, StepId, StepInputs};
use rite_runtime::{
    Action, ArtifactValue, ExecutionState, Response, StepInfo, test_support::ReporterHarness,
};
use rite_sdk::{KeyAlgorithm, KeyPolicy, KeySpec, KeyStoreBackend};
use rite_stdlib::{
    AttestAction, CheckValueAction, ClockCheckAction, ConfirmAction, ExportPublicAction,
    GatherEntropyAction, MachineInfoAction, MockBackend, OralReadbackAction, UnwrapKeyAction,
    WrapKeyAction,
};

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
    harness.respond(0, Response::Bool(true));
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
    harness.respond(0, Response::Bool(true));
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
    harness.respond(0, Response::Text("attest".to_string()));
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
    harness.respond(0, Response::Text("3 1 4 1 5 9 2 6".to_string()));
    let state = make_state();
    let step = bare_step("entropy");

    let result = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        GatherEntropyAction.execute(&step, &ctx, &serde_json::json!({}), &mut reporter, None)
    };

    result.expect("a non-empty contribution is folded and the step completes");
}

#[test]
fn oral_readback_completes_on_confirmation() {
    let mut harness = ReporterHarness::new();
    harness.respond(0, Response::Bool(true));
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

fn key_spec(label: &str, algorithm: KeyAlgorithm) -> KeySpec {
    KeySpec {
        algorithm,
        label: label.to_string(),
        policy: KeyPolicy::default(),
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
    let meta = backend.generate_key(key_spec(id, algorithm)).unwrap();
    (
        ArtifactId::new(id),
        ArtifactValue::BackendKey {
            backend_name: "mock".to_string(),
            key_id: meta.key_id,
            algorithm: meta.algorithm,
            public_key: meta.public_key,
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
                ArtifactRef::Produced {
                    id: id.clone(),
                    property: None,
                },
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
    // CMS-RSA-GCM (the action default) wraps to an RSA recipient.
    let (recipient_id, recipient) = backend_key(&mut backend, "recipient", KeyAlgorithm::Rsa4096);
    let (secret_id, secret) = backend_key(&mut backend, "secret_key", KeyAlgorithm::Rsa4096);
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
