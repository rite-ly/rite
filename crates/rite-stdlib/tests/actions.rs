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
    AttestAction, CheckValueAction, ClockCheckAction, ConfirmAction, DecryptDataAction,
    EncryptDataAction, ExportPublicAction, GatherEntropyAction, ImportKeyAction, MachineInfoAction,
    MockBackend, OralReadbackAction, UnwrapKeyAction, WrapKeyAction,
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
#[test]
fn import_key_refuses_an_encrypted_pem_by_name() {
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let key = openssl::pkey::PKey::from_rsa(rsa).unwrap();
    let cipher = openssl::symm::Cipher::aes_256_cbc();
    let pkcs8 = key
        .private_key_to_pem_pkcs8_passphrase(cipher, b"secret")
        .unwrap();
    let traditional = key
        .rsa()
        .unwrap()
        .private_key_to_pem_passphrase(cipher, b"secret")
        .unwrap();
    assert!(
        traditional.windows(10).any(|w| w == b"Proc-Type:"),
        "the traditional form marks the body, not the preamble"
    );

    for pem in [pkcs8, traditional] {
        let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());
        let material_id = ArtifactId::new("escrowed");
        let state = make_state().with_material(material_id.clone(), ArtifactValue::Bytes(pem));
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
            .expect_err("a ceremony carries no passphrase");

        assert!(
            error.to_string().contains("encrypted PEM"),
            "the refusal should name the encoding, got: {error}"
        );
    }
}

#[test]
fn import_key_refuses_material_that_is_not_the_declared_algorithm() {
    let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());
    let material_id = ArtifactId::new("escrowed");
    let state = make_state().with_material(
        material_id.clone(),
        ArtifactValue::Bytes(import_material(KeyAlgorithm::Ed25519)),
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

/// Valid import material for one algorithm: the key itself for a symmetric
/// one, PKCS#8 DER for every other.
///
/// The wildcard arm fails rather than skipping. `KeyAlgorithm` is
/// `#[non_exhaustive]`, so a match here cannot be compiler-complete, and a new
/// algorithm should surface as a failing test rather than as silence.
fn import_material(algorithm: KeyAlgorithm) -> Vec<u8> {
    use openssl::pkey::{Id, KeyType, PKey};

    fn pkcs8(key: &PKey<openssl::pkey::Private>) -> Vec<u8> {
        key.private_key_to_pkcs8().unwrap()
    }
    fn from_seed(key_type: KeyType, seed_len: usize) -> Vec<u8> {
        let seed = vec![9u8; seed_len];
        pkcs8(&PKey::private_key_from_seed(None, key_type, None, &seed).unwrap())
    }
    fn ec(nid: openssl::nid::Nid) -> Vec<u8> {
        let group = openssl::ec::EcGroup::from_curve_name(nid).unwrap();
        pkcs8(&PKey::from_ec_key(openssl::ec::EcKey::generate(&group).unwrap()).unwrap())
    }

    match algorithm {
        KeyAlgorithm::Aes128 | KeyAlgorithm::Aes256 => {
            vec![7u8; algorithm.key_bytes().unwrap()]
        }
        KeyAlgorithm::Rsa2048 => {
            pkcs8(&PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap())
        }
        KeyAlgorithm::Rsa4096 => {
            pkcs8(&PKey::from_rsa(openssl::rsa::Rsa::generate(4096).unwrap()).unwrap())
        }
        KeyAlgorithm::EcdsaP256 => ec(openssl::nid::Nid::X9_62_PRIME256V1),
        KeyAlgorithm::EcdsaP384 => ec(openssl::nid::Nid::SECP384R1),
        KeyAlgorithm::Ed25519 => {
            let key = PKey::generate_ed25519().unwrap();
            assert_eq!(key.id(), Id::ED25519);
            pkcs8(&key)
        }
        KeyAlgorithm::MlDsa44 => from_seed(KeyType::ML_DSA_44, 32),
        KeyAlgorithm::MlDsa65 => from_seed(KeyType::ML_DSA_65, 32),
        KeyAlgorithm::MlDsa87 => from_seed(KeyType::ML_DSA_87, 32),
        KeyAlgorithm::MlKem512 => from_seed(KeyType::ML_KEM_512, 64),
        KeyAlgorithm::MlKem768 => from_seed(KeyType::ML_KEM_768, 64),
        KeyAlgorithm::MlKem1024 => from_seed(KeyType::ML_KEM_1024, 64),
        other => {
            panic!("import_material has no case for {other}, so import_key is untested for it")
        }
    }
}

/// Every algorithm the SDK offers, imported once, on whatever build is running.
///
/// The two arms of `import_key` differ in how they read the material and in
/// what names the key afterwards, so both are asserted per algorithm rather
/// than once for the family.
#[test]
fn import_key_accepts_every_algorithm_this_build_supports() {
    let algorithms = [
        KeyAlgorithm::Rsa2048,
        KeyAlgorithm::Rsa4096,
        KeyAlgorithm::EcdsaP256,
        KeyAlgorithm::EcdsaP384,
        KeyAlgorithm::Ed25519,
        KeyAlgorithm::MlDsa44,
        KeyAlgorithm::MlDsa65,
        KeyAlgorithm::MlDsa87,
        KeyAlgorithm::MlKem512,
        KeyAlgorithm::MlKem768,
        KeyAlgorithm::MlKem1024,
        KeyAlgorithm::Aes128,
        KeyAlgorithm::Aes256,
    ];

    let mut exercised = 0;
    for algorithm in algorithms {
        // Build-relative, exactly as at generation: an OpenSSL without the
        // post-quantum providers cannot read that material either.
        if rite_openssl::build_limitation(algorithm).is_some() {
            continue;
        }
        exercised += 1;

        let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());
        let material_id = ArtifactId::new("material");
        let state = make_state().with_material(
            material_id.clone(),
            ArtifactValue::Bytes(import_material(algorithm)),
        );
        let step = import_step("import", "imported", material_id);

        let mut harness = ReporterHarness::new();
        let result = {
            let ctx = state.handler_context();
            let mut reporter = harness.reporter(step.id.clone());
            ImportKeyAction
                .execute(
                    &step,
                    &ctx,
                    &serde_json::json!({ "algorithm": algorithm.to_string() }),
                    &mut reporter,
                    Some(&mut backend),
                )
                .unwrap_or_else(|e| panic!("import_key must accept {algorithm}: {e}"))
        };

        match produced(&result.artifacts, "imported") {
            ArtifactValue::BackendKey {
                algorithm: imported,
                public_key,
                check_value,
                ..
            } => {
                assert_eq!(*imported, algorithm);
                if algorithm.is_symmetric() {
                    assert!(public_key.is_none(), "{algorithm} has no public half");
                    assert!(
                        check_value.is_some(),
                        "{algorithm} is named by its check value"
                    );
                } else {
                    assert!(
                        public_key.is_some(),
                        "{algorithm} is named by its public half"
                    );
                    assert!(check_value.is_none(), "{algorithm} has no check value");
                }
            }
            other => panic!("import_key must produce a BackendKey for {algorithm}, got {other:?}"),
        }
    }

    // Only the post-quantum set is build-relative, so a run that exercised
    // fewer than the rest skipped something it should not have, and the test
    // would otherwise pass by doing nothing.
    assert!(
        exercised >= 7,
        "only {exercised} algorithms were exercised; the classical and symmetric \
         ones are supported by every build"
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

    match produced(&result.artifacts, "recovered") {
        ArtifactValue::Bytes(bytes) => assert_eq!(bytes.as_slice(), b"the recovery phrase"),
        other => panic!("decrypt_data must produce Bytes, got {other:?}"),
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
