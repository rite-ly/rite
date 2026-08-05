// Round trip through the `sign_data` and `verify_signature` actions.
//
// The example ceremony covers the happy path end to end. What it cannot show is
// that verification would have failed: a check that always passes is worth
// nothing, so the negative cases live here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rite_model::{ArtifactId, ArtifactRef, StepId, StepInputs};
use rite_openssl::OpenSslBackend;
use rite_runtime::{
    Action, ArtifactValue, ExecutionState, StepInfo, test_support::ReporterHarness,
};
use rite_stdlib::{GenerateKeypairAction, SignDataAction, VerifySignatureAction};
use std::collections::HashMap;

const MESSAGE: &[u8] = b"rite release manifest";

fn named_inputs(pairs: &[(&str, &str)]) -> StepInputs {
    StepInputs::Named(
        pairs
            .iter()
            .map(|(name, id)| {
                (
                    (*name).to_string(),
                    ArtifactRef::Produced {
                        id: ArtifactId::new(*id),
                        property: None,
                    },
                )
            })
            .collect(),
    )
}

fn step(id: &str, produces: Option<&str>, backend: Option<&str>, inputs: StepInputs) -> StepInfo {
    StepInfo::new(
        StepId::new(id),
        None,
        backend.map(ToString::to_string),
        produces.map(ArtifactId::new),
        Some(inputs),
    )
}

/// A ceremony carried far enough to have a key, a document, and a signature.
struct Signed {
    backend: OpenSslBackend,
    harness: ReporterHarness,
    state: ExecutionState,
}

impl Signed {
    /// Overwrite an artifact, to stage what a tampered ceremony would hold.
    fn replace(self, id: &str, value: ArtifactValue) -> Self {
        Self {
            state: self.state.with_material(ArtifactId::new(id), value),
            ..self
        }
    }
}

/// Generate a key of `algorithm` and sign `MESSAGE` with it.
fn sign_with(algorithm: &str, sign_params: &serde_json::Value) -> Signed {
    let mut backend = OpenSslBackend::try_new("openssl").unwrap();
    let mut harness = ReporterHarness::new();
    let mut state = ExecutionState::new(HashMap::new(), HashMap::new(), HashMap::new(), false);

    let keygen_step = step(
        "generate",
        Some("signing_key"),
        Some("openssl"),
        StepInputs::Named(HashMap::new()),
    );
    let keygen = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(keygen_step.id.clone());
        GenerateKeypairAction
            .execute(
                &keygen_step,
                &ctx,
                &serde_json::json!({ "algorithm": algorithm }),
                &mut reporter,
                Some(&mut backend),
            )
            .unwrap_or_else(|e| panic!("generate_keypair {algorithm}: {e}"))
    };
    for (id, value) in keygen.artifacts {
        state = state.with_material(id, value);
    }
    state = state.with_material(
        ArtifactId::new("document"),
        ArtifactValue::Bytes(MESSAGE.to_vec()),
    );

    let sign_step = step(
        "sign",
        Some("signature"),
        Some("openssl"),
        named_inputs(&[("key", "signing_key"), ("data", "document")]),
    );
    let signed = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(sign_step.id.clone());
        SignDataAction
            .execute(
                &sign_step,
                &ctx,
                sign_params,
                &mut reporter,
                Some(&mut backend),
            )
            .unwrap_or_else(|e| panic!("sign_data {algorithm}: {e}"))
    };
    for (id, value) in signed.artifacts {
        state = state.with_material(id, value);
    }

    Signed {
        backend,
        harness,
        state,
    }
}

/// Run `verify_signature` over the artifacts in `signed`.
fn verify(
    signed: &mut Signed,
    params: &serde_json::Value,
    backend: Option<&str>,
) -> Result<(), String> {
    let verify_step = step(
        "verify",
        None,
        backend,
        named_inputs(&[
            ("key", "signing_key"),
            ("data", "document"),
            ("signature", "signature"),
        ]),
    );
    let ctx = signed.state.handler_context();
    let mut reporter = signed.harness.reporter(verify_step.id.clone());
    // The executor supplies a backend exactly when the step names one.
    let backend_arg: Option<&mut dyn rite_sdk::Backend> =
        backend.map(|_| &mut signed.backend as &mut dyn rite_sdk::Backend);
    VerifySignatureAction
        .execute(&verify_step, &ctx, params, &mut reporter, backend_arg)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[test]
fn verifies_a_signature_it_just_produced() {
    let mut signed = sign_with("ECDSA-P256", &serde_json::json!({}));
    verify(&mut signed, &serde_json::json!({}), None).expect("signature must verify");
}

/// ML-DSA signing is hedged, so the same key over the same message gives
/// different bytes each time. The assertion is that verification succeeds, never
/// that the signature equals a fixed value.
#[test]
fn verifies_a_post_quantum_signature() {
    if !rite_openssl::ML_DSA_AVAILABLE {
        return;
    }
    let mut signed = sign_with("ML-DSA-65", &serde_json::json!({}));
    verify(&mut signed, &serde_json::json!({}), None).expect("ML-DSA signature must verify");
}

/// An RSA key admits two schemes, so the algorithm named at signing time has to
/// reach verification. Deriving it from the key would pick PKCS#1 v1.5 and fail.
#[test]
fn round_trips_an_rsa_pss_signature_through_the_override() {
    let mut signed = sign_with(
        "RSA-2048",
        &serde_json::json!({ "algorithm": "RSA-PSS-SHA256" }),
    );

    verify(
        &mut signed,
        &serde_json::json!({ "algorithm": "RSA-PSS-SHA256" }),
        None,
    )
    .expect("PSS signature must verify when the scheme is named");

    let err = verify(&mut signed, &serde_json::json!({}), None)
        .expect_err("a PSS signature must not verify as PKCS#1 v1.5");
    assert!(err.contains("does not match"), "{err}");
}

/// The whole point of a verification step. A signature over other bytes must
/// fail the step, not be recorded as checked.
#[test]
fn fails_when_the_signed_data_differs() {
    let mut signed = sign_with("ECDSA-P256", &serde_json::json!({})).replace(
        "document",
        ArtifactValue::Bytes(b"a different manifest".to_vec()),
    );

    let err = verify(&mut signed, &serde_json::json!({}), None)
        .expect_err("verification must fail for data that was never signed");
    assert!(err.contains("does not match"), "{err}");
}

#[test]
fn fails_when_the_signature_is_corrupt() {
    let mut signed = sign_with("ECDSA-P256", &serde_json::json!({}))
        .replace("signature", ArtifactValue::Bytes(vec![0u8; 70]));

    assert!(
        verify(&mut signed, &serde_json::json!({}), None).is_err(),
        "a corrupt signature must fail the step"
    );
}

/// Naming a backend delegates the check to it, which is what a remote or
/// hardware verifier needs. The result must agree with the software path.
#[test]
fn delegates_to_the_backend_when_the_step_names_one() {
    let mut signed = sign_with("ECDSA-P256", &serde_json::json!({}));
    verify(&mut signed, &serde_json::json!({}), Some("openssl"))
        .expect("the backend must verify its own signature");
}
