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
use rite_stdlib::{
    GenerateCsrAction, GenerateKeypairAction, IssueCertificateAction, SignDataAction,
    VerifySignatureAction,
};
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

/// Run `verify_signature` over the artifacts in `signed`, keyed on `signing_key`.
fn verify(
    signed: &mut Signed,
    params: &serde_json::Value,
    backend: Option<&str>,
) -> Result<(), String> {
    verify_under("signing_key", signed, params, backend)
}

/// Run `verify_signature`, naming `key_artifact` as the verification key.
fn verify_under(
    key_artifact: &str,
    signed: &mut Signed,
    params: &serde_json::Value,
    backend: Option<&str>,
) -> Result<(), String> {
    let verify_step = step(
        "verify",
        None,
        backend,
        named_inputs(&[
            ("key", key_artifact),
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

/// A signer's public key normally reaches a ceremony wrapped in a certificate
/// rather than on its own: `piv_read_certificate` reads one off the card, and a
/// counterparty sends one. Naming that certificate as the key has to work, or
/// the hardware case the action exists for cannot be expressed at all.
#[test]
fn verifies_against_a_certificate_carrying_the_signers_key() {
    let mut signed = issue_self_signed_certificate(sign_with("ECDSA-P256", &serde_json::json!({})));

    verify_under("signing_cert", &mut signed, &serde_json::json!({}), None)
        .expect("a certificate must serve as the verification key");
}

/// The certificate path must not become a way to skip the check. The same
/// certificate over other bytes still has to fail.
#[test]
fn fails_against_a_certificate_when_the_data_differs() {
    let mut signed = issue_self_signed_certificate(sign_with("ECDSA-P256", &serde_json::json!({})))
        .replace(
            "document",
            ArtifactValue::Bytes(b"a different manifest".to_vec()),
        );

    let err = verify_under("signing_cert", &mut signed, &serde_json::json!({}), None)
        .expect_err("verification must fail for data that was never signed");
    assert!(err.contains("does not match"), "{err}");
}

/// A device that never exports its key can still verify what it signed. Only
/// software verification needs the key material, so refusing the step outright
/// would rule out exactly the hardware verifier the backend path exists for.
#[test]
fn verifies_a_non_exportable_backend_key_through_its_own_backend() {
    let signed = sign_with("ECDSA-P256", &serde_json::json!({}));

    // The same key as the backend holds it, minus the public half: what a
    // signing-only device reports about its slot.
    let stripped = {
        let ctx = signed.state.handler_context();
        match ctx.artifacts.get(&ArtifactId::new("signing_key")) {
            Some(ArtifactValue::BackendKey {
                backend_name,
                key_id,
                algorithm,
                ..
            }) => ArtifactValue::BackendKey {
                backend_name: backend_name.clone(),
                key_id: key_id.clone(),
                algorithm: *algorithm,
                public_key: None,
            },
            other => panic!("expected a backend key, got {other:?}"),
        }
    };
    let mut signed = signed.replace("signing_key", stripped);

    verify(&mut signed, &serde_json::json!({}), Some("openssl"))
        .expect("the backend must verify a key it does not export");

    // Without a backend there is nothing to verify against, and the error has
    // to say which way out the author has.
    let err = verify(&mut signed, &serde_json::json!({}), None)
        .expect_err("software verification has no key material to work with");
    assert!(err.contains("does not expose a public key"), "{err}");
    assert!(err.contains("Name that backend"), "{err}");
}

/// Issue a self-signed certificate over `signing_key` and store it as
/// `signing_cert`, standing in for a certificate read off a card.
fn issue_self_signed_certificate(signed: Signed) -> Signed {
    let Signed {
        mut backend,
        mut harness,
        mut state,
    } = signed;

    let csr_step = step(
        "csr",
        Some("csr"),
        Some("openssl"),
        named_inputs(&[("signing_key", "signing_key")]),
    );
    let csr = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(csr_step.id.clone());
        GenerateCsrAction
            .execute(
                &csr_step,
                &ctx,
                &serde_json::json!({ "subject": "CN=Release Signer" }),
                &mut reporter,
                Some(&mut backend),
            )
            .expect("generate_csr")
    };
    for (id, value) in csr.artifacts {
        state = state.with_material(id, value);
    }

    let cert_step = step(
        "issue",
        Some("signing_cert"),
        Some("openssl"),
        named_inputs(&[("signing_key", "signing_key"), ("csr", "csr")]),
    );
    let cert = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(cert_step.id.clone());
        IssueCertificateAction
            .execute(
                &cert_step,
                &ctx,
                &serde_json::json!({ "profile": "root_ca", "validity_days": 365 }),
                &mut reporter,
                Some(&mut backend),
            )
            .expect("issue_certificate")
    };
    for (id, value) in cert.artifacts {
        state = state.with_material(id, value);
    }

    Signed {
        backend,
        harness,
        state,
    }
}
