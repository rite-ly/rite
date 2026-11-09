// The `sign_data` and `verify_signature` actions, beyond the algorithms.
//
// What each algorithm signs and verifies, and each form the key arrives in,
// is the algorithm matrix (`tests/algorithms/`). What it cannot show is that
// verification would have failed: a check that always passes is worth
// nothing, so the negative cases live here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rite_model::{ArtifactId, ArtifactRef, NamedInput, StepId, StepInputs};
use rite_openssl::OpenSslBackend;
use rite_runtime::{
    Action, ArtifactValue, ExecutionState, StepInfo, test_support::ReporterHarness,
};
use rite_stdlib::{
    GenerateCsrAction, GenerateKeyAction, IssueCertificateAction, SignDataAction,
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
                    NamedInput::One(ArtifactRef::Produced {
                        id: ArtifactId::new(*id),
                        property: None,
                    }),
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
        GenerateKeyAction
            .execute(
                &keygen_step,
                &ctx,
                &serde_json::json!({ "algorithm": algorithm }),
                &mut reporter,
                Some(&mut backend),
            )
            .unwrap_or_else(|e| panic!("generate_key {algorithm}: {e}"))
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

/// An RSA key admits two schemes, so the algorithm named at signing time has to
/// reach verification: deriving it from the key picks PKCS#1 v1.5, which a PSS
/// signature must fail. That it verifies when the scheme is named is a row of
/// the algorithm matrix.
#[test]
fn a_pss_signature_does_not_verify_under_the_default_scheme() {
    let mut signed = sign_with(
        "RSA-2048",
        &serde_json::json!({ "algorithm": "RSA-PSS-SHA256" }),
    );

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

/// Bytes that are neither DER nor `r || s` of the curve's width are refused
/// by name, not handed to the verifier.
#[test]
fn fails_when_the_signature_is_corrupt() {
    let mut signed = sign_with("ECDSA-P256", &serde_json::json!({}))
        .replace("signature", ArtifactValue::Bytes(vec![0u8; 70]));

    let err = verify(&mut signed, &serde_json::json!({}), None)
        .expect_err("a corrupt signature must fail the step");
    assert!(
        err.contains("takes a DER signature, or r || s in 64 bytes, and this one is 70 bytes"),
        "{err}"
    );
}

/// `r || s` of the right width is read, and still has to match.
#[test]
fn fails_when_a_raw_signature_does_not_match() {
    let mut signed = sign_with("ECDSA-P256", &serde_json::json!({}))
        .replace("signature", ArtifactValue::Bytes(vec![0x01; 64]));

    let err = verify(&mut signed, &serde_json::json!({}), None)
        .expect_err("a raw signature that was never made must fail");
    assert!(err.contains("does not match"), "{err}");
}

/// Naming a backend delegates the check to it. A remote or hardware verifier
/// needs this, and the result must agree with the software path.
#[test]
fn delegates_to_the_backend_when_the_step_names_one() {
    let mut signed = sign_with("ECDSA-P256", &serde_json::json!({}));
    verify(&mut signed, &serde_json::json!({}), Some("openssl"))
        .expect("the backend must verify its own signature");
}

/// A certificate can serve as the verification key, not just a bare one. This
/// is the only way to check a signature from a device that never exports its
/// key, since `piv_read_certificate` yields a certificate.
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

/// A key the device never exports cannot be verified, by anyone.
///
/// Naming the signing backend does not rescue it. Verification takes a public
/// key, and there is none; a signature only its producing device can check is
/// not evidence an auditor can confirm from the transcript. Both ways out say
/// the same thing, which is the point of resolving the key before choosing a
/// verifier.
#[test]
fn refuses_a_backend_key_that_exports_no_public_half() {
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
                check_value: None,
            },
            other => panic!("expected a backend key, got {other:?}"),
        }
    };
    let mut signed = signed.replace("signing_key", stripped);

    for backend in [Some("openssl"), None] {
        let err = verify(&mut signed, &serde_json::json!({}), backend)
            .expect_err("there is no public key to verify under");
        assert!(err.contains("does not export it"), "{err}");
    }
}

/// Issue a self-signed certificate over `signing_key` and store it as
/// `signing_cert`, standing in for a certificate read off a card.
fn issue_self_signed_certificate(mut signed: Signed) -> Signed {
    let csr_step = step(
        "csr",
        Some("csr"),
        Some("openssl"),
        named_inputs(&[("signing_key", "signing_key")]),
    );
    let csr = {
        let ctx = signed.state.handler_context();
        let mut reporter = signed.harness.reporter(csr_step.id.clone());
        GenerateCsrAction
            .execute(
                &csr_step,
                &ctx,
                &serde_json::json!({ "subject": "CN=Release Signer" }),
                &mut reporter,
                Some(&mut signed.backend),
            )
            .expect("generate_csr")
    };
    for (id, value) in csr.artifacts {
        signed.state = signed.state.with_material(id, value);
    }

    let cert_step = step(
        "issue",
        Some("signing_cert"),
        Some("openssl"),
        named_inputs(&[("signing_key", "signing_key"), ("csr", "csr")]),
    );
    let cert = {
        let ctx = signed.state.handler_context();
        let mut reporter = signed.harness.reporter(cert_step.id.clone());
        IssueCertificateAction
            .execute(
                &cert_step,
                &ctx,
                &serde_json::json!({ "profile": "root_ca", "validity_days": 365 }),
                &mut reporter,
                Some(&mut signed.backend),
            )
            .expect("issue_certificate")
    };
    for (id, value) in cert.artifacts {
        signed.state = signed.state.with_material(id, value);
    }

    signed
}

/// Naming a backend picks who checks the signature, never what is checked.
///
/// The same certificate artifact that verifies in software verifies through a
/// backend, with no `backend:`-shaped input rules of its own.
#[test]
fn a_named_backend_verifies_the_same_input_software_does() {
    let signed = sign_with("ECDSA-P256", &serde_json::json!({}));
    let mut signed = issue_self_signed_certificate(signed);

    verify_under("signing_cert", &mut signed, &serde_json::json!({}), None)
        .expect("software verifies under the certificate");
    verify_under(
        "signing_cert",
        &mut signed,
        &serde_json::json!({}),
        Some("openssl"),
    )
    .expect("the backend verifies under the same certificate");
}

/// A named backend reads `r || s` as software does: the step rewrites it
/// before either verifier sees it.
#[test]
fn a_named_backend_verifies_a_raw_signature() {
    let signed = sign_with("ECDSA-P256", &serde_json::json!({}));
    let der = match signed
        .state
        .handler_context()
        .artifacts
        .get(&ArtifactId::new("signature"))
    {
        Some(ArtifactValue::Bytes(bytes)) => bytes.clone(),
        other => panic!("sign_data wrote {other:?}"),
    };
    let sig = openssl::ecdsa::EcdsaSig::from_der(&der).unwrap();
    let mut raw = sig.r().to_vec_padded(32).unwrap();
    raw.extend(sig.s().to_vec_padded(32).unwrap());
    let mut signed = signed.replace("signature", ArtifactValue::Bytes(raw));

    verify(&mut signed, &serde_json::json!({}), Some("openssl"))
        .expect("the backend verifies the same signature as r || s");
}
