// Every key algorithm the PKI actions accept must survive the full chain:
// generate a key, self-sign a CSR, have `issue_certificate` check that
// self-signature, and produce a certificate an outside verifier accepts.
//
// The CSR check is the interesting link. It is the one place the runtime
// verifies a signature it did not produce, and the algorithm it verifies under
// comes from the CSR rather than from the key, so a new algorithm reaching
// `generate_csr` without reaching the verifier's allowlist would fail here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use openssl::x509::X509;
use rite_model::{ArtifactId, ArtifactRef, StepId, StepInputs};
use rite_openssl::OpenSslBackend;
use rite_runtime::{
    Action, ArtifactValue, ExecutionState, StepInfo, test_support::ReporterHarness,
};
use rite_stdlib::{GenerateCsrAction, GenerateKeypairAction, IssueCertificateAction};
use std::collections::HashMap;

fn named_inputs(pairs: &[(&str, ArtifactId)]) -> StepInputs {
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
    StepInputs::Named(map)
}

fn step(id: &str, produces: &str, inputs: Option<StepInputs>) -> StepInfo {
    StepInfo::new(
        StepId::new(id),
        None,
        Some("openssl".to_string()),
        Some(ArtifactId::new(produces)),
        inputs,
    )
}

/// Run keygen, CSR, and issuance for one algorithm; return the certificate DER.
fn issue_self_signed_root(algorithm: &str) -> Vec<u8> {
    let mut backend = OpenSslBackend::try_new("test").unwrap();
    let mut harness = ReporterHarness::new();
    let mut state = ExecutionState::new(HashMap::new(), HashMap::new(), HashMap::new(), false);

    let keypair_id = ArtifactId::new("root_key");
    let keygen_step = step("generate_root", "root_key", None);
    let keygen_result = {
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
    state = state.with_material(
        keypair_id.clone(),
        keygen_result
            .artifacts
            .into_iter()
            .find(|(id, _)| id == &keypair_id)
            .map(|(_, v)| v)
            .expect("keypair artifact"),
    );

    let csr_id = ArtifactId::new("root_csr");
    let csr_step = step(
        "generate_root_csr",
        "root_csr",
        Some(named_inputs(&[("signing_key", keypair_id.clone())])),
    );
    let csr_result = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(csr_step.id.clone());
        GenerateCsrAction
            .execute(
                &csr_step,
                &ctx,
                &serde_json::json!({ "subject": format!("CN=Test Root {algorithm}") }),
                &mut reporter,
                Some(&mut backend),
            )
            .unwrap_or_else(|e| panic!("generate_csr {algorithm}: {e}"))
    };
    state = state.with_material(
        csr_id.clone(),
        csr_result
            .artifacts
            .into_iter()
            .find(|(id, _)| id == &csr_id)
            .map(|(_, v)| v)
            .expect("CSR artifact"),
    );

    let cert_id = ArtifactId::new("root_cert");
    let cert_step = step(
        "issue_root_cert",
        "root_cert",
        Some(named_inputs(&[
            ("signing_key", keypair_id),
            ("csr", csr_id),
        ])),
    );
    let cert_result = {
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
            .unwrap_or_else(|e| panic!("issue_certificate {algorithm}: {e}"))
    };

    match cert_result
        .artifacts
        .into_iter()
        .find(|(id, _)| id == &cert_id)
        .map(|(_, v)| v)
        .expect("certificate artifact")
    {
        ArtifactValue::Certificate { der } => der,
        other => panic!("expected a certificate artifact, got {other:?}"),
    }
}

#[test]
fn every_signing_algorithm_completes_the_pki_chain() {
    let mut algorithms = vec!["RSA-2048", "ECDSA-P256", "ECDSA-P384", "Ed25519"];
    if rite_openssl::ML_DSA_AVAILABLE {
        algorithms.push("ML-DSA-65");
    }

    for algorithm in algorithms {
        let der = issue_self_signed_root(algorithm);
        let cert = X509::from_der(&der).unwrap_or_else(|e| panic!("{algorithm} cert DER: {e}"));
        let public_key = cert.public_key().expect("certificate exposes a public key");
        assert!(
            cert.verify(&public_key)
                .unwrap_or_else(|e| panic!("{algorithm} verification runs: {e}")),
            "{algorithm} root certificate must verify under its own public key"
        );
    }
}
