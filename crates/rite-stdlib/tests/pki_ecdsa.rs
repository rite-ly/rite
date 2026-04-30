// Integration tests for ECDSA-P256 PKI flow through stdlib action handlers.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use openssl::x509::X509;
use rite_model::{ArtifactId, ArtifactRef, StepId, StepInputs};
use rite_openssl::OpenSslBackend;
use rite_runtime::ActionHandler;
use rite_runtime::{ArtifactValue, ExecutionState, MinimalStepUI, StepInfo};
use rite_stdlib::{GenerateCsrAction, GenerateKeypairAction, IssueCertificateAction};
use std::collections::HashMap;

fn make_state() -> ExecutionState {
    ExecutionState::new(HashMap::new(), HashMap::new(), HashMap::new(), false)
}

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

fn step(id: &str, produces: &str) -> StepInfo {
    StepInfo::new(
        StepId::new(id),
        None,
        Some("openssl".to_string()),
        Some(ArtifactId::new(produces)),
        None,
    )
}

fn step_with_inputs(id: &str, produces: &str, inputs: StepInputs) -> StepInfo {
    StepInfo::new(
        StepId::new(id),
        None,
        Some("openssl".to_string()),
        Some(ArtifactId::new(produces)),
        Some(inputs),
    )
}

#[test]
fn test_ecdsa_p256_pki_flow() {
    let mut backend = OpenSslBackend::try_new("test").unwrap();
    let mut ui = MinimalStepUI::silent();

    // ── generate_keypair ────────────────────────────────────────────────────
    let keypair_id = ArtifactId::new("root_ca_keypair");
    let keygen_step = step("generate_root_ca", "root_ca_keypair");
    let keygen_params = serde_json::json!({ "algorithm": "ECDSA-P256" });

    let mut state = make_state();
    let (keygen_result, _) = {
        let ctx = state.handler_context();
        GenerateKeypairAction
            .execute(
                &keygen_step,
                &ctx,
                &keygen_params,
                &mut ui,
                Some(&mut backend),
            )
            .expect("generate_keypair ECDSA-P256 must succeed")
    };

    let keypair_artifact = keygen_result
        .artifacts
        .into_iter()
        .find(|(id, _)| id == &keypair_id)
        .map(|(_, v)| v)
        .expect("keypair artifact must be produced");

    assert!(
        matches!(&keypair_artifact, ArtifactValue::BackendKey { algorithm, .. } if
            *algorithm == rite_sdk::KeyAlgorithm::EcdsaP256),
        "keypair must be BackendKey with EcdsaP256"
    );
    state = state.with_material(keypair_id.clone(), keypair_artifact);

    // ── generate_csr ────────────────────────────────────────────────────────
    let csr_id = ArtifactId::new("root_ca_csr");
    let csr_step = step_with_inputs(
        "generate_root_csr",
        "root_ca_csr",
        named_inputs(&[("signing_key", keypair_id.clone())]),
    );
    let csr_params = serde_json::json!({ "subject": "CN=Test Root CA ECDSA" });

    let (csr_result, _) = {
        let ctx = state.handler_context();
        GenerateCsrAction
            .execute(&csr_step, &ctx, &csr_params, &mut ui, Some(&mut backend))
            .expect("generate_csr with ECDSA-P256 must succeed")
    };

    let csr_artifact = csr_result
        .artifacts
        .into_iter()
        .find(|(id, _)| id == &csr_id)
        .map(|(_, v)| v)
        .expect("CSR artifact must be produced");

    let csr_der = match &csr_artifact {
        ArtifactValue::Bytes(b) => {
            assert!(!b.is_empty(), "CSR DER must not be empty");
            b.clone()
        }
        other => panic!("expected Bytes for CSR, got {other:?}"),
    };
    state = state.with_material(csr_id.clone(), csr_artifact);

    // Verify the CSR is a parseable PKCS#10 structure.
    openssl::x509::X509Req::from_der(&csr_der).expect("CSR must be valid DER");

    // ── issue_certificate ───────────────────────────────────────────────────
    let cert_id = ArtifactId::new("root_ca_cert");
    let cert_step = step_with_inputs(
        "issue_root_cert",
        "root_ca_cert",
        named_inputs(&[("signing_key", keypair_id), ("csr", csr_id)]),
    );
    let cert_params = serde_json::json!({ "profile": "root_ca", "validity_days": 3650 });

    let (cert_result, _) = {
        let ctx = state.handler_context();
        IssueCertificateAction
            .execute(&cert_step, &ctx, &cert_params, &mut ui, Some(&mut backend))
            .expect("issue_certificate with ECDSA-P256 must succeed")
    };

    let cert_artifact = cert_result
        .artifacts
        .into_iter()
        .find(|(id, _)| id == &cert_id)
        .map(|(_, v)| v)
        .expect("certificate artifact must be produced");

    let cert_der = match cert_artifact {
        ArtifactValue::Certificate { der } => der,
        other => panic!("expected Certificate for certificate artifact, got {other:?}"),
    };

    let cert = X509::from_der(&cert_der).expect("certificate must be valid DER");
    let subject = cert.subject_name();
    let cn = subject
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .expect("certificate must have CN");
    assert_eq!(
        cn.data().as_utf8().unwrap().to_string(),
        "Test Root CA ECDSA",
        "certificate CN must match CSR subject"
    );
}
