// Integration tests for ECDSA-P256 PKI flow through the stdlib actions.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use openssl::x509::X509;
use rite_model::{ArtifactId, ArtifactRef, StepId, StepInputs};
use rite_openssl::OpenSslBackend;
use rite_runtime::{
    Action, ArtifactValue, ExecutionState, StepInfo, test_support::ReporterHarness,
};
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
#[allow(clippy::too_many_lines)]
fn test_ecdsa_p256_pki_flow() {
    let mut backend = OpenSslBackend::try_new("test").unwrap();
    let mut harness = ReporterHarness::new();

    // ── generate_keypair ────────────────────────────────────────────────────
    let keypair_id = ArtifactId::new("root_ca_keypair");
    let keygen_step = step("generate_root_ca", "root_ca_keypair");
    let keygen_params = serde_json::json!({ "algorithm": "ECDSA-P256" });

    let mut state = make_state();
    let keygen_result = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(keygen_step.id.clone());
        GenerateKeypairAction
            .execute(
                &keygen_step,
                &ctx,
                &keygen_params,
                &mut reporter,
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

    let csr_result = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(csr_step.id.clone());
        GenerateCsrAction
            .execute(
                &csr_step,
                &ctx,
                &csr_params,
                &mut reporter,
                Some(&mut backend),
            )
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

    let cert_result = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(cert_step.id.clone());
        IssueCertificateAction
            .execute(
                &cert_step,
                &ctx,
                &cert_params,
                &mut reporter,
                Some(&mut backend),
            )
            .expect("issue_certificate with ECDSA-P256 must succeed")
    };

    let cert_artifact = cert_result
        .artifacts
        .into_iter()
        .find(|(id, _)| id == &cert_id)
        .map(|(_, v)| v)
        .expect("certificate artifact must be produced");

    let cert_der = match cert_artifact {
        ArtifactValue::Certificate(certificate) => certificate.as_bytes().to_vec(),
        other => panic!("expected Certificate for certificate artifact, got {other:?}"),
    };

    let cert = X509::from_der(&cert_der).expect("certificate must be valid DER");
    let subject = cert.subject_name();
    let cn = subject
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .expect("certificate must have CN");
    assert_eq!(
        cn.data().to_string().unwrap(),
        "Test Root CA ECDSA",
        "certificate CN must match CSR subject"
    );

    // Root profile without an issuer_cert must be self-issued: issuer equals
    // subject and the certificate verifies under its own public key.
    let issuer_cn = cert
        .issuer_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .expect("certificate must have issuer CN");
    assert_eq!(
        issuer_cn.data().to_string().unwrap(),
        "Test Root CA ECDSA",
        "root certificate must be self-issued"
    );
    let pubkey = cert
        .public_key()
        .expect("certificate must expose public key");
    assert!(
        cert.verify(&pubkey)
            .expect("signature verification must run"),
        "root certificate must verify under its own public key"
    );

    drop(harness);
}

/// A `SubjectAltName` requested in the CSR must survive the round trip into a
/// `tls_server` certificate: `generate_csr` encodes it as a PKCS#9
/// extensionRequest attribute, `issue_certificate` extracts and copies it.
#[test]
fn test_csr_san_roundtrip() {
    let mut backend = OpenSslBackend::try_new("test").unwrap();
    let mut harness = ReporterHarness::new();

    let keypair_id = ArtifactId::new("tls_keypair");
    let keygen_step = step("generate_tls_key", "tls_keypair");
    let keygen_params = serde_json::json!({ "algorithm": "ECDSA-P256" });

    let mut state = make_state();
    let keygen_result = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(keygen_step.id.clone());
        GenerateKeypairAction
            .execute(
                &keygen_step,
                &ctx,
                &keygen_params,
                &mut reporter,
                Some(&mut backend),
            )
            .expect("generate_keypair must succeed")
    };
    let keypair_artifact = keygen_result
        .artifacts
        .into_iter()
        .find(|(id, _)| id == &keypair_id)
        .map(|(_, v)| v)
        .expect("keypair artifact must be produced");
    state = state.with_material(keypair_id.clone(), keypair_artifact);

    let csr_id = ArtifactId::new("tls_csr");
    let csr_step = step_with_inputs(
        "generate_tls_csr",
        "tls_csr",
        named_inputs(&[("signing_key", keypair_id.clone())]),
    );
    let csr_params = serde_json::json!({
        "subject": "CN=tls.example.test",
        "san": ["DNS:tls.example.test", "IP:192.0.2.1", "email:ops@example.test"],
    });

    let csr_result = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(csr_step.id.clone());
        GenerateCsrAction
            .execute(
                &csr_step,
                &ctx,
                &csr_params,
                &mut reporter,
                Some(&mut backend),
            )
            .expect("generate_csr with SAN must succeed")
    };
    let csr_artifact = csr_result
        .artifacts
        .into_iter()
        .find(|(id, _)| id == &csr_id)
        .map(|(_, v)| v)
        .expect("CSR artifact must be produced");
    state = state.with_material(csr_id.clone(), csr_artifact);

    let cert_id = ArtifactId::new("tls_cert");
    let cert_step = step_with_inputs(
        "issue_tls_cert",
        "tls_cert",
        named_inputs(&[("signing_key", keypair_id), ("csr", csr_id)]),
    );
    let cert_params = serde_json::json!({ "profile": "tls_server", "validity_days": 90 });

    let cert_result = {
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(cert_step.id.clone());
        IssueCertificateAction
            .execute(
                &cert_step,
                &ctx,
                &cert_params,
                &mut reporter,
                Some(&mut backend),
            )
            .expect("issue_certificate tls_server must succeed")
    };
    let cert_der = cert_result
        .artifacts
        .into_iter()
        .find_map(|(id, v)| (id == cert_id).then_some(v))
        .and_then(|v| match v {
            ArtifactValue::Certificate(certificate) => Some(certificate.as_bytes().to_vec()),
            _ => None,
        })
        .expect("certificate artifact must be produced");

    let cert = X509::from_der(&cert_der).expect("certificate must be valid DER");
    let sans = cert
        .subject_alt_names()
        .expect("tls_server certificate must carry the CSR's SubjectAltName");
    let dns: Vec<_> = sans.iter().filter_map(|n| n.dnsname()).collect();
    let ips: Vec<_> = sans.iter().filter_map(|n| n.ipaddress()).collect();
    let emails: Vec<_> = sans.iter().filter_map(|n| n.email()).collect();
    assert_eq!(dns, ["tls.example.test"], "DNS SAN must round-trip");
    assert_eq!(ips, [&[192u8, 0, 2, 1][..]], "IP SAN must round-trip");
    assert_eq!(emails, ["ops@example.test"], "email SAN must round-trip");

    drop(harness);
}
