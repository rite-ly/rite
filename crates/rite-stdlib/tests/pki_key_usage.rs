// What a certificate permits its key to do, read back by OpenSSL rather than by
// the `x509_cert` code that wrote it.
//
// The rule for `keyEncipherment` comes from the key type. None of these keys can
// perform RSA key transport, and the bit is outside what each allows: RFC 5480
// section 3 for an elliptic curve key and RFC 8410 section 9 for Ed25519 leave it
// off their lists, and RFC 9881 section 5 says MUST NOT for ML-DSA.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use openssl::x509::{X509, X509ExtendedKeyUsage, X509KeyUsage};
use rite_model::{ArtifactId, ArtifactRef, NamedInput, StepId, StepInputs};
use rite_openssl::OpenSslBackend;
use rite_runtime::{
    Action, ArtifactValue, ExecutionState, StepInfo, test_support::ReporterHarness,
};
use rite_stdlib::{GenerateCsrAction, GenerateKeyAction, IssueCertificateAction};
use std::collections::HashMap;

const RSA_TLS_SERVER: X509KeyUsage =
    X509KeyUsage::DIGITAL_SIGNATURE.union(X509KeyUsage::KEY_ENCIPHERMENT);

/// Each signing algorithm, with what a `tls_server` certificate for its key
/// must permit.
const SIGNING_ALGORITHMS: [(&str, X509KeyUsage); 5] = [
    ("RSA-2048", RSA_TLS_SERVER),
    ("ECDSA-P256", X509KeyUsage::DIGITAL_SIGNATURE),
    ("ECDSA-P384", X509KeyUsage::DIGITAL_SIGNATURE),
    ("Ed25519", X509KeyUsage::DIGITAL_SIGNATURE),
    ("ML-DSA-65", X509KeyUsage::DIGITAL_SIGNATURE),
];

/// Drives the three actions of a chain over one backend and artifact state.
struct Chain {
    backend: OpenSslBackend,
    harness: ReporterHarness,
    state: ExecutionState,
}

impl Chain {
    fn new() -> Self {
        Self {
            backend: OpenSslBackend::try_new("test").unwrap(),
            harness: ReporterHarness::new(),
            state: empty_state(),
        }
    }

    /// Run one action and keep the artifact it produces. Returns its DER if it
    /// is a certificate, the only artifact these tests need to look inside.
    fn run(
        &mut self,
        action: &dyn Action,
        produces: &str,
        inputs: Option<StepInputs>,
        params: &serde_json::Value,
    ) -> Option<Vec<u8>> {
        let id = ArtifactId::new(produces);
        let step = StepInfo::new(
            StepId::new(format!("make_{produces}")),
            None,
            Some("openssl".to_string()),
            Some(id.clone()),
            inputs,
        );
        let result = {
            let ctx = self.state.handler_context();
            let mut reporter = self.harness.reporter(step.id.clone());
            action
                .execute(&step, &ctx, params, &mut reporter, Some(&mut self.backend))
                .unwrap_or_else(|e| panic!("making {produces} with {params}: {e}"))
        };
        let value = result
            .artifacts
            .into_iter()
            .find_map(|(candidate, value)| (candidate == id).then_some(value))
            .unwrap_or_else(|| panic!("{produces} must be produced"));
        let certificate = match &value {
            ArtifactValue::Certificate(certificate) => Some(certificate.as_bytes().to_vec()),
            _ => None,
        };
        let state = std::mem::replace(&mut self.state, empty_state());
        self.state = state.with_material(id, value);
        certificate
    }

    /// Generate a key named `name` and a CSR for it, named `{name}_csr`.
    fn key_and_csr(&mut self, name: &str, algorithm: &str) {
        self.run(
            &GenerateKeyAction,
            name,
            None,
            &serde_json::json!({ "algorithm": algorithm }),
        );
        self.run(
            &GenerateCsrAction,
            &format!("{name}_csr"),
            Some(named_inputs(&[("signing_key", name)])),
            &serde_json::json!({ "subject": format!("CN={name}") }),
        );
    }

    fn issue(&mut self, produces: &str, inputs: &[(&str, &str)], profile: &str) -> X509 {
        let params = serde_json::json!({ "profile": profile, "validity_days": 365 });
        let der = self
            .run(
                &IssueCertificateAction,
                produces,
                Some(named_inputs(inputs)),
                &params,
            )
            .expect("issue_certificate must produce a certificate");
        X509::from_der(&der).expect("certificate must be valid DER")
    }
}

fn empty_state() -> ExecutionState {
    ExecutionState::new(HashMap::new(), HashMap::new(), HashMap::new(), false)
}

fn named_inputs(pairs: &[(&str, &str)]) -> StepInputs {
    StepInputs::Named(
        pairs
            .iter()
            .map(|(name, artifact)| {
                (
                    (*name).to_string(),
                    NamedInput::One(ArtifactRef::Produced {
                        id: ArtifactId::new(*artifact),
                        property: None,
                    }),
                )
            })
            .collect(),
    )
}

#[test]
fn every_profile_carries_the_usages_its_subject_key_allows() {
    let ca = X509KeyUsage::KEY_CERT_SIGN | X509KeyUsage::CRL_SIGN | X509KeyUsage::DIGITAL_SIGNATURE;

    for (algorithm, tls_server) in SIGNING_ALGORITHMS {
        let expected = [
            ("root_ca", Some(ca), None),
            ("sub_ca", Some(ca), None),
            (
                "tls_server",
                Some(tls_server),
                Some(X509ExtendedKeyUsage::SSL_SERVER),
            ),
            (
                "code_signing",
                Some(X509KeyUsage::DIGITAL_SIGNATURE),
                Some(X509ExtendedKeyUsage::CODE_SIGN),
            ),
            ("end_entity", None, None),
        ];

        let mut chain = Chain::new();
        chain.key_and_csr("subject", algorithm);
        for (profile, key_usage, extended_key_usage) in expected {
            let cert = chain.issue(
                &format!("{profile}_cert"),
                &[("signing_key", "subject"), ("csr", "subject_csr")],
                profile,
            );
            assert_eq!(cert.key_usage(), key_usage, "{profile} on {algorithm}");
            assert_eq!(
                cert.extended_key_usage(),
                extended_key_usage,
                "{profile} on {algorithm}"
            );
        }
    }
}

/// The issuing key signs the certificate but says nothing about what the
/// subject's key can do, so swapping the two must not change the usages.
#[test]
fn a_tls_server_certificate_takes_its_usages_from_the_subject_key_not_the_issuer() {
    // One key of each kind, each with its own root, so either can issue for
    // the other.
    let mut chain = Chain::new();
    for (name, algorithm) in [("rsa", "RSA-2048"), ("ecdsa", "ECDSA-P256")] {
        let csr = format!("{name}_csr");
        chain.key_and_csr(name, algorithm);
        chain.issue(
            &format!("{name}_root"),
            &[("signing_key", name), ("csr", csr.as_str())],
            "root_ca",
        );
    }

    for (issuer, subject, expected) in [
        ("rsa", "ecdsa", X509KeyUsage::DIGITAL_SIGNATURE),
        ("ecdsa", "rsa", RSA_TLS_SERVER),
    ] {
        let csr = format!("{subject}_csr");
        let root = format!("{issuer}_root");
        let cert = chain.issue(
            &format!("{subject}_by_{issuer}"),
            &[
                ("signing_key", issuer),
                ("csr", csr.as_str()),
                ("issuer_cert", root.as_str()),
            ],
            "tls_server",
        );

        assert_eq!(
            cert.key_usage(),
            Some(expected),
            "{subject} subject issued by {issuer}"
        );
    }
}
