// What each certificate profile writes, read back by OpenSSL rather than by the
// `x509_cert` code that wrote it: what the certificate permits its key to do,
// and the key identifiers that link it to its issuer.
//
// The rule for `keyEncipherment` comes from the key type. None of these keys can
// perform RSA key transport, and the bit is outside what each allows: RFC 5480
// section 3 for an elliptic curve key and RFC 8410 section 9 for Ed25519 leave it
// off their lists, and RFC 9881 section 5 says MUST NOT for ML-DSA.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1OctetStringRef, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::stack::Stack;
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{
    X509, X509Builder, X509ExtendedKeyUsage, X509Extension, X509KeyUsage, X509StoreContext,
    X509StoreContextRef,
};
use rite_model::{ArtifactId, ArtifactRef, NamedInput, StepId, StepInputs};
use rite_openssl::OpenSslBackend;
use rite_runtime::{
    Action, ArtifactValue, ExecutionState, StepInfo, test_support::ReporterHarness,
};
use rite_sdk::CertificateDer;
use rite_stdlib::{GenerateCsrAction, GenerateKeyAction, IssueCertificateAction};
use std::collections::HashMap;
use x509_cert::der::Decode;
use x509_cert::spki::SubjectPublicKeyInfoRef;

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

    /// Put a certificate made outside the chain in place as `name`.
    fn bring(&mut self, name: &str, certificate: &X509) {
        let value =
            ArtifactValue::Certificate(CertificateDer::new(certificate.to_der().unwrap()).unwrap());
        let state = std::mem::replace(&mut self.state, empty_state());
        self.state = state.with_material(ArtifactId::new(name), value);
    }
}

/// A CA certificate for the key in `template`, as an issuer other than Rite
/// would write it: its `subjectKeyIdentifier` is `key_id`, or absent. Only
/// what `issue_certificate` reads from it matters here, so a throwaway key
/// signs it.
fn outside_ca(template: &X509, key_id: Option<&[u8]>) -> X509 {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let signer = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
    builder.set_serial_number(&serial).unwrap();
    builder.set_subject_name(template.subject_name()).unwrap();
    builder.set_issuer_name(template.subject_name()).unwrap();
    builder.set_pubkey(&template.public_key().unwrap()).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(30).unwrap())
        .unwrap();
    builder
        .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
    if let Some(key_id) = key_id {
        // The extension's value is the DER of an OCTET STRING holding the identifier.
        let mut value = vec![0x04, u8::try_from(key_id.len()).unwrap()];
        value.extend_from_slice(key_id);
        let extension = X509Extension::new_from_der(
            &Asn1Object::from_str("2.5.29.14").unwrap(),
            false,
            &Asn1OctetString::new_from_bytes(&value).unwrap(),
        )
        .unwrap();
        builder.append_extension(extension).unwrap();
    }
    builder.sign(&signer, MessageDigest::sha256()).unwrap();
    builder.build()
}

/// Whether OpenSSL builds a chain from `leaf` to `ca`, which finds the issuer
/// through the leaf's `authorityKeyIdentifier`.
fn chains_to(leaf: &X509, ca: &X509) -> bool {
    let mut store = X509StoreBuilder::new().unwrap();
    store.add_cert(ca.clone()).unwrap();
    let store = store.build();
    let untrusted = Stack::new().unwrap();
    let mut context = X509StoreContext::new().unwrap();
    context
        .init(&store, leaf, &untrusted, X509StoreContextRef::verify_cert)
        .unwrap()
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

/// Every profile carries the method-1 identifier of the subject's key, so a
/// tool that names a recipient or a signer by key identifier finds the
/// certificate.
#[test]
fn every_profile_carries_its_subject_key_identifier() {
    let mut chain = Chain::new();
    chain.key_and_csr("ca", "ECDSA-P256");
    let ca = chain.issue(
        "ca_cert",
        &[("signing_key", "ca"), ("csr", "ca_csr")],
        "root_ca",
    );
    assert_eq!(
        ca.subject_key_id().map(Asn1OctetStringRef::as_slice),
        Some(method_1(&ca).as_slice()),
        "root_ca"
    );

    chain.key_and_csr("subject", "RSA-2048");
    for profile in ["sub_ca", "tls_server", "code_signing", "end_entity"] {
        let cert = chain.issue(
            &format!("{profile}_cert"),
            &[
                ("signing_key", "ca"),
                ("csr", "subject_csr"),
                ("issuer_cert", "ca_cert"),
            ],
            profile,
        );
        assert_eq!(
            cert.subject_key_id().map(Asn1OctetStringRef::as_slice),
            Some(method_1(&cert).as_slice()),
            "{profile}"
        );
    }
}

/// RFC 5280 section 4.2.1.2 method 1: the SHA-1 of the subjectPublicKey bits,
/// computed here rather than by the `x509_cert` code under test.
fn method_1(certificate: &X509) -> Vec<u8> {
    let spki = certificate
        .public_key()
        .unwrap()
        .public_key_to_der()
        .unwrap();
    let spki = SubjectPublicKeyInfoRef::from_der(&spki).unwrap();
    openssl::sha::sha1(spki.subject_public_key.raw_bytes()).to_vec()
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

/// A certificate names its issuer by the identifier the issuer certificate
/// carries, whatever method made it (RFC 5280 section 4.2.1.2), and OpenSSL
/// finds the issuer through it.
#[test]
fn a_certificate_names_its_issuer_by_the_issuer_certificates_own_key_identifier() {
    let mut chain = Chain::new();
    chain.key_and_csr("ca", "ECDSA-P256");
    let rite_ca = chain.issue(
        "rite_ca",
        &[("signing_key", "ca"), ("csr", "ca_csr")],
        "root_ca",
    );
    let method_1 = method_1(&rite_ca);
    // Not derived from the key by any method, as an issuer drawing random
    // identifiers writes it.
    let foreign = [0x5a; 20];

    let issuers = [
        ("rite_ca", rite_ca.clone(), method_1.clone()),
        (
            "foreign_ski_ca",
            outside_ca(&rite_ca, Some(&foreign)),
            foreign.to_vec(),
        ),
        // Without an identifier to repeat, the method-1 one of its key.
        ("no_ski_ca", outside_ca(&rite_ca, None), method_1),
    ];

    chain.key_and_csr("leaf", "ECDSA-P256");
    for (issuer, ca, expected) in issuers {
        chain.bring(issuer, &ca);
        for profile in ["sub_ca", "tls_server", "code_signing", "end_entity"] {
            let cert = chain.issue(
                &format!("{profile}_by_{issuer}"),
                &[
                    ("signing_key", "ca"),
                    ("csr", "leaf_csr"),
                    ("issuer_cert", issuer),
                ],
                profile,
            );
            assert_eq!(
                cert.authority_key_id().map(Asn1OctetStringRef::as_slice),
                Some(expected.as_slice()),
                "{profile} by {issuer}"
            );
            assert!(chains_to(&cert, &ca), "{profile} by {issuer} chains");
        }
    }
}
