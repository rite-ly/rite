//! `piv_sign` action: sign data with a PIV smart card on-device key.

use rite_model::{ActionType, Prompt, StepFact, StepInputs};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, ArtifactValue, HandlerContext, Icon,
    Reporter, Response, StepInfo, StepResult, compute_fingerprint, parse_params,
    resolve_artifact_bytes,
};
use rite_sdk::{Backend, SignAlgorithm};
use secrecy::ExposeSecret;
use serde_json::json;

use super::params::PivSignParams;

/// Sign data using a PIV smart card on-device key.
pub struct PivSignAction;

impl Action for PivSignAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::PivSign,
            description: "Sign data using PIV smart card on-device key",
            category: ActionCategory::Crypto,
        }
    }

    fn execute(
        &self,
        step: &StepInfo,
        ctx: &HandlerContext,
        params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        let typed: PivSignParams = parse_params(params)?;

        if let Some(msg) = &typed.message {
            reporter.log(Icon::Info, msg.clone())?;
        }
        reporter.log(
            Icon::Spinner,
            format!(
                "Signing with PIV slot {} using {}...",
                typed.slot, typed.algorithm
            ),
        )?;

        // Validate slot and algorithm early.
        let piv_slot = rite_piv::ops::slot_from_hint(&typed.slot)
            .map_err(|e| ActionError::Failed(format!("Invalid PIV slot: {e}")))?;
        let sign_algorithm = parse_sign_algorithm(&typed.algorithm)?;

        // Resolve the single input artifact to sign.
        let input_ref = step
            .typed_inputs
            .as_ref()
            .and_then(StepInputs::as_single)
            .ok_or_else(|| {
                ActionError::Failed("piv_sign requires a single input artifact reference".into())
            })?;
        reporter.log(Icon::Info, format!("Input: {}", input_ref.display_name()))?;

        let artifact_id = input_ref.artifact_id();
        let data = resolve_artifact_bytes(ctx.artifacts, &artifact_id, input_ref.property())
            .map_err(|e| {
                ActionError::Failed(format!(
                    "input '{}' could not be resolved: {e}",
                    input_ref.display_name()
                ))
            })?;

        let backend = backend
            .ok_or_else(|| ActionError::Failed("Backend required for PIV signing".into()))?;
        let backend_name = backend.name().to_string();
        let backend_fingerprint = backend.fingerprint();

        // PIN verification through the PIV capability.
        {
            let piv = backend.as_piv_mut().ok_or_else(|| {
                ActionError::Failed(format!(
                    "Backend '{backend_name}' does not support PIV operations"
                ))
            })?;

            let retries = piv.pin_retries()?;
            if retries <= 1 {
                reporter.log(
                    Icon::Warning,
                    format!("Only {retries} PIN attempt(s) remaining. Card will lock on failure."),
                )?;
            }

            let response = reporter.prompt(&Prompt::Secret {
                label: "Enter PIV PIN".to_string(),
            })?;
            let Response::Secret(pin) = response else {
                return Err(ActionError::Failed(
                    "expected a secret response for the PIV PIN".to_string(),
                ));
            };

            piv.verify_pin(pin.expose_secret().as_bytes())?;
            reporter.log(Icon::Checkmark, "PIN verified")?;
        }

        // Signing through the Sign capability.
        let signature = {
            let sign_backend = backend.as_sign_mut().ok_or_else(|| {
                ActionError::Failed(format!("Backend '{backend_name}' does not support signing"))
            })?;
            // Canonical key id from the parsed slot; assembling the `piv:`
            // prefix from the raw hint would double it for prefixed hints.
            let key_id = rite_piv::ops::key_id_for_piv_slot(piv_slot)?;
            sign_backend.sign(&key_id, &data, sign_algorithm)?
        };

        let signature_fingerprint = compute_fingerprint(&signature);
        reporter.log(
            Icon::Checkmark,
            format!("Signature produced ({} bytes)", signature.len()),
        )?;

        reporter.fact(StepFact::BackendOperation {
            step: step.id.clone(),
            kind: "piv_sign".to_string(),
            inputs: json!({
                "slot": typed.slot,
                "algorithm": typed.algorithm,
                "input_artifact": input_ref.display_name(),
            }),
            outputs: json!({
                "backend": backend_name,
                "backend_fingerprint": backend_fingerprint,
                "signature_len": signature.len(),
            }),
            fingerprint: Some(signature_fingerprint),
        })?;

        if let Some(produces) = &step.produces {
            reporter.log(
                Icon::Info,
                format!("Signature stored as artifact '{produces}'"),
            )?;
            Ok(StepResult::completed_with_artifact(
                "PIV signature produced",
                produces.clone(),
                ArtifactValue::Bytes(signature),
            ))
        } else {
            Ok(StepResult::completed("PIV signature produced"))
        }
    }
}

/// Map a string algorithm name to a `SignAlgorithm` supported by PIV cards.
///
/// This is the action-level allowlist: it names what `piv_sign` offers to
/// ceremony authors. RSA-PSS is absent because PIV cards apply a raw RSA
/// operation and the client-side PSS encoding is not implemented.
fn parse_sign_algorithm(s: &str) -> Result<SignAlgorithm, ActionError> {
    match s {
        "ecdsa_sha256" => Ok(SignAlgorithm::EcdsaSha256),
        "ecdsa_sha384" => Ok(SignAlgorithm::EcdsaSha384),
        "rsa_pkcs1_sha256" => Ok(SignAlgorithm::RsaPkcs1Sha256),
        other => Err(ActionError::Failed(format!(
            "Unsupported signing algorithm: {other}. \
             Supported: ecdsa_sha256, ecdsa_sha384, rsa_pkcs1_sha256"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rite_sdk::{BackendError, KeyId, PivBackend, PivDeviceInfo, PivSlotInfo, SignBackend};

    #[test]
    fn parse_sign_algorithm_valid() {
        assert_eq!(
            parse_sign_algorithm("ecdsa_sha256").unwrap(),
            SignAlgorithm::EcdsaSha256
        );
        assert_eq!(
            parse_sign_algorithm("ecdsa_sha384").unwrap(),
            SignAlgorithm::EcdsaSha384
        );
        assert_eq!(
            parse_sign_algorithm("rsa_pkcs1_sha256").unwrap(),
            SignAlgorithm::RsaPkcs1Sha256
        );
    }

    #[test]
    fn parse_sign_algorithm_invalid() {
        let err = parse_sign_algorithm("ed25519").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ed25519"));
        assert!(msg.contains("Supported:"));
    }

    #[test]
    fn parse_sign_algorithm_rejects_pss() {
        // PIV cards do raw RSA; the client-side PSS encoding is not
        // implemented, so the action must refuse it up front.
        assert!(parse_sign_algorithm("rsa_pss_sha256").is_err());
    }

    // Signing needs the mock's embedded crypto (and its lazy stand-in key),
    // which is only present with the `openssl` feature.
    #[cfg(feature = "openssl")]
    #[test]
    fn signs_input_against_the_mock_and_records_pin_and_operation() {
        use crate::MockBackend;
        use rite_model::{ArtifactId, ArtifactRef, StepId};
        use rite_runtime::test_support::ReporterHarness;
        use secrecy::SecretString;
        use std::collections::HashMap;

        let mut harness = ReporterHarness::new();
        // Answer the single PIN prompt the action will issue (prompt id 0).
        harness.enqueue_response(Response::Secret(SecretString::from("123456")));

        let manifest = ArtifactId::new("manifest");
        let mut artifacts = HashMap::new();
        artifacts.insert(
            manifest.clone(),
            ArtifactValue::Bytes(b"release manifest".to_vec()),
        );
        let pmap = HashMap::new();
        let roles = HashMap::new();
        let materials = HashMap::new();
        let ctx = HandlerContext {
            params: &pmap,
            artifacts: &artifacts,
            roles: &roles,
            materials: &materials,
        };

        let input = StepInputs::Single(ArtifactRef::Produced {
            id: manifest,
            property: None,
        });
        let step = StepInfo::new(
            StepId::new("sign"),
            None,
            Some("mock".to_string()),
            Some(ArtifactId::new("signature")),
            Some(input),
        );
        let params = serde_json::json!({ "slot": "9c", "algorithm": "ecdsa_sha256" });
        let mut backend = MockBackend::new("token".to_string(), "seed".to_string());

        let result = {
            let mut reporter = harness.reporter(StepId::new("sign"));
            PivSignAction
                .execute(&step, &ctx, &params, &mut reporter, Some(&mut backend))
                .expect("sign succeeds against the mock stand-in key")
        };

        assert_eq!(result.artifacts.len(), 1);
        let (id, value) = result.artifacts.first().expect("one produced artifact");
        assert_eq!(id.as_str(), "signature");
        assert!(matches!(value, ArtifactValue::Bytes(b) if !b.is_empty()));

        // Both the PIN prompt and the signing operation are recorded.
        assert!(
            harness
                .facts()
                .iter()
                .any(|f| matches!(f, StepFact::PromptAnswered { .. }))
        );
        assert!(harness.facts().iter().any(|f| matches!(
            f,
            StepFact::BackendOperation { kind, .. } if kind == "piv_sign"
        )));
    }

    // A backend signing error (an empty slot on real hardware) must surface as a
    // failed step. Uses a minimal stub rather than the mock, whose lazy stand-in
    // would mask the missing key during a rehearsal.
    #[test]
    fn surfaces_a_backend_signing_error() {
        use rite_model::{ArtifactId, ArtifactRef, StepId};
        use rite_runtime::test_support::ReporterHarness;
        use rite_sdk::{
            Backend, BackendError, KeyId, PivBackend, PivDeviceInfo, PivSlotInfo, SignAlgorithm,
            SignBackend,
        };
        use secrecy::SecretString;
        use std::collections::HashMap;

        /// Authenticates fine, but the slot holds no key, so signing fails.
        struct EmptySlotBackend;

        impl Backend for EmptySlotBackend {
            fn name(&self) -> &'static str {
                "empty"
            }
            fn provider(&self) -> &'static str {
                "stub"
            }
            fn fingerprint(&self) -> String {
                "stub".to_string()
            }
            rite_sdk::backend_capabilities!(as_piv_mut: PivBackend, as_sign_mut: SignBackend);
        }

        impl PivBackend for EmptySlotBackend {
            fn list_slots(&self) -> Result<Vec<PivSlotInfo>, BackendError> {
                Ok(Vec::new())
            }
            fn verify_pin(&mut self, _pin: &[u8]) -> Result<(), BackendError> {
                Ok(())
            }
            fn change_pin(&mut self, _current: &[u8], _new: &[u8]) -> Result<(), BackendError> {
                Ok(())
            }
            fn pin_retries(&mut self) -> Result<u32, BackendError> {
                Ok(3)
            }
            fn unblock_pin(&mut self, _puk: &[u8], _new: &[u8]) -> Result<(), BackendError> {
                Ok(())
            }
            fn device_info(&self) -> Result<PivDeviceInfo, BackendError> {
                Ok(PivDeviceInfo {
                    serial: None,
                    firmware_version: None,
                    form_factor: None,
                })
            }
        }

        impl SignBackend for EmptySlotBackend {
            fn sign(
                &mut self,
                key_id: &KeyId,
                _message: &[u8],
                _algorithm: SignAlgorithm,
            ) -> Result<Vec<u8>, BackendError> {
                Err(BackendError::KeyNotFound(key_id.to_string()))
            }
            fn verify(
                &self,
                _key_id: &KeyId,
                _message: &[u8],
                _signature: &[u8],
                _algorithm: SignAlgorithm,
            ) -> Result<bool, BackendError> {
                Ok(false)
            }
        }

        let mut harness = ReporterHarness::new();
        harness.enqueue_response(Response::Secret(SecretString::from("123456")));

        let manifest = ArtifactId::new("manifest");
        let mut artifacts = HashMap::new();
        artifacts.insert(manifest.clone(), ArtifactValue::Bytes(b"data".to_vec()));
        let pmap = HashMap::new();
        let roles = HashMap::new();
        let materials = HashMap::new();
        let ctx = HandlerContext {
            params: &pmap,
            artifacts: &artifacts,
            roles: &roles,
            materials: &materials,
        };
        let input = StepInputs::Single(ArtifactRef::Produced {
            id: manifest,
            property: None,
        });
        let step = StepInfo::new(
            StepId::new("sign"),
            None,
            Some("stub".to_string()),
            Some(ArtifactId::new("signature")),
            Some(input),
        );
        let params = serde_json::json!({ "slot": "9c", "algorithm": "ecdsa_sha256" });
        let mut backend = EmptySlotBackend;

        let mut reporter = harness.reporter(StepId::new("sign"));
        let err = PivSignAction
            .execute(&step, &ctx, &params, &mut reporter, Some(&mut backend))
            .expect_err("an empty slot must fail signing");
        assert!(err.to_string().contains("Key not found"));
    }

    /// Records the key id the action passes to `sign`.
    ///
    /// Used by the double-prefix regression test below; the mock cannot catch
    /// that bug because its lazy stand-in minting accepts any key id string.
    #[derive(Default)]
    struct KeyIdCapture {
        seen: Vec<String>,
    }

    impl Backend for KeyIdCapture {
        fn name(&self) -> &'static str {
            "capture"
        }
        fn provider(&self) -> &'static str {
            "stub"
        }
        fn fingerprint(&self) -> String {
            "stub".to_string()
        }
        rite_sdk::backend_capabilities!(
            as_piv_mut: PivBackend, as_sign_mut: SignBackend);
    }

    impl PivBackend for KeyIdCapture {
        fn list_slots(&self) -> Result<Vec<PivSlotInfo>, BackendError> {
            Ok(Vec::new())
        }
        fn verify_pin(&mut self, _pin: &[u8]) -> Result<(), BackendError> {
            Ok(())
        }
        fn change_pin(&mut self, _current: &[u8], _new: &[u8]) -> Result<(), BackendError> {
            Ok(())
        }
        fn pin_retries(&mut self) -> Result<u32, BackendError> {
            Ok(3)
        }
        fn unblock_pin(&mut self, _puk: &[u8], _new: &[u8]) -> Result<(), BackendError> {
            Ok(())
        }
        fn device_info(&self) -> Result<PivDeviceInfo, BackendError> {
            Ok(PivDeviceInfo {
                serial: None,
                firmware_version: None,
                form_factor: None,
            })
        }
    }

    impl SignBackend for KeyIdCapture {
        fn sign(
            &mut self,
            key_id: &KeyId,
            _message: &[u8],
            _algorithm: SignAlgorithm,
        ) -> Result<Vec<u8>, BackendError> {
            self.seen.push(key_id.to_string());
            Ok(vec![0x01])
        }
        fn verify(
            &self,
            _key_id: &KeyId,
            _message: &[u8],
            _signature: &[u8],
            _algorithm: SignAlgorithm,
        ) -> Result<bool, BackendError> {
            Ok(true)
        }
    }

    // A `piv:`-prefixed slot hint is documented as valid, so it must reach the
    // backend as the canonical key id, not doubled to `piv:piv:9c`.
    #[test]
    fn prefixed_slot_hint_reaches_the_backend_as_canonical_key_id() {
        use rite_model::{ArtifactId, ArtifactRef, StepId};
        use rite_runtime::test_support::ReporterHarness;
        use secrecy::SecretString;
        use std::collections::HashMap;

        let manifest = ArtifactId::new("manifest");
        let mut artifacts = HashMap::new();
        artifacts.insert(manifest.clone(), ArtifactValue::Bytes(b"data".to_vec()));
        let pmap = HashMap::new();
        let roles = HashMap::new();
        let materials = HashMap::new();
        let ctx = HandlerContext {
            params: &pmap,
            artifacts: &artifacts,
            roles: &roles,
            materials: &materials,
        };

        let mut backend = KeyIdCapture::default();
        for slot in ["9c", "piv:9c"] {
            let mut harness = ReporterHarness::new();
            harness.enqueue_response(Response::Secret(SecretString::from("123456")));
            let input = StepInputs::Single(ArtifactRef::Produced {
                id: manifest.clone(),
                property: None,
            });
            let step = StepInfo::new(
                StepId::new("sign"),
                None,
                Some("stub".to_string()),
                None,
                Some(input),
            );
            let params = serde_json::json!({ "slot": slot, "algorithm": "ecdsa_sha256" });
            let mut reporter = harness.reporter(StepId::new("sign"));
            PivSignAction
                .execute(&step, &ctx, &params, &mut reporter, Some(&mut backend))
                .expect("signing against the capture stub succeeds");
        }
        assert_eq!(backend.seen, vec!["piv:9c", "piv:9c"]);
    }
}
