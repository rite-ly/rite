//! `attest_key` action: ask the device holding a key for its signed statement
//! about the key.

use rite_model::ActionType;
use rite_model::params::AttestKeyParams;
use rite_runtime::{
    Action, ActionError, ArtifactValue, HandlerContext, Icon, Reporter, StepInfo, StepResult,
    compute_fingerprint, parse_params, resolve_backend_key,
};
use rite_sdk::Backend;
use serde_json::json;

/// Ask the device holding a key for its attestation of the key.
///
/// Takes the key by artifact reference, as `sign_data` does, so the step
/// names a key and not a slot. The evidence is stored as the device gave it;
/// checking it against the vendor's roots is a separate step, which needs no
/// device. Attesting needs no PIN.
pub struct AttestKeyAction;

impl Action for AttestKeyAction {
    fn action_type(&self) -> ActionType {
        ActionType::AttestKey
    }

    fn execute(
        &self,
        step: &StepInfo,
        ctx: &HandlerContext,
        params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        let typed: AttestKeyParams = parse_params(params)?;
        if let Some(message) = &typed.message {
            reporter.log(Icon::Info, message.clone())?;
        }

        let key_ref = step.required_named_input("key", "attest_key")?;
        let key_name = key_ref.display_name();
        let key = resolve_backend_key(ctx.artifacts, &key_ref.artifact_id()).map_err(|e| {
            ActionError::Failed(format!(
                "attest_key input 'key' ('{key_name}') must be a key a backend holds: {e}"
            ))
        })?;

        let backend =
            backend.ok_or_else(|| ActionError::Failed("Backend required for attest_key".into()))?;
        crate::backend::require_key_owner(backend, key.backend_name, &key_name)?;
        let backend_name = backend.name().to_string();
        let attester = backend.as_attest_mut().ok_or_else(|| {
            ActionError::Failed(format!("Backend '{backend_name}' cannot attest its keys"))
        })?;

        reporter.log(
            Icon::Spinner,
            format!("Asking '{backend_name}' to attest '{key_name}'..."),
        )?;
        let attestation = attester.attest_key(key.key_id)?;

        // Not a verification, which needs the vendor's roots: a statement
        // about another key is refused before it is stored as this one's.
        if let Some(expected) = key.public_key {
            let named = attestation.leaf().public_key()?;
            if named.fingerprint() != expected.fingerprint() {
                return Err(ActionError::Failed(format!(
                    "Backend '{backend_name}' returned an attestation for key {}, not for \
                     '{key_name}' ({})",
                    named.fingerprint(),
                    expected.fingerprint()
                )));
            }
        }

        let fingerprints: Vec<String> = attestation
            .certificates()
            .map(|certificate| compute_fingerprint(certificate.as_bytes()))
            .collect();
        let leaf = fingerprints.first().cloned();
        reporter.backend_operation(
            "attest_key",
            json!({
                "key_artifact": key_name,
                "key_id": key.key_id.as_str(),
            }),
            json!({
                "format": attestation.format().as_str(),
                "certificates": fingerprints,
            }),
            leaf,
        )?;

        let summary = format!(
            "Attestation received ({}, {} certificates)",
            attestation.format(),
            fingerprints.len()
        );
        match &step.produces {
            Some(produces) => {
                reporter.log(
                    Icon::Info,
                    format!("Attestation stored as artifact '{produces}'"),
                )?;
                Ok(StepResult::completed_with_artifact(
                    summary,
                    produces.clone(),
                    ArtifactValue::Attestation(attestation),
                ))
            }
            None => Ok(StepResult::completed(summary)),
        }
    }
}

#[cfg(all(test, feature = "pki"))]
mod tests {
    use super::*;
    use crate::MockBackend;
    use rite_model::{ArtifactId, ArtifactRef, NamedInput, StepFact, StepId, StepInputs};
    use rite_runtime::test_support::ReporterHarness;
    use rite_sdk::{AttestationFormat, KeyAlgorithm, KeyId, PublicKeyDer};
    use std::collections::HashMap;

    /// A mock holding a P-256 key in 9C, as a rehearsal of a provisioned
    /// card does.
    fn token() -> Result<MockBackend, rite_sdk::BackendError> {
        MockBackend::new("token".to_string(), "seed".to_string())
            .with_held_keys(&[(KeyId::new("piv:9c"), KeyAlgorithm::EcdsaP256)])
    }

    fn key_artifact(backend: &str, public_key: PublicKeyDer) -> ArtifactValue {
        ArtifactValue::BackendKey {
            backend_name: backend.to_string(),
            key_id: KeyId::new("piv:9c"),
            algorithm: KeyAlgorithm::EcdsaP256,
            public_key: Some(public_key),
            check_value: None,
        }
    }

    fn run(
        key: ArtifactValue,
        backend: &mut MockBackend,
    ) -> (Result<StepResult, ActionError>, ReporterHarness) {
        let mut harness = ReporterHarness::new();
        let mut step = StepInfo::new(
            StepId::new("attest"),
            None,
            Some("token".to_string()),
            Some(ArtifactId::new("attestation")),
            None,
        );
        step.typed_inputs = Some(StepInputs::Named(HashMap::from([(
            "key".to_string(),
            NamedInput::One(ArtifactRef::Material {
                id: rite_model::MaterialId::new("signing_key"),
                property: None,
            }),
        )])));
        let artifacts = HashMap::from([(ArtifactId::new("signing_key"), key)]);
        let (params, roles, materials) = (HashMap::new(), HashMap::new(), HashMap::new());
        let ctx = HandlerContext {
            params: &params,
            artifacts: &artifacts,
            roles: &roles,
            materials: &materials,
            credentials: &HashMap::new(),
            dry_run: false,
        };
        let result = {
            let mut reporter = harness.reporter(StepId::new("attest"));
            AttestKeyAction.execute(
                &step,
                &ctx,
                &serde_json::json!({}),
                &mut reporter,
                Some(backend),
            )
        };
        (result, harness)
    }

    #[test]
    fn stores_the_chain_for_the_key_and_records_it() {
        let mut backend = token().unwrap();
        let public_key =
            rite_sdk::KeyStoreBackend::export_public_key(&backend, &KeyId::new("piv:9c")).unwrap();
        let (result, harness) = run(key_artifact("token", public_key.clone()), &mut backend);

        let result = result.expect("the mock attests");
        let (id, value) = result.artifacts.first().expect("one artifact");
        assert_eq!(id.as_str(), "attestation");
        let ArtifactValue::Attestation(attestation) = value else {
            panic!("an attestation, got {value:?}");
        };
        assert_eq!(attestation.format(), AttestationFormat::YubicoPiv);
        assert_eq!(attestation.leaf().public_key().unwrap(), public_key);
        assert!(harness.facts().iter().any(|fact| matches!(
            fact,
            StepFact::BackendOperation { kind, .. } if kind == "attest_key"
        )));
    }

    #[test]
    fn refuses_a_key_held_by_another_backend() {
        let mut backend = token().unwrap();
        let public_key =
            rite_sdk::KeyStoreBackend::export_public_key(&backend, &KeyId::new("piv:9c")).unwrap();
        let (result, _) = run(key_artifact("other", public_key), &mut backend);
        let error = result.expect_err("the key is not on this backend");
        assert!(
            error.to_string().contains("owned by backend 'other'"),
            "{error}"
        );
    }
}
