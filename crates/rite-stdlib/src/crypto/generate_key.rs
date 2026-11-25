//! `generate_key` action, produce a key through a backend.

use rite_model::ActionType;
use rite_runtime::{
    Action, ActionError, ArtifactValue, HandlerContext, Icon, Reporter, StepInfo, StepResult,
    parse_params,
};
use rite_sdk::{AccessAxis, AccessPolicy, Backend, KeyAlgorithm, KeyMetadata, KeyPolicy, KeySpec};
use serde_json::json;

use rite_model::params::GenerateKeyParams;

/// Generate a cryptographic key via the configured backend.
///
/// A keypair for an asymmetric algorithm, one secret for a symmetric one.
pub struct GenerateKeyAction;

impl Action for GenerateKeyAction {
    fn action_type(&self) -> ActionType {
        ActionType::GenerateKey
    }

    fn unsupported_params(&self, params: &serde_json::Value, _step: &StepInfo) -> Vec<String> {
        // Whether the name is a key algorithm at all is settled during
        // resolution. What is left is whether this build can generate one.
        let Ok(typed) = parse_params::<GenerateKeyParams>(params) else {
            return Vec::new();
        };
        unavailable_here(typed.algorithm).into_iter().collect()
    }

    fn execute(
        &self,
        step: &StepInfo,
        _ctx: &HandlerContext,
        params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        let typed: GenerateKeyParams = parse_params(params)?;

        let key_algorithm = typed.algorithm;

        // An AES key is not a keypair, and a step's own log line is read in
        // the room.
        let kind = if key_algorithm.is_symmetric() {
            "key"
        } else {
            "keypair"
        };
        let display_algo = match &typed.slot {
            Some(slot) => format!("{} {kind} (slot {slot})...", typed.algorithm),
            None => format!("{} {kind}...", typed.algorithm),
        };
        reporter.log(Icon::Spinner, format!("Generating {display_algo}"))?;

        let backend = backend.ok_or_else(|| {
            ActionError::Failed(
                "Backend required for cryptographic key generation (use MockBackend for dry-run)"
                    .to_string(),
            )
        })?;

        let backend_name = backend.name().to_string();

        let keystore = backend.as_keystore_mut().ok_or_else(|| {
            ActionError::Failed(format!(
                "Backend '{backend_name}' does not support key generation"
            ))
        })?;

        // Resolved against the algorithm's own default, so a policy declaring
        // only `extractable:` does not silently take a keypair's sign and
        // verify usages onto a symmetric key.
        let defaults = KeyPolicy::default_for(key_algorithm);
        let policy = match &typed.policy {
            None => defaults,
            Some(declared) => declared.resolve_from(&defaults),
        };
        let spec = KeySpec {
            algorithm: key_algorithm,
            label: format!("key-{}", step.id_str()),
            policy: policy.clone(),
            location_hint: typed.slot.clone(),
        };
        let metadata = keystore.generate_key(spec)?;
        // What the device says it set, which is evidence the declaration is
        // not: an axis left out shows here as the device's default. The key
        // exists by now, so a failed read still leaves its record.
        let access = match keystore.access_policy(&metadata.key_id) {
            Ok(access) => access,
            Err(error) => {
                reporter.log(
                    Icon::Warning,
                    format!("The device did not report the key's access policy: {error}"),
                )?;
                None
            }
        };

        let public_key_fingerprint = metadata
            .public_key
            .as_ref()
            .map(|key| key.fingerprint().to_string());

        let key = ArtifactValue::BackendKey {
            backend_name: backend_name.clone(),
            key_id: metadata.key_id.clone(),
            algorithm: metadata.algorithm,
            public_key: metadata.public_key.clone(),
            check_value: metadata.check_value.clone(),
        };

        reporter.backend_operation(
            "generate_key",
            requested(&typed, &policy),
            produced(&metadata, public_key_fingerprint.as_deref(), access),
            public_key_fingerprint,
        )?;
        if let Some(reported) = access {
            refuse_unkept_access(policy.access, reported)?;
        }

        let message = format!("{} {kind} generated", typed.algorithm);
        if let Some(produces) = &step.produces {
            reporter.log(
                Icon::Checkmark,
                format!("Key stored as artifact '{produces}'"),
            )?;
            Ok(StepResult::completed_with_artifact(
                message,
                produces.clone(),
                key,
            ))
        } else {
            Ok(StepResult::completed(message))
        }
    }
}

/// What the ceremony asked this step for.
///
/// The policy is recorded whether or not the ceremony declared one: an auditor
/// reading the transcript should not have to know the defaults.
fn requested(typed: &GenerateKeyParams, policy: &KeyPolicy) -> serde_json::Value {
    let mut inputs = serde_json::Map::new();
    inputs.insert("algorithm".to_string(), typed.algorithm.as_str().into());
    if let Some(slot) = &typed.slot {
        inputs.insert("slot".to_string(), slot.clone().into());
    }
    inputs.insert("policy".to_string(), crate::params::policy_json(policy));
    json!(inputs)
}

/// What came back, and what names it.
///
/// A keypair is named by the fingerprint of its public half and a symmetric
/// key by its check value. Without one or the other the record says a key was
/// made and nothing that identifies which.
fn produced(
    metadata: &KeyMetadata,
    public_key_fingerprint: Option<&str>,
    access: Option<AccessPolicy>,
) -> serde_json::Value {
    let mut outputs = serde_json::Map::new();
    outputs.insert("key_id".to_string(), metadata.key_id.as_str().into());
    if let Some(fingerprint) = public_key_fingerprint {
        outputs.insert("public_key_fingerprint".to_string(), fingerprint.into());
    }
    if let Some(kcv) = &metadata.check_value {
        outputs.insert("key_check_value".to_string(), kcv.to_string().into());
    }
    if let Some(access) = access {
        outputs.insert("access".to_string(), json!(access));
    }
    json!(outputs)
}

/// Fail the step when the device reports a value other than the one it was
/// asked for: an explicit value is a promise. The record is written first,
/// so the transcript shows both.
fn refuse_unkept_access(declared: AccessPolicy, reported: AccessPolicy) -> Result<(), ActionError> {
    for axis in AccessAxis::ALL {
        if let (Some(asked), Some(set)) = (declared.get(axis), reported.get(axis))
            && asked != set
        {
            return Err(ActionError::Failed(format!(
                "The step asked for '{axis}: {asked}', and the device reports '{axis}: {set}'"
            )));
        }
    }
    Ok(())
}

/// Whether this build can generate keys of this algorithm at all.
///
/// Saying so at check time is worth more than the mid-run failure it replaces,
/// and it is build-relative rather than a defect in the ceremony: another
/// machine's build may run the same document.
#[cfg(feature = "openssl")]
fn unavailable_here(algorithm: KeyAlgorithm) -> Option<String> {
    rite_openssl::build_limitation(algorithm)
        .map(|reason| format!("key algorithm '{algorithm}' {reason}"))
}

/// With no software backend compiled in, there is no library to ask.
#[cfg(not(feature = "openssl"))]
fn unavailable_here(_algorithm: KeyAlgorithm) -> Option<String> {
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::backend::MockBackend;
    use rite_model::{StepFact, StepId, StepInputs};
    use rite_runtime::ExecutionState;
    use rite_runtime::test_support::ReporterHarness;
    use rite_sdk::AccessWhen;
    use std::collections::HashMap;

    /// Generate a P-256 key in slot 9C on `backend` with `policy`, and
    /// return the run's error or its `generate_key` record.
    fn generate(
        backend: &mut dyn Backend,
        policy: &serde_json::Value,
    ) -> Result<(serde_json::Value, serde_json::Value), ActionError> {
        let mut harness = ReporterHarness::new();
        let state = ExecutionState::new(HashMap::new(), HashMap::new(), HashMap::new(), false);
        let step = StepInfo::new(
            StepId::new("make"),
            None,
            Some(backend.name().to_string()),
            None,
            Some(StepInputs::Named(HashMap::new())),
        );
        let ctx = state.handler_context();
        let mut reporter = harness.reporter(step.id.clone());
        GenerateKeyAction.execute(
            &step,
            &ctx,
            &json!({"algorithm": "ECDSA-P256", "slot": "9c", "policy": policy}),
            &mut reporter,
            Some(backend),
        )?;
        Ok(harness
            .facts()
            .iter()
            .find_map(|fact| match fact {
                StepFact::BackendOperation {
                    kind,
                    inputs,
                    outputs,
                    ..
                } if kind == "generate_key" => Some((inputs.clone(), outputs.clone())),
                _ => None,
            })
            .expect("a generate_key record"))
    }

    /// The record keeps what the step declared apart from what the device
    /// reported: an axis left out shows only in the report, as the device's
    /// default.
    #[test]
    fn the_record_holds_the_declared_access_and_what_the_device_reports() {
        let mut mock = MockBackend::new("token".to_string(), "seed".to_string());
        let (inputs, outputs) = generate(&mut mock, &json!({"authentication": "per_use"})).unwrap();
        assert_eq!(inputs["policy"]["authentication"], "per_use");
        assert!(inputs["policy"].get("presence").is_none(), "{inputs}");
        assert_eq!(
            outputs["access"],
            json!({"authentication": "per_use", "presence": "never"})
        );

        let (_, outputs) = generate(&mut mock, &json!({})).unwrap();
        // Slot 9C's default PIN policy is `always`.
        assert_eq!(outputs["access"]["authentication"], "per_use");
    }

    /// A device that reports another value than the one asked for fails
    /// the step; an axis left out, or one the device does not report, is
    /// no promise.
    #[test]
    fn an_access_value_the_device_did_not_keep_fails_the_step() {
        let asked = AccessPolicy {
            authentication: Some(AccessWhen::PerUse),
            presence: None,
        };
        let kept = AccessPolicy {
            authentication: Some(AccessWhen::PerUse),
            presence: Some(AccessWhen::Never),
        };
        assert!(refuse_unkept_access(asked, kept).is_ok());
        assert!(refuse_unkept_access(asked, AccessPolicy::default()).is_ok());
        let error = refuse_unkept_access(
            asked,
            AccessPolicy {
                authentication: Some(AccessWhen::PerSession),
                presence: None,
            },
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("'authentication: per_use'")
                && error.to_string().contains("'authentication: per_session'"),
            "{error}"
        );
    }

    /// The mock refuses an access policy on a key a PIV device cannot hold.
    #[test]
    fn the_mock_refuses_an_access_policy_on_a_symmetric_key() {
        let mut mock = MockBackend::new("token".to_string(), "seed".to_string());
        let spec = KeySpec {
            algorithm: KeyAlgorithm::Aes256,
            label: "aes".to_string(),
            policy: KeyPolicy {
                access: AccessPolicy {
                    authentication: Some(AccessWhen::PerUse),
                    presence: None,
                },
                ..KeyPolicy::default_for(KeyAlgorithm::Aes256)
            },
            location_hint: None,
        };
        let keystore = mock.as_keystore_mut().unwrap();
        let error = keystore.generate_key(spec).unwrap_err();
        assert!(error.to_string().contains("access policy"), "{error}");
    }

    /// A software key keeps no access value, so it refuses one rather than
    /// record a promise it cannot keep.
    #[test]
    fn a_software_key_refuses_an_access_policy() {
        let mut software = rite_openssl::OpenSslBackend::try_new("software").unwrap();
        let error = generate(&mut software, &json!({"authentication": "never"})).unwrap_err();
        assert!(error.to_string().contains("access policy"), "{error}");
        let (_, outputs) = generate(&mut software, &json!({})).unwrap();
        assert!(outputs.get("access").is_none(), "{outputs}");
    }
}
