//! `generate_key` action, produce a key through a backend.

use rite_model::ActionType;
use rite_runtime::{
    Action, ActionError, ArtifactValue, HandlerContext, Icon, Reporter, StepInfo, StepResult,
    compute_fingerprint, parse_params,
};
use rite_sdk::{Backend, KeyAlgorithm, KeyMetadata, KeyPolicy, KeySpec};
use serde_json::json;

use crate::params::GenerateKeyParams;

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
        let Ok(algorithm) = typed.algorithm.parse::<KeyAlgorithm>() else {
            return Vec::new();
        };
        unavailable_here(algorithm).into_iter().collect()
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

        let key_algorithm: KeyAlgorithm = typed.algorithm.parse().map_err(|_| {
            ActionError::Failed(format!("Unsupported algorithm: '{}'", typed.algorithm))
        })?;

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
            Some(declared) => declared
                .resolve_from(&defaults)
                .map_err(ActionError::Failed)?,
        };
        let spec = KeySpec {
            algorithm: key_algorithm,
            label: format!("key-{}", step.id_str()),
            policy: policy.clone(),
            location_hint: typed.slot.clone(),
        };
        let metadata = keystore.generate_key(spec)?;

        let public_key_fingerprint = metadata
            .public_key
            .as_ref()
            .map(|key| compute_fingerprint(key.as_bytes()));

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
            produced(&metadata, public_key_fingerprint.as_deref()),
            public_key_fingerprint,
        )?;

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
    inputs.insert("algorithm".to_string(), typed.algorithm.clone().into());
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
fn produced(metadata: &KeyMetadata, public_key_fingerprint: Option<&str>) -> serde_json::Value {
    let mut outputs = serde_json::Map::new();
    outputs.insert("key_id".to_string(), metadata.key_id.as_str().into());
    if let Some(fingerprint) = public_key_fingerprint {
        outputs.insert("public_key_fingerprint".to_string(), fingerprint.into());
    }
    if let Some(kcv) = &metadata.check_value {
        outputs.insert("key_check_value".to_string(), kcv.to_string().into());
    }
    json!(outputs)
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
