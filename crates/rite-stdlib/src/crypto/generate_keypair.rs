//! `generate_keypair` action, produce an asymmetric keypair through a backend.

use rite_model::{ActionType, StepFact};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, ArtifactValue, HandlerContext, Icon,
    Reporter, StepInfo, StepResult, compute_fingerprint, parse_params,
};
use rite_sdk::{Backend, KeyAlgorithm, KeyPolicy, KeySpec};
use serde_json::json;

use crate::params::GenerateKeypairParams;

/// Generate an asymmetric cryptographic keypair via the configured backend.
pub struct GenerateKeypairAction;

impl Action for GenerateKeypairAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::GenerateKeypair,
            description: "Generate an asymmetric cryptographic keypair",
            category: ActionCategory::Crypto,
        }
    }

    fn unsupported_params(&self, params: &serde_json::Value, _step: &StepInfo) -> Vec<String> {
        // Whether the name is a key algorithm at all is settled during
        // resolution. What is left is whether this build can generate one.
        let Ok(typed) = parse_params::<GenerateKeypairParams>(params) else {
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
        let typed: GenerateKeypairParams = parse_params(params)?;

        let display_algo = match &typed.slot {
            Some(slot) => format!("{} keypair (slot {slot})...", typed.algorithm),
            None => format!("{} keypair...", typed.algorithm),
        };
        reporter.log(Icon::Spinner, format!("Generating {display_algo}"))?;

        let backend = backend.ok_or_else(|| {
            ActionError::Failed(
                "Backend required for cryptographic key generation (use MockBackend for dry-run)"
                    .to_string(),
            )
        })?;

        let backend_name = backend.name().to_string();
        let backend_fingerprint = backend.fingerprint();

        let keystore = backend.as_keystore_mut().ok_or_else(|| {
            ActionError::Failed(format!(
                "Backend '{backend_name}' does not support key generation"
            ))
        })?;

        let key_algorithm: KeyAlgorithm = typed.algorithm.parse().map_err(|_| {
            ActionError::Failed(format!("Unsupported algorithm: '{}'", typed.algorithm))
        })?;

        let policy = match &typed.policy {
            None => KeyPolicy::default(),
            Some(declared) => declared.resolve().map_err(ActionError::Failed)?,
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

        let keypair = ArtifactValue::BackendKey {
            backend_name: backend_name.clone(),
            key_id: metadata.key_id.clone(),
            algorithm: metadata.algorithm,
            public_key: metadata.public_key.clone(),
        };

        let mut inputs = serde_json::Map::new();
        inputs.insert("algorithm".to_string(), typed.algorithm.clone().into());
        if let Some(slot) = &typed.slot {
            inputs.insert("slot".to_string(), slot.clone().into());
        }
        // The policy is recorded whether or not the ceremony declared one: an
        // auditor reading the transcript should not have to know the defaults.
        inputs.insert(
            "policy".to_string(),
            json!({
                "persistent": policy.persistent,
                "sensitive": policy.sensitive,
                "extractable": policy.extractable,
                "wrap_with_trusted_only": policy.wrap_with_trusted_only,
                "usages": policy.usages.names(),
            }),
        );

        let mut outputs = serde_json::Map::new();
        outputs.insert("backend".to_string(), backend_name.clone().into());
        outputs.insert(
            "backend_fingerprint".to_string(),
            backend_fingerprint.into(),
        );
        outputs.insert(
            "key_id".to_string(),
            metadata.key_id.as_str().to_string().into(),
        );
        if let Some(fp) = &public_key_fingerprint {
            outputs.insert("public_key_fingerprint".to_string(), fp.clone().into());
        }

        reporter.fact(StepFact::BackendOperation {
            step: step.id.clone(),
            kind: "generate_keypair".to_string(),
            inputs: json!(inputs),
            outputs: json!(outputs),
            fingerprint: public_key_fingerprint,
        })?;

        let message = format!("{} keypair generated", typed.algorithm);
        if let Some(produces) = &step.produces {
            reporter.log(
                Icon::Checkmark,
                format!("Keypair stored as artifact '{produces}'"),
            )?;
            Ok(StepResult::completed_with_artifact(
                message,
                produces.clone(),
                keypair,
            ))
        } else {
            Ok(StepResult::completed(message))
        }
    }
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
