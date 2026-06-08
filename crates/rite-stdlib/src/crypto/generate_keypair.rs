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

        let spec = KeySpec {
            algorithm: key_algorithm,
            label: format!("key-{}", step.id_str()),
            policy: KeyPolicy::default(),
            location_hint: typed.slot.clone(),
        };
        let metadata = keystore
            .generate_key(spec)
            .map_err(|e| ActionError::Failed(format!("Backend key generation failed: {e}")))?;

        let public_key_fingerprint = metadata.public_key.as_deref().map(compute_fingerprint);

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
