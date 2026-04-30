//! Generate keypair action.

use rite_model::ActionType;
use rite_runtime::{
    ActionCategory, ActionHandler, ActionMetadata, ArtifactValue, ExecutionError, HandlerContext,
    StepEvidence, StepInfo, StepResult, StepUI, compute_fingerprint, display,
};
use rite_sdk::{Backend, KeyAlgorithm, KeyPolicy, KeySpec};

use crate::params::GenerateKeypairParams;

/// Generate keypair action.
pub struct GenerateKeypairAction;

impl ActionHandler for GenerateKeypairAction {
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
        ctx: &HandlerContext,
        params: &serde_json::Value,
        ui: &mut dyn StepUI,
        backend: Option<&mut dyn Backend>,
    ) -> Result<(StepResult, StepEvidence), ExecutionError> {
        let typed: GenerateKeypairParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecutionError::InvalidParams(e.to_string()))?;

        let display_algo = match &typed.slot {
            Some(slot) => format!("{} keypair (slot {slot})...", typed.algorithm),
            None => format!("{} keypair...", typed.algorithm),
        };
        display::write_line(ui, &format!("Generating {display_algo}"))?;

        if ctx.dry_run {
            display::write_dry_run(ui, "key generation skipped")?;
            let mut evidence = StepEvidence::new();
            evidence.insert("algorithm", typed.algorithm);
            if let Some(slot) = typed.slot {
                evidence.insert("slot", slot);
            }
            return Ok((StepResult::completed("Key generated (dry run)"), evidence));
        }

        let backend = backend.ok_or_else(|| ExecutionError::StepFailed {
            step: step.id.clone(),
            reason:
                "Backend required for cryptographic key generation (use MockBackend for dry-run)"
                    .to_string(),
        })?;

        let backend_name = backend.name().to_string();
        let backend_fingerprint = backend.fingerprint();

        let keystore = backend
            .as_keystore_mut()
            .ok_or_else(|| ExecutionError::StepFailed {
                step: step.id.clone(),
                reason: format!("Backend '{backend_name}' does not support key generation"),
            })?;

        let key_algorithm: KeyAlgorithm = typed.algorithm.parse().map_err(|_| {
            ExecutionError::InvalidParams(format!("Unsupported algorithm: '{}'", typed.algorithm))
        })?;

        let spec = KeySpec {
            algorithm: key_algorithm,
            label: format!("key-{}", step.id_str()),
            policy: KeyPolicy::default(),
            location_hint: typed.slot.clone(),
        };
        let metadata = keystore
            .generate_key(spec)
            .map_err(|e| ExecutionError::StepFailed {
                step: step.id.clone(),
                reason: format!("Backend key generation failed: {e}"),
            })?;

        display::write_success(ui, &format!("{} keypair generated", typed.algorithm))?;

        let keypair = ArtifactValue::BackendKey {
            backend_name: backend_name.clone(),
            key_id: metadata.key_id,
            algorithm: metadata.algorithm,
            public_key: metadata.public_key,
        };

        let message = format!("{} keypair generated", typed.algorithm);

        let mut evidence = StepEvidence::new();
        evidence.insert("algorithm", typed.algorithm);
        if let Some(slot) = &typed.slot {
            evidence.insert("slot", slot.as_str());
        }

        if let ArtifactValue::BackendKey {
            key_id, public_key, ..
        } = &keypair
        {
            evidence.insert("backend", backend_name.as_str());
            evidence.insert("backend_fingerprint", backend_fingerprint);
            evidence.insert("key_id", key_id.as_str());
            if let Some(pub_key) = public_key {
                let fingerprint = compute_fingerprint(pub_key);
                evidence.insert("public_key_fingerprint", fingerprint);
            }
        }

        if let Some(produces) = &step.produces {
            display::write_line(ui, &format!("Keypair stored as artifact '{produces}'"))?;
            let result = StepResult::completed_with_artifact(message, produces.clone(), keypair);
            Ok((result, evidence))
        } else {
            let result = StepResult::completed(message);
            Ok((result, evidence))
        }
    }
}
