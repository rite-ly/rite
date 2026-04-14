//! Export public key action.

use rite_model::{ActionType, StepInputs};
use rite_runtime::{
    ActionCategory, ActionHandler, ActionMetadata, ArtifactValue, ExecutionError, HandlerContext,
    KeyFormat, StepEvidence, StepInfo, StepResult, StepUI, compute_fingerprint,
    display, resolve_backend_key,
};
use rite_sdk::Backend;

/// Export public key action.
pub struct ExportPublicAction;

impl ActionHandler for ExportPublicAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::ExportPublic,
            description: "Export the public key from a keypair",
            category: ActionCategory::Crypto,
        }
    }

    fn execute(
        &self,
        step: &StepInfo,
        ctx: &HandlerContext,
        _params: &serde_json::Value,
        ui: &mut dyn StepUI,
        backend: Option<&mut dyn Backend>,
    ) -> Result<(StepResult, StepEvidence), ExecutionError> {
        display::write_line(ui, "Exporting public key...")?;

        let source_ref = step
            .typed_inputs
            .as_ref()
            .and_then(StepInputs::as_single);

        if let Some(r) = source_ref {
            display::write_line(ui, &format!("Source keypair: {}", r.display_name()))?;
        }

        let source_ref = source_ref.ok_or_else(|| {
            ExecutionError::InvalidParams("export_public requires input reference".to_string())
        })?;

        let artifact_id = source_ref.artifact_id();

        let (backend_name, key_id, _algorithm, cached_pub_key) =
            resolve_backend_key(ctx.artifacts, &artifact_id).map_err(|_| {
                ExecutionError::InvalidParams(
                    "export_public requires BackendKey artifact".to_string(),
                )
            })?;

        let public_key_bytes = if let Some(pub_key) = cached_pub_key {
            pub_key.clone()
        } else {
            let backend_mut = backend.ok_or_else(|| ExecutionError::StepFailed {
                step: step.id.clone(),
                reason: "Backend required to export public key".to_string(),
            })?;

            if backend_mut.name() != backend_name {
                return Err(ExecutionError::StepFailed {
                    step: step.id.clone(),
                    reason: format!(
                        "Key owned by backend '{backend_name}', but current backend is '{}'",
                        backend_mut.name()
                    ),
                });
            }

            let keystore =
                backend_mut
                    .as_keystore_mut()
                    .ok_or_else(|| ExecutionError::StepFailed {
                        step: step.id.clone(),
                        reason: format!(
                            "Backend '{backend_name}' does not support key export"
                        ),
                    })?;

            keystore
                .export_public_key(key_id)
                .map_err(|e| ExecutionError::StepFailed {
                    step: step.id.clone(),
                    reason: format!("Failed to export public key from backend: {e}"),
                })?
        };

        display::write_success(ui, "Public key extracted successfully")?;

        let public_key = ArtifactValue::PublicKey {
            key_data: public_key_bytes,
            format: KeyFormat::Pem,
        };

        let mut evidence = StepEvidence::new();
        evidence.insert("source_artifact", source_ref.display_name());

        if let Some(produces) = &step.produces {
            display::write_line(ui, &format!("Public key stored as artifact '{produces}'"))?;
            let fingerprint = match &public_key {
                ArtifactValue::PublicKey { key_data, .. } => compute_fingerprint(key_data),
                _ => String::new(),
            };
            if !fingerprint.is_empty() {
                evidence.insert("exported_key_fingerprint", fingerprint);
            }

            let result = StepResult::completed_with_artifact(
                "Public key exported",
                produces.clone(),
                public_key,
            );

            Ok((result, evidence))
        } else {
            let result = StepResult::completed("Public key exported");
            Ok((result, evidence))
        }
    }
}
