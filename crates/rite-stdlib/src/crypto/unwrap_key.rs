//! Unwrap key action.

use rite_model::{ActionType, StepInputs};
use rite_runtime::{
    ActionCategory, ActionHandler, ActionMetadata, ArtifactValue, ExecutionError, HandlerContext,
    StepEvidence, StepInfo, StepResult, StepUI, compute_fingerprint, display, resolve_backend_key,
};
use rite_sdk::{Backend, WrapAlgorithm, WrappedKey};

use crate::params::UnwrapKeyParams;

/// Unwrap key action.
pub struct UnwrapKeyAction;

impl ActionHandler for UnwrapKeyAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::UnwrapKey,
            description: "Unwrap a key using another key",
            category: ActionCategory::Crypto,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn execute(
        &self,
        step: &StepInfo,
        ctx: &HandlerContext,
        params: &serde_json::Value,
        ui: &mut dyn StepUI,
        backend: Option<&mut dyn Backend>,
    ) -> Result<(StepResult, StepEvidence), ExecutionError> {
        let typed: UnwrapKeyParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecutionError::InvalidParams(e.to_string()))?;

        let algorithm_str = typed.algorithm.as_deref().unwrap_or("CMS-RSA-GCM");
        let wrap_alg: WrapAlgorithm = algorithm_str
            .parse::<WrapAlgorithm>()
            .map_err(|e| ExecutionError::InvalidParams(e.to_string()))?;
        let label = typed
            .label
            .as_deref()
            .unwrap_or("unwrapped-key")
            .to_string();

        display::write_line(ui, &format!("Unwrapping key using {wrap_alg}..."))?;

        let named = step.typed_inputs.as_ref().and_then(StepInputs::as_named);

        let unwrapping_key_ref = named.and_then(|m| m.get("unwrapping_key"));
        let wrapped_data_ref = named.and_then(|m| m.get("wrapped_data"));

        if let Some(r) = unwrapping_key_ref {
            display::write_line(ui, &format!("Unwrapping key: {}", r.display_name()))?;
        }
        if let Some(r) = wrapped_data_ref {
            display::write_line(ui, &format!("Wrapped data: {}", r.display_name()))?;
        }

        let unwrapping_key_ref = unwrapping_key_ref.ok_or_else(|| {
            ExecutionError::InvalidParams(
                "Missing 'unwrapping_key' input - must reference a BackendKey".to_string(),
            )
        })?;
        let wrapped_data_ref = wrapped_data_ref.ok_or_else(|| {
            ExecutionError::InvalidParams(
                "Missing 'wrapped_data' input - must reference a WrappedKey artifact".to_string(),
            )
        })?;

        let unwrapping_key_id = unwrapping_key_ref.artifact_id();
        let wrapped_data_id = wrapped_data_ref.artifact_id();

        let (key_backend, unwrapping_key_keyid, _, _) =
            resolve_backend_key(ctx.artifacts, &unwrapping_key_id).map_err(|e| {
                ExecutionError::InvalidParams(format!(
                    "Unwrapping key '{}' must be a BackendKey: {e}",
                    unwrapping_key_ref.display_name()
                ))
            })?;

        let wrapped_key_artifact = ctx.artifacts.get(&wrapped_data_id).ok_or_else(|| {
            ExecutionError::InvalidParams(format!(
                "Wrapped data artifact '{wrapped_data_id}' not found"
            ))
        })?;

        let (wrapped_data, wrapped_fingerprint) = match wrapped_key_artifact {
            ArtifactValue::WrappedKey { data, .. } => {
                let fp = compute_fingerprint(data);
                (data.clone(), fp)
            }
            _ => {
                return Err(ExecutionError::InvalidParams(format!(
                    "Artifact '{wrapped_data_id}' must be a WrappedKey, found: {:?}",
                    std::mem::discriminant(wrapped_key_artifact)
                )));
            }
        };

        let backend_mut = backend.ok_or_else(|| ExecutionError::StepFailed {
            step: step.id.clone(),
            reason: "Backend required for key unwrapping".to_string(),
        })?;

        let backend_name = backend_mut.name().to_string();
        let backend_fingerprint = backend_mut.fingerprint();

        if backend_name != key_backend {
            return Err(ExecutionError::StepFailed {
                step: step.id.clone(),
                reason: format!(
                    "Unwrapping key owned by backend '{key_backend}', but current backend is '{backend_name}'"
                ),
            });
        }

        let unwrap_backend =
            backend_mut
                .as_transport_mut()
                .ok_or_else(|| ExecutionError::StepFailed {
                    step: step.id.clone(),
                    reason: format!("Backend '{backend_name}' does not support key unwrapping"),
                })?;

        display::write_line(ui, "Unwrapping key using backend...")?;
        let wrapped = WrappedKey {
            algorithm: wrap_alg,
            data: wrapped_data,
            recipient_hint: None,
        };
        let key_metadata = unwrap_backend
            .unwrap(&wrapped, unwrapping_key_keyid, &label)
            .map_err(|e| ExecutionError::StepFailed {
                step: step.id.clone(),
                reason: format!("Backend key unwrapping failed: {e}"),
            })?;

        display::write_success(
            ui,
            &format!(
                "Key unwrapped using backend (algorithm: {})",
                key_metadata.algorithm
            ),
        )?;

        let mut evidence = StepEvidence::new();
        evidence.insert("algorithm", algorithm_str);
        evidence.insert("unwrapping_key", unwrapping_key_ref.display_name().as_str());
        evidence.insert("wrapped_data", wrapped_data_ref.display_name().as_str());
        evidence.insert("wrapped_data_fingerprint", wrapped_fingerprint.as_str());
        evidence.insert("backend", backend_name.as_str());
        evidence.insert("backend_fingerprint", backend_fingerprint.as_str());
        evidence.insert("unwrapped_key_id", key_metadata.key_id.as_str());
        evidence.insert(
            "unwrapped_key_algorithm",
            key_metadata.algorithm.to_string(),
        );
        evidence.insert("label", label.as_str());

        let unwrapped = ArtifactValue::BackendKey {
            backend_name: backend_name.clone(),
            key_id: key_metadata.key_id,
            algorithm: key_metadata.algorithm,
            public_key: key_metadata.public_key,
        };

        let message = format!("Key unwrapped using {wrap_alg}");

        if let Some(produces) = &step.produces {
            display::write_line(
                ui,
                &format!("Unwrapped key stored as artifact '{produces}'"),
            )?;
            let result = StepResult::completed_with_artifact(message, produces.clone(), unwrapped);
            Ok((result, evidence))
        } else {
            let result = StepResult::completed(message);
            Ok((result, evidence))
        }
    }
}
