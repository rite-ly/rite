//! `unwrap_key` action, unwrap a transport-wrapped key into a backend keypair.

use rite_model::{ActionType, StepFact};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, ArtifactValue, HandlerContext, Icon,
    Reporter, StepInfo, StepResult, compute_fingerprint, parse_params, resolve_backend_key,
};
use rite_sdk::{Backend, WrapAlgorithm, WrappedKey};
use serde_json::json;

use crate::params::UnwrapKeyParams;

/// Unwrap a key inside the receiving backend.
pub struct UnwrapKeyAction;

impl Action for UnwrapKeyAction {
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
        reporter: &mut Reporter<'_>,
        backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        let typed: UnwrapKeyParams = parse_params(params)?;

        let algorithm_str = typed.algorithm.as_deref().unwrap_or("CMS-RSA-GCM");
        let wrap_alg: WrapAlgorithm = algorithm_str
            .parse::<WrapAlgorithm>()
            .map_err(|e| ActionError::Failed(e.to_string()))?;
        let label = typed
            .label
            .as_deref()
            .unwrap_or("unwrapped-key")
            .to_string();

        reporter.log(Icon::Spinner, format!("Unwrapping key using {wrap_alg}..."))?;

        let unwrapping_key_ref = step.required_named_input("unwrapping_key", "unwrap_key")?;
        let wrapped_data_ref = step.required_named_input("wrapped_data", "unwrap_key")?;

        reporter.log(
            Icon::Info,
            format!("Unwrapping key: {}", unwrapping_key_ref.display_name()),
        )?;
        reporter.log(
            Icon::Info,
            format!("Wrapped data: {}", wrapped_data_ref.display_name()),
        )?;

        let unwrapping_key_id = unwrapping_key_ref.artifact_id();
        let wrapped_data_id = wrapped_data_ref.artifact_id();

        let (key_backend, unwrapping_key_keyid, _, _) =
            resolve_backend_key(ctx.artifacts, &unwrapping_key_id).map_err(|e| {
                ActionError::Failed(format!(
                    "Unwrapping key '{}' must be a BackendKey: {e}",
                    unwrapping_key_ref.display_name()
                ))
            })?;

        let wrapped_key_artifact = ctx.artifacts.get(&wrapped_data_id).ok_or_else(|| {
            ActionError::Failed(format!(
                "Wrapped data artifact '{wrapped_data_id}' not found"
            ))
        })?;

        let (wrapped_data, wrapped_fingerprint) = match wrapped_key_artifact {
            ArtifactValue::WrappedKey { data, .. } => {
                let fp = compute_fingerprint(data);
                (data.clone(), fp)
            }
            _ => {
                return Err(ActionError::Failed(format!(
                    "Artifact '{wrapped_data_id}' must be a WrappedKey, found: {:?}",
                    std::mem::discriminant(wrapped_key_artifact)
                )));
            }
        };

        let backend_mut = backend.ok_or_else(|| {
            ActionError::Failed("Backend required for key unwrapping".to_string())
        })?;
        let backend_name = backend_mut.name().to_string();
        let backend_fingerprint = backend_mut.fingerprint();

        if backend_name != key_backend {
            return Err(ActionError::Failed(format!(
                "Unwrapping key owned by backend '{key_backend}', but current backend is '{backend_name}'"
            )));
        }

        let unwrap_backend = backend_mut.as_transport_mut().ok_or_else(|| {
            ActionError::Failed(format!(
                "Backend '{backend_name}' does not support key unwrapping"
            ))
        })?;

        reporter.log(Icon::Spinner, "Unwrapping key using backend...")?;
        let wrapped = WrappedKey {
            algorithm: wrap_alg,
            data: wrapped_data,
            recipient_hint: None,
        };
        let key_metadata = unwrap_backend.unwrap(&wrapped, unwrapping_key_keyid, &label)?;

        reporter.fact(StepFact::BackendOperation {
            step: step.id.clone(),
            kind: "unwrap_key".to_string(),
            inputs: json!({
                "algorithm": algorithm_str,
                "unwrapping_key": unwrapping_key_ref.display_name(),
                "wrapped_data": wrapped_data_ref.display_name(),
                "wrapped_data_fingerprint": wrapped_fingerprint,
                "label": label,
            }),
            outputs: json!({
                "backend": backend_name,
                "backend_fingerprint": backend_fingerprint,
                "unwrapped_key_id": key_metadata.key_id.as_str(),
                "unwrapped_key_algorithm": key_metadata.algorithm.to_string(),
            }),
            fingerprint: None,
        })?;

        let unwrapped = ArtifactValue::BackendKey {
            backend_name: backend_name.clone(),
            key_id: key_metadata.key_id,
            algorithm: key_metadata.algorithm,
            public_key: key_metadata.public_key,
        };

        let message = format!("Key unwrapped using {wrap_alg}");

        if let Some(produces) = &step.produces {
            reporter.log(
                Icon::Info,
                format!("Unwrapped key stored as artifact '{produces}'"),
            )?;
            Ok(StepResult::completed_with_artifact(
                message,
                produces.clone(),
                unwrapped,
            ))
        } else {
            Ok(StepResult::completed(message))
        }
    }
}
