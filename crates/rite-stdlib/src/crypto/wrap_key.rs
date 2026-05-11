//! Wrap key action.

use rite_model::{ActionType, StepInputs};
use rite_runtime::{
    ActionCategory, ActionHandler, ActionMetadata, ArtifactValue, ExecutionError, HandlerContext,
    StepEvidence, StepInfo, StepResult, StepUI, compute_fingerprint, display,
    resolve_artifact_bytes, resolve_backend_key,
};
use rite_sdk::{Backend, KeyTransportBackend, WrapAlgorithm};

use crate::params::WrapKeyParams;

/// Wrap key action.
pub struct WrapKeyAction;

impl ActionHandler for WrapKeyAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::WrapKey,
            description: "Wrap a key using another key",
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
        let typed: WrapKeyParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecutionError::InvalidParams(e.to_string()))?;

        let algorithm_str = typed.algorithm.as_deref().unwrap_or("CMS-RSA-GCM");
        let wrap_alg: WrapAlgorithm = algorithm_str
            .parse::<WrapAlgorithm>()
            .map_err(|e| ExecutionError::InvalidParams(e.to_string()))?;

        display::write_line(ui, &format!("Wrapping key using {wrap_alg}..."))?;

        let named = step.typed_inputs.as_ref().and_then(StepInputs::as_named);

        let key_to_wrap_ref = named.and_then(|m| m.get("key_to_wrap"));
        let wrapping_key_ref = named.and_then(|m| m.get("wrapping_key"));

        if let Some(r) = key_to_wrap_ref {
            display::write_line(ui, &format!("Key to wrap: {}", r.display_name()))?;
        }
        if let Some(r) = wrapping_key_ref {
            display::write_line(ui, &format!("Wrapping key: {}", r.display_name()))?;
        }

        let (Some(key_to_wrap_ref), Some(wrapping_key_ref)) = (key_to_wrap_ref, wrapping_key_ref)
        else {
            return Err(ExecutionError::InvalidParams(
                "wrap_key: key_to_wrap must be a BackendKey; wrapping_key must be a BackendKey or raw public key".to_string()
            ));
        };

        let key_to_wrap_id = key_to_wrap_ref.artifact_id();
        let wrapping_key_id = wrapping_key_ref.artifact_id();

        let (key_backend, key_id, _, _) = resolve_backend_key(ctx.artifacts, &key_to_wrap_id)
            .map_err(|e| {
                ExecutionError::InvalidParams(format!(
                    "key_to_wrap '{}' must be a BackendKey: {e}",
                    key_to_wrap_ref.display_name()
                ))
            })?;

        let wrapping_key_meta = resolve_backend_key(ctx.artifacts, &wrapping_key_id);

        let (wrapped_key, backend_fingerprint) = if let Ok((wrap_key_backend, wrap_key_id, _, _)) =
            wrapping_key_meta
        {
            if key_backend != wrap_key_backend {
                return Err(ExecutionError::InvalidParams(format!(
                    "Key wrapping requires both keys on same backend (key: '{key_backend}', wrapper: '{wrap_key_backend}')"
                )));
            }

            let (transport, backend_fp) = require_transport_backend(step, backend, key_backend)?;
            display::write_line(ui, "Wrapping key using backend...")?;
            let wk = transport.wrap(key_id, wrap_key_id, wrap_alg).map_err(|e| {
                ExecutionError::StepFailed {
                    step: step.id.clone(),
                    reason: format!("Backend key wrapping failed: {e}"),
                }
            })?;
            (wk, backend_fp)
        } else {
            let pub_key_bytes = resolve_artifact_bytes(
                ctx.artifacts,
                &wrapping_key_id,
                wrapping_key_ref.property(),
            )
            .map_err(|_| {
                ExecutionError::InvalidParams(format!(
                    "Cannot resolve wrapping key '{}' as a public key",
                    wrapping_key_ref.display_name()
                ))
            })?;

            let (transport, backend_fp) = require_transport_backend(step, backend, key_backend)?;
            display::write_line(ui, "Wrapping key to external recipient public key...")?;
            let wk = transport
                .wrap_to_public(key_id, &pub_key_bytes, wrap_alg)
                .map_err(|e| ExecutionError::StepFailed {
                    step: step.id.clone(),
                    reason: format!("Key wrapping failed: {e}"),
                })?;
            (wk, backend_fp)
        };

        let fingerprint = compute_fingerprint(&wrapped_key.data);
        display::write_success(ui, "Key wrapped")?;

        let mut evidence = StepEvidence::new();
        evidence.insert("algorithm", algorithm_str);
        evidence.insert("key_to_wrap", key_to_wrap_ref.display_name().as_str());
        evidence.insert("wrapping_key", wrapping_key_ref.display_name().as_str());
        evidence.insert("wrapped_key_fingerprint", fingerprint.as_str());
        evidence.insert("backend", key_backend);
        evidence.insert("backend_fingerprint", backend_fingerprint);

        let wrapped = ArtifactValue::WrappedKey {
            data: wrapped_key.data,
            algorithm: wrap_alg,
        };

        let message = format!("Key wrapped using {wrap_alg}");

        if let Some(produces) = &step.produces {
            display::write_line(ui, &format!("Wrapped key stored as artifact '{produces}'"))?;
            let result = StepResult::completed_with_artifact(message, produces.clone(), wrapped);
            Ok((result, evidence))
        } else {
            let result = StepResult::completed(message);
            Ok((result, evidence))
        }
    }
}

/// Validate and downcast the backend to `KeyTransportBackend`.
///
/// Returns the transport backend and the backend fingerprint (for evidence).
fn require_transport_backend<'a>(
    step: &StepInfo,
    backend: Option<&'a mut dyn Backend>,
    expected_name: &str,
) -> Result<(&'a mut dyn KeyTransportBackend, String), ExecutionError> {
    let backend_mut = backend.ok_or_else(|| ExecutionError::StepFailed {
        step: step.id.clone(),
        reason: "Backend required for key wrapping".to_string(),
    })?;

    let backend_name = backend_mut.name().to_string();
    let backend_fingerprint = backend_mut.fingerprint();

    if backend_name != expected_name {
        return Err(ExecutionError::StepFailed {
            step: step.id.clone(),
            reason: format!(
                "Key owned by backend '{expected_name}', but current backend is '{backend_name}'"
            ),
        });
    }

    let transport = backend_mut
        .as_transport_mut()
        .ok_or_else(|| ExecutionError::StepFailed {
            step: step.id.clone(),
            reason: format!("Backend '{backend_name}' does not support key wrapping"),
        })?;

    Ok((transport, backend_fingerprint))
}
