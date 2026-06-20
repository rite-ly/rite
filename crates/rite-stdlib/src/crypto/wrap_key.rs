//! `wrap_key` action, wrap a backend-resident key for transport.

use rite_model::{ActionType, StepFact};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, ArtifactValue, HandlerContext, Icon,
    Reporter, StepInfo, StepResult, compute_fingerprint, parse_params, resolve_artifact_bytes,
    resolve_backend_key,
};
use rite_sdk::{Backend, KeyTransportBackend, WrapAlgorithm};
use serde_json::json;

use crate::params::WrapKeyParams;

/// Wrap a key using either another backend key or an external recipient
/// public key, producing a transport-safe wrapped artifact.
pub struct WrapKeyAction;

impl Action for WrapKeyAction {
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
        reporter: &mut Reporter<'_>,
        backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        let typed: WrapKeyParams = parse_params(params)?;

        let algorithm_str = typed.algorithm.as_deref().unwrap_or("CMS-RSA-GCM");
        let wrap_alg: WrapAlgorithm = algorithm_str
            .parse::<WrapAlgorithm>()
            .map_err(|e| ActionError::Failed(e.to_string()))?;

        reporter.log(Icon::Spinner, format!("Wrapping key using {wrap_alg}..."))?;

        let key_to_wrap_ref = step.required_named_input("key_to_wrap", "wrap_key")?;
        let wrapping_key_ref = step.required_named_input("wrapping_key", "wrap_key")?;

        reporter.log(
            Icon::Info,
            format!("Key to wrap: {}", key_to_wrap_ref.display_name()),
        )?;
        reporter.log(
            Icon::Info,
            format!("Wrapping key: {}", wrapping_key_ref.display_name()),
        )?;

        let key_to_wrap_id = key_to_wrap_ref.artifact_id();
        let wrapping_key_id = wrapping_key_ref.artifact_id();

        let (key_backend, key_id, _, _) = resolve_backend_key(ctx.artifacts, &key_to_wrap_id)
            .map_err(|e| {
                ActionError::Failed(format!(
                    "key_to_wrap '{}' must be a BackendKey: {e}",
                    key_to_wrap_ref.display_name()
                ))
            })?;

        let wrapping_key_meta = resolve_backend_key(ctx.artifacts, &wrapping_key_id);

        let (wrapped_key, backend_fingerprint) = if let Ok((wrap_key_backend, wrap_key_id, _, _)) =
            wrapping_key_meta
        {
            if key_backend != wrap_key_backend {
                return Err(ActionError::Failed(format!(
                    "Key wrapping requires both keys on same backend (key: '{key_backend}', wrapper: '{wrap_key_backend}')"
                )));
            }
            let (transport, backend_fp) = require_transport_backend(backend, key_backend)?;
            reporter.log(Icon::Spinner, "Wrapping key using backend...")?;
            let wk = transport.wrap(key_id, wrap_key_id, wrap_alg)?;
            (wk, backend_fp)
        } else {
            let pub_key_bytes = resolve_artifact_bytes(
                ctx.artifacts,
                &wrapping_key_id,
                wrapping_key_ref.property(),
            )
            .map_err(|_| {
                ActionError::Failed(format!(
                    "Cannot resolve wrapping key '{}' as a public key",
                    wrapping_key_ref.display_name()
                ))
            })?;
            let (transport, backend_fp) = require_transport_backend(backend, key_backend)?;
            reporter.log(
                Icon::Spinner,
                "Wrapping key to external recipient public key...",
            )?;
            let wk = transport.wrap_to_public(key_id, &pub_key_bytes, wrap_alg)?;
            (wk, backend_fp)
        };

        let fingerprint = compute_fingerprint(&wrapped_key.data);
        reporter.log(Icon::Checkmark, "Key wrapped")?;

        reporter.fact(StepFact::BackendOperation {
            step: step.id.clone(),
            kind: "wrap_key".to_string(),
            inputs: json!({
                "algorithm": algorithm_str,
                "key_to_wrap": key_to_wrap_ref.display_name(),
                "wrapping_key": wrapping_key_ref.display_name(),
            }),
            outputs: json!({
                "wrapped_key_fingerprint": fingerprint,
                "backend": key_backend,
                "backend_fingerprint": backend_fingerprint,
            }),
            fingerprint: Some(fingerprint),
        })?;

        let wrapped = ArtifactValue::WrappedKey {
            data: wrapped_key.data,
            algorithm: wrap_alg,
        };
        let message = format!("Key wrapped using {wrap_alg}");

        if let Some(produces) = &step.produces {
            reporter.log(
                Icon::Info,
                format!("Wrapped key stored as artifact '{produces}'"),
            )?;
            Ok(StepResult::completed_with_artifact(
                message,
                produces.clone(),
                wrapped,
            ))
        } else {
            Ok(StepResult::completed(message))
        }
    }
}

/// Validate and downcast the backend to [`KeyTransportBackend`].
fn require_transport_backend<'a>(
    backend: Option<&'a mut dyn Backend>,
    expected_name: &str,
) -> Result<(&'a mut dyn KeyTransportBackend, String), ActionError> {
    let backend_mut = backend
        .ok_or_else(|| ActionError::Failed("Backend required for key wrapping".to_string()))?;
    let backend_name = backend_mut.name().to_string();
    let backend_fingerprint = backend_mut.fingerprint();
    if backend_name != expected_name {
        return Err(ActionError::Failed(format!(
            "Key owned by backend '{expected_name}', but current backend is '{backend_name}'"
        )));
    }
    let transport = backend_mut.as_transport_mut().ok_or_else(|| {
        ActionError::Failed(format!(
            "Backend '{backend_name}' does not support key wrapping"
        ))
    })?;
    Ok((transport, backend_fingerprint))
}
