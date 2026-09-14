//! `unwrap_key` action, unwrap a transport-wrapped key into a backend keypair.

use rite_model::{ActionType, StepFact};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, ArtifactValue, HandlerContext, Icon,
    Reporter, StepInfo, StepResult, compute_fingerprint, parse_params, resolve_backend_key,
};
use rite_sdk::{Backend, KeyAlgorithm};
use serde_json::json;

use crate::params::{UnwrapKeyParams, unwrapped_key_default_policy};

/// Unwrap a key inside the receiving backend.
///
/// The scheme comes from the wrapped artifact, which carries what the wrap
/// did. The ceremony does not restate it: a restated value could disagree with
/// the bytes, and the bytes are what has to be decrypted.
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

        // What the ceremony says it is restoring. `rite check` has already
        // refused an unknown name, so a parse failure here is a run reaching
        // the backend with something that never passed the resolver.
        let expected = typed
            .algorithm
            .as_deref()
            .map(str::parse::<KeyAlgorithm>)
            .transpose()
            .map_err(|e| ActionError::Failed(format!("Unknown key algorithm: {e}")))?;

        let label = typed
            .label
            .as_deref()
            .unwrap_or("unwrapped-key")
            .to_string();

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

        let unwrapping_key =
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

        let ArtifactValue::WrappedKey(wrapped) = wrapped_key_artifact else {
            return Err(ActionError::Failed(format!(
                "Artifact '{wrapped_data_id}' must be a WrappedKey, found: {:?}",
                std::mem::discriminant(wrapped_key_artifact)
            )));
        };
        let wrapped_fingerprint = compute_fingerprint(wrapped.data());
        let scheme = wrapped.scheme();

        reporter.log(Icon::Spinner, format!("Unwrapping key using {scheme}..."))?;

        let backend_mut = backend.ok_or_else(|| {
            ActionError::Failed("Backend required for key unwrapping".to_string())
        })?;
        let backend_name = backend_mut.name().to_string();
        let backend_fingerprint = backend_mut.fingerprint();

        if backend_name != unwrapping_key.backend_name {
            return Err(ActionError::Failed(format!(
                "Unwrapping key owned by backend '{}', but current backend is '{backend_name}'",
                unwrapping_key.backend_name
            )));
        }

        let unwrap_backend = backend_mut.as_transport_mut().ok_or_else(|| {
            ActionError::Failed(format!(
                "Backend '{backend_name}' does not support key unwrapping"
            ))
        })?;

        let default_policy = unwrapped_key_default_policy(expected);
        let policy = match &typed.policy {
            None => default_policy,
            Some(declared) => declared
                .resolve_from(&default_policy)
                .map_err(ActionError::Failed)?,
        };

        reporter.log(Icon::Spinner, "Unwrapping key using backend...")?;
        let key_metadata = unwrap_backend.unwrap(
            wrapped,
            unwrapping_key.key_id,
            &label,
            policy.clone(),
            expected,
        )?;

        // The public half of what came out. With the wrap step's record from
        // the origin ceremony, this is what shows the key recovered here is the
        // key that went in there.
        let recovered_fingerprint = key_metadata
            .public_key
            .as_ref()
            .map(|key| compute_fingerprint(key.as_bytes()));

        // A symmetric key has no public half, so what names it is its check
        // value, which is also what a custodian reads off the token. One
        // `expect_key` serves both, discriminated by the prefix the value
        // carries rather than by a second field.
        let recovered_identity = recovered_fingerprint
            .clone()
            .or_else(|| key_metadata.check_value.as_ref().map(ToString::to_string));

        if let Some(declared) = &typed.expect_key {
            match &recovered_identity {
                Some(recovered) if recovered == declared => {}
                Some(recovered) => {
                    return Err(ActionError::Failed(format!(
                        "Unwrapped key is {recovered}, but the ceremony declares {declared}. \
                         The wrong key was recovered, so this step will not complete."
                    )));
                }
                None => {
                    return Err(ActionError::Failed(format!(
                        "Backend '{backend_name}' names the unwrapped key neither by a public \
                         key nor by a check value, so the declared {declared} cannot be checked."
                    )));
                }
            }
        }

        reporter.fact(StepFact::BackendOperation {
            step: step.id.clone(),
            kind: "unwrap_key".to_string(),
            inputs: json!({
                "scheme": scheme.to_string(),
                "unwrapping_key": unwrapping_key_ref.display_name(),
                "wrapped_data": wrapped_data_ref.display_name(),
                "wrapped_data_fingerprint": wrapped_fingerprint,
                "label": label,
                // What the ceremony committed to before the key came out,
                // null where it committed to nothing. Without them the record
                // says which key was recovered but not which was expected.
                "algorithm": typed.algorithm,
                "expect_key": typed.expect_key,
                // Recorded whether or not the ceremony declared one: what a
                // recovered key may do is the receiving ceremony's claim, and
                // an auditor should not have to know the defaults.
                "policy": json!({
                    "persistent": policy.persistent,
                    "sensitive": policy.sensitive,
                    "extractable": policy.extractable,
                    "wrap_with_trusted_only": policy.wrap_with_trusted_only,
                    "usages": policy.usages.names(),
                }),
            }),
            outputs: json!({
                "backend": backend_name,
                "backend_fingerprint": backend_fingerprint,
                "unwrapped_key_id": key_metadata.key_id.as_str(),
                "unwrapped_key_algorithm": key_metadata.algorithm.to_string(),
                "unwrapped_key_fingerprint": recovered_fingerprint,
                // The symmetric counterpart, and null for a keypair, so the
                // record names the recovered key in whichever form it has one.
                "unwrapped_key_check_value": key_metadata.check_value.as_ref().map(ToString::to_string),
            }),
            fingerprint: recovered_fingerprint,
        })?;

        let unwrapped = ArtifactValue::BackendKey {
            backend_name: backend_name.clone(),
            key_id: key_metadata.key_id,
            algorithm: key_metadata.algorithm,
            public_key: key_metadata.public_key,
            check_value: key_metadata.check_value,
        };

        let message = format!("Key unwrapped using {scheme}");

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
