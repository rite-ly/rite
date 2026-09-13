//! `wrap_key` action, wrap a backend-resident key for transport.

use rite_model::{ActionType, ArtifactRef, StepFact};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, ArtifactValue, HandlerContext, Icon,
    Reporter, StepInfo, StepResult, compute_fingerprint, parse_params, resolve_backend_key,
};
use rite_sdk::{Backend, KeyTransportBackend, WrapScheme};
use serde_json::json;

use crate::params::WrapKeyParams;

/// Wrap a key for transport, producing a wrapped-key artifact.
///
/// The input the step names selects who can undo it. `wrapping_key:` names a
/// key this backend holds, so the ceremony keeps the means to unwrap.
/// `recipient:` names a public key held elsewhere, so only its holder can open
/// the result and Rite has no evidence they can.
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
        let scheme = typed.scheme.unwrap_or(WrapScheme::CmsAes256Gcm);

        reporter.log(Icon::Spinner, format!("Wrapping key using {scheme}..."))?;

        let key_to_wrap_ref = step.required_named_input("key_to_wrap", "wrap_key")?;
        let (custody, wrapping_key_ref) = wrapping_input(step)?;

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

        let key_to_wrap = resolve_backend_key(ctx.artifacts, &key_to_wrap_id).map_err(|e| {
            ActionError::Failed(format!(
                "key_to_wrap '{}' must be a BackendKey: {e}",
                key_to_wrap_ref.display_name()
            ))
        })?;

        // The public half of what is being wrapped, so the record names the key
        // that went in rather than only the label the author chose for it.
        let target_fingerprint = key_to_wrap
            .public_key
            .map(|key| compute_fingerprint(key.as_bytes()));

        let key_backend = key_to_wrap.backend_name;
        let (wrapped_key, backend_fingerprint) = match custody {
            Custody::Backend => {
                let wrapping_key =
                    resolve_backend_key(ctx.artifacts, &wrapping_key_id).map_err(|e| {
                        ActionError::Failed(format!(
                            "wrapping_key '{}' must be a key held by this backend: {e}. \
                             Read it as 'recipient:' to wrap to a public key instead.",
                            wrapping_key_ref.display_name()
                        ))
                    })?;
                let wrap_key_backend = wrapping_key.backend_name;
                if key_backend != wrap_key_backend {
                    return Err(ActionError::Failed(format!(
                        "Key wrapping requires both keys on same backend (key: '{key_backend}', wrapper: '{wrap_key_backend}')"
                    )));
                }
                let (transport, backend_fp) = require_transport_backend(backend, key_backend)?;
                reporter.log(Icon::Spinner, "Wrapping key using backend...")?;
                let wk = transport.wrap(key_to_wrap.key_id, wrapping_key.key_id, scheme)?;
                (wk, backend_fp)
            }
            Custody::External => {
                let recipient = crate::signatures::resolve_public_key(
                    ctx.artifacts,
                    &wrapping_key_id,
                    wrapping_key_ref.property(),
                )
                .map_err(|e| {
                    ActionError::Failed(format!(
                        "Cannot resolve recipient '{}' as a public key: {e}",
                        wrapping_key_ref.display_name()
                    ))
                })?;

                // Who the ceremony is trusting, recorded before the wrap so an
                // aborted run still says which key was presented.
                let recipient_fingerprint = compute_fingerprint(recipient.as_bytes());
                if let Some(declared) = &typed.expect_recipient
                    && declared != &recipient_fingerprint
                {
                    return Err(ActionError::Failed(format!(
                        "Recipient '{}' is {recipient_fingerprint}, but the ceremony declares {declared}. \
                         Wrapping to an unintended recipient cannot be undone, so this step will not run.",
                        wrapping_key_ref.display_name()
                    )));
                }
                reporter.fact(StepFact::WrapRecipientRecorded {
                    step: step.id.clone(),
                    source: wrapping_key_ref.display_name(),
                    fingerprint: recipient_fingerprint,
                    declared: typed.expect_recipient.is_some(),
                })?;

                let (transport, backend_fp) = require_transport_backend(backend, key_backend)?;
                reporter.log(
                    Icon::Spinner,
                    "Wrapping key to external recipient public key...",
                )?;
                let wk = transport.wrap_to_public(key_to_wrap.key_id, &recipient, scheme)?;
                (wk, backend_fp)
            }
        };

        let fingerprint = compute_fingerprint(wrapped_key.data());
        reporter.log(Icon::Checkmark, "Key wrapped")?;

        let description = wrapped_key.description();
        reporter.fact(StepFact::BackendOperation {
            step: step.id.clone(),
            kind: "wrap_key".to_string(),
            inputs: json!({
                "scheme": wrapped_key.scheme().to_string(),
                "key_to_wrap": key_to_wrap_ref.display_name(),
                "wrapping_key": wrapping_key_ref.display_name(),
                "custody": match custody {
                    Custody::Backend => "backend",
                    Custody::External => "external_recipient",
                },
                "key_to_wrap_fingerprint": target_fingerprint,
            }),
            outputs: json!({
                "wrapped_key_fingerprint": fingerprint,
                "backend": key_backend,
                "backend_fingerprint": backend_fingerprint,
                // Read back out of the artifact, not predicted from the
                // request, and recorded whole. A verifier compares the
                // description it re-derives from the blob against this one, so
                // a field added to it is checked without touching either side.
                "wrap": description,
            }),
            fingerprint: Some(fingerprint),
        })?;

        let message = format!("Key wrapped using {}", wrapped_key.scheme());
        let wrapped = ArtifactValue::WrappedKey(wrapped_key);

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

/// Who holds the key that can undo the wrap.
///
/// The two paths differ by custody, not by exposure. A software backend exports
/// the target key either way. The input the author names selects the path, so
/// the choice is visible in the ceremony definition and in the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Custody {
    /// `wrapping_key:`, a key this backend already holds. The ceremony can
    /// unwrap what it wrapped.
    Backend,
    /// `recipient:`, a public key belonging to a party outside the room. Only
    /// that party can open the result, and Rite cannot check that they can.
    External,
}

/// Select the wrapping path from the input the step names.
///
/// The resolver rejects a step that names neither or both, so reaching the
/// error here means the step was built without going through resolution.
fn wrapping_input(step: &StepInfo) -> Result<(Custody, &ArtifactRef), ActionError> {
    if let Some(key) = step.named_input("wrapping_key") {
        if step.named_input("recipient").is_some() {
            return Err(ActionError::Failed(
                "wrap_key reads both 'wrapping_key' and 'recipient'; name one".to_string(),
            ));
        }
        return Ok((Custody::Backend, key));
    }
    match step.named_input("recipient") {
        Some(key) => Ok((Custody::External, key)),
        None => Err(ActionError::Failed(
            "wrap_key: missing required input 'wrapping_key' or 'recipient'".to_string(),
        )),
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
