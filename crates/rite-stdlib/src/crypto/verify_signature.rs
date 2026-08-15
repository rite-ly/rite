//! `verify_signature` action: check a signature against a public key.

use rite_model::{ActionType, StepFact};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, ArtifactValue, BackendKeyMeta,
    HandlerContext, Icon, Reporter, StepInfo, StepResult, compute_fingerprint, parse_params,
    resolve_artifact_bytes, resolve_backend_key,
};
use rite_sdk::{Backend, KeyAlgorithm};
use serde_json::json;

use super::sign_data::{require_sign_backend, resolve_sign_algorithm};
use crate::params::VerifySignatureParams;

/// Verify a signature over data, given the signer's public key.
///
/// Unlike every other cryptographic action, this one needs no backend.
/// Verification takes only a public key, so a ceremony can check evidence it
/// did not produce: a signature made on a smart card, or one that arrived with
/// a document from outside. The `key` input may be a keypair, a bare public
/// key, or a certificate carrying one, since that is how a signer's key usually
/// arrives. Naming a `backend:` on the step delegates the check to that backend
/// instead, which is what a remote or hardware verifier needs.
pub struct VerifySignatureAction;

impl Action for VerifySignatureAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::VerifySignature,
            description: "Verify a signature against a public key",
            category: ActionCategory::Crypto,
        }
    }

    fn execute(
        &self,
        step: &StepInfo,
        ctx: &HandlerContext,
        params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        let typed: VerifySignatureParams = parse_params(params)?;

        if let Some(message) = &typed.message {
            reporter.log(Icon::Info, message.clone())?;
        }

        let key_ref = step.required_named_input("key", "verify_signature")?;
        let data_ref = step.required_named_input("data", "verify_signature")?;
        let signature_ref = step.required_named_input("signature", "verify_signature")?;

        let key_id = key_ref.artifact_id();
        let backend_key = resolve_backend_key(ctx.artifacts, &key_id).ok();
        let (public_der, key_algorithm) =
            resolve_public_key(ctx, key_ref, &key_id, backend_key.as_ref())?;

        let algorithm = resolve_sign_algorithm(typed.algorithm.as_deref(), key_algorithm)?;

        let data_id = data_ref.artifact_id();
        let data =
            resolve_artifact_bytes(ctx.artifacts, &data_id, data_ref.property()).map_err(|e| {
                ActionError::Failed(format!(
                    "verify_signature input 'data' ('{}') could not be resolved: {e}",
                    data_ref.display_name()
                ))
            })?;

        let signature_id = signature_ref.artifact_id();
        let signature =
            resolve_artifact_bytes(ctx.artifacts, &signature_id, signature_ref.property())
                .map_err(|e| {
                    ActionError::Failed(format!(
                        "verify_signature input 'signature' ('{}') could not be resolved: {e}",
                        signature_ref.display_name()
                    ))
                })?;

        reporter.log(
            Icon::Spinner,
            format!(
                "Verifying {algorithm} signature over {}...",
                data_ref.display_name()
            ),
        )?;

        let (verified, checked_by) = if let Some(backend) = backend {
            verify_through_backend(
                backend,
                backend_key.as_ref(),
                &data,
                &signature,
                algorithm,
                &key_ref.display_name(),
            )?
        } else {
            let public_der = public_der.as_deref().ok_or_else(|| {
                ActionError::Failed(format!(
                    "Key '{}' does not expose a public key, so its signatures can only be \
                     checked by the backend holding it. Name that backend on this step.",
                    key_ref.display_name()
                ))
            })?;
            let verified = crate::signatures::verify(public_der, &data, &signature, algorithm)
                .map_err(|e| ActionError::Failed(format!("Verification failed to run: {e}")))?;
            (verified, "software".to_string())
        };

        if !verified {
            reporter.log(Icon::Cross, "Signature does not match")?;
            return Err(ActionError::Failed(format!(
                "Signature verification failed: the {algorithm} signature '{}' does not match '{}' under key '{}'",
                signature_ref.display_name(),
                data_ref.display_name(),
                key_ref.display_name()
            )));
        }

        reporter.log(Icon::Checkmark, "Signature verified")?;

        reporter.fact(StepFact::BackendOperation {
            step: step.id.clone(),
            kind: "verify_signature".to_string(),
            inputs: json!({
                "key_artifact": key_ref.display_name(),
                "data_artifact": data_ref.display_name(),
                "signature_artifact": signature_ref.display_name(),
                "algorithm": algorithm.to_string(),
                "verifier": checked_by,
            }),
            outputs: json!({
                "verified": true,
                // Absent when the key never left the device that checked the
                // signature, which is the only case with nothing to fingerprint.
                "public_key_fingerprint": public_der.as_deref().map(compute_fingerprint),
                "signature_fingerprint": compute_fingerprint(&signature),
            }),
            fingerprint: None,
        })?;

        Ok(StepResult::completed("Signature verified"))
    }
}

/// Delegate verification to the backend named on the step.
///
/// The backend verifies by key reference, so this needs a key the backend
/// holds. A step that names a backend but passes a bare public key is refused
/// rather than quietly verified in software: the author asked for a specific
/// verifier, and silently substituting another would misreport who checked the
/// evidence.
fn verify_through_backend(
    backend: &mut dyn Backend,
    backend_key: Option<&BackendKeyMeta<'_>>,
    data: &[u8],
    signature: &[u8],
    algorithm: rite_sdk::SignAlgorithm,
    key_name: &str,
) -> Result<(bool, String), ActionError> {
    let backend_name = backend.name().to_string();

    let Some((owner, key_id, _, _)) = backend_key else {
        return Err(ActionError::Failed(format!(
            "Step names backend '{backend_name}', but key '{key_name}' is not managed by a backend. \
             Drop the `backend:` field to verify it in software."
        )));
    };

    let sign_backend = require_sign_backend(backend, owner, key_name)?;
    let verified = sign_backend.verify(key_id, data, signature, algorithm)?;
    Ok((verified, backend_name))
}

/// Recover the public key to verify under, and the algorithm it implies.
///
/// A backend-managed key states its own algorithm and may keep the key itself
/// on the device, so the key material is optional: it is needed to verify in
/// software and to fingerprint the verifier in the transcript, but a backend
/// asked to check its own signature needs neither. A bare key states nothing,
/// so the provider reads the algorithm out of the structure rather than the
/// ceremony having to declare what the bytes already say.
fn resolve_public_key(
    ctx: &HandlerContext,
    key_ref: &rite_model::ArtifactRef,
    key_id: &rite_model::ArtifactId,
    backend_key: Option<&BackendKeyMeta<'_>>,
) -> Result<(Option<Vec<u8>>, KeyAlgorithm), ActionError> {
    if let Some((_, _, algorithm, public_key)) = backend_key {
        return Ok((public_key.map(|key| (*key).clone()), *algorithm));
    }

    // A signer's public key usually arrives inside a certificate rather than on
    // its own: `piv_read_certificate` produces one, and a counterparty sends
    // one. Unwrapping it here lets a step name the certificate directly.
    let der = match ctx.artifacts.get(key_id) {
        Some(ArtifactValue::Certificate { der }) => crate::signatures::certificate_public_key(der)
            .map_err(|e| {
            ActionError::Failed(format!(
                "verify_signature input 'key' ('{}') is a certificate whose public key could not \
                 be read: {e}",
                key_ref.display_name()
            ))
        })?,
        _ => resolve_artifact_bytes(ctx.artifacts, key_id, key_ref.property()).map_err(|e| {
            ActionError::Failed(format!(
                "verify_signature input 'key' ('{}') could not be resolved: {e}",
                key_ref.display_name()
            ))
        })?,
    };

    let algorithm = crate::signatures::public_key_algorithm(&der).map_err(|e| {
        ActionError::Failed(format!(
            "verify_signature input 'key' ('{}') is not a usable public key: {e}",
            key_ref.display_name()
        ))
    })?;
    Ok((Some(der), algorithm))
}
