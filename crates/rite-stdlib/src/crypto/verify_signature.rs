//! `verify_signature` action: check a signature against a public key.

use rite_model::{ActionType, StepFact};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, HandlerContext, Icon, Reporter, StepInfo,
    StepResult, compute_fingerprint, parse_params, resolve_artifact_bytes,
};
use rite_sdk::Backend;
use serde_json::json;

use super::sign_data::resolve_sign_algorithm;
use crate::params::VerifySignatureParams;

/// Verify a signature over data, given the signer's public key.
///
/// Alone among the cryptographic actions, this one needs no backend (see
/// [`crate::signatures`] for why). The `key` input may be a keypair, a bare
/// public key, or a certificate carrying one.
///
/// Naming a `backend:` chooses who runs the check, not what is checked. The key
/// resolves the same way either way, so a step gains a hardware or remote
/// verifier without changing what it accepts.
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
        let public_key =
            crate::signatures::resolve_public_key(ctx.artifacts, &key_id, key_ref.property())
                .map_err(|e| {
                    ActionError::Failed(format!(
                        "verify_signature input 'key' ('{}') is not a usable public key: {e}",
                        key_ref.display_name()
                    ))
                })?;
        let key_algorithm = public_key.algorithm().map_err(|e| {
            ActionError::Failed(format!(
                "verify_signature input 'key' ('{}') uses an algorithm Rite cannot verify: {e}",
                key_ref.display_name()
            ))
        })?;

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

        // The key is already resolved, so the backend decides only who runs the
        // check, never what is checked.
        let (verified, checked_by) = if let Some(backend) = backend {
            let backend_name = backend.name().to_string();
            let verifier = backend.as_verify_mut().ok_or_else(|| {
                ActionError::Failed(format!(
                    "Backend '{backend_name}' does not verify signatures. \
                     Drop the `backend:` field to check this one in software."
                ))
            })?;
            let checked = verifier.verify_public_key(&public_key, &data, &signature, algorithm)?;
            (checked, backend_name)
        } else {
            let checked = crate::signatures::verify(&public_key, &data, &signature, algorithm)
                .map_err(|e| ActionError::Failed(format!("Verification failed to run: {e}")))?;
            (checked, "software".to_string())
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
                "public_key_fingerprint": compute_fingerprint(public_key.as_bytes()),
                "signature_fingerprint": compute_fingerprint(&signature),
            }),
            fingerprint: None,
        })?;

        Ok(StepResult::completed("Signature verified"))
    }
}
