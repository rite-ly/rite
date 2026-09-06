//! `sign_data` action: sign arbitrary data with a backend-managed key.

use rite_model::{ActionType, StepFact};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, ArtifactValue, HandlerContext, Icon,
    ParamIssue, Reporter, StepInfo, StepResult, compute_fingerprint, parse_params,
    resolve_artifact_bytes, resolve_backend_key,
};
use rite_sdk::{Backend, KeyAlgorithm, SignAlgorithm, SignBackend};
use serde_json::json;

use crate::params::{SignDataParams, string_param};

/// Sign data with a key the backend holds.
///
/// The generic counterpart to `piv_sign`: it works with any backend
/// implementing `SignBackend`, and takes the key by artifact reference rather
/// than by device slot.
pub struct SignDataAction;

impl Action for SignDataAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::SignData,
            description: "Sign data with a backend-managed key",
            category: ActionCategory::Crypto,
        }
    }

    fn validate(&self, params: &serde_json::Value, _step: &StepInfo) -> Vec<ParamIssue> {
        validate_sign_algorithm(params)
    }

    fn execute(
        &self,
        step: &StepInfo,
        ctx: &HandlerContext,
        params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        let typed: SignDataParams = parse_params(params)?;

        if let Some(message) = &typed.message {
            reporter.log(Icon::Info, message.clone())?;
        }

        let key_ref = step.required_named_input("key", "sign_data")?;
        let data_ref = step.required_named_input("data", "sign_data")?;

        let key_id = key_ref.artifact_id();
        let key = resolve_backend_key(ctx.artifacts, &key_id).map_err(|e| {
            ActionError::Failed(format!(
                "sign_data input 'key' ('{}') must be a backend-managed key: {e}",
                key_ref.display_name()
            ))
        })?;
        let key_algorithm = key.algorithm;
        let algorithm = resolve_sign_algorithm(typed.algorithm.as_deref(), key_algorithm)?;

        let data_id = data_ref.artifact_id();
        let data =
            resolve_artifact_bytes(ctx.artifacts, &data_id, data_ref.property()).map_err(|e| {
                ActionError::Failed(format!(
                    "sign_data input 'data' ('{}') could not be resolved: {e}",
                    data_ref.display_name()
                ))
            })?;

        reporter.log(
            Icon::Spinner,
            format!(
                "Signing {} ({} bytes) with {algorithm}...",
                data_ref.display_name(),
                data.len()
            ),
        )?;

        let backend = backend
            .ok_or_else(|| ActionError::Failed("Backend required for sign_data".to_string()))?;
        let backend_name = backend.name().to_string();
        let backend_fingerprint = backend.fingerprint();

        let sign_backend =
            require_sign_backend(backend, key.backend_name, &key_ref.display_name())?;
        let signature = sign_backend.sign(key.key_id, &data, algorithm)?;

        let signature_fingerprint = compute_fingerprint(&signature);
        // The step's completion message is shown on its own, so it carries the
        // result rather than a log line repeating it.
        let summary = format!("Signature produced ({} bytes)", signature.len());

        reporter.fact(StepFact::BackendOperation {
            step: step.id.clone(),
            kind: "sign_data".to_string(),
            inputs: json!({
                "key_artifact": key_ref.display_name(),
                "data_artifact": data_ref.display_name(),
                "key_algorithm": key_algorithm.to_string(),
                "algorithm": algorithm.to_string(),
            }),
            outputs: json!({
                "backend": backend_name,
                "backend_fingerprint": backend_fingerprint,
                "signature_len": signature.len(),
            }),
            fingerprint: Some(signature_fingerprint),
        })?;

        if let Some(produces) = &step.produces {
            reporter.log(
                Icon::Info,
                format!("Signature stored as artifact '{produces}'"),
            )?;
            Ok(StepResult::completed_with_artifact(
                summary,
                produces.clone(),
                ArtifactValue::Bytes(signature),
            ))
        } else {
            Ok(StepResult::completed(summary))
        }
    }
}

/// Check that `backend` owns the key, and expose its signing capability.
///
/// Shared by both signing actions so an operator who points a step at the wrong
/// backend gets the same message either way. Read `name()` and `fingerprint()`
/// before calling: the returned capability borrows the backend mutably.
pub(super) fn require_sign_backend<'a>(
    backend: &'a mut dyn Backend,
    key_owner: &str,
    key_name: &str,
) -> Result<&'a mut dyn SignBackend, ActionError> {
    let backend_name = backend.name().to_string();
    if key_owner != backend_name {
        return Err(ActionError::Failed(format!(
            "Key '{key_name}' is owned by backend '{key_owner}', but this step runs on '{backend_name}'"
        )));
    }
    backend.as_sign_mut().ok_or_else(|| {
        ActionError::Failed(format!("Backend '{backend_name}' does not support signing"))
    })
}

/// Check an `algorithm:` value both signing actions accept, before either runs.
///
/// Only the name is checked. Whether the key accepts it needs the key, which
/// exists no earlier than execution, so [`resolve_sign_algorithm`] settles that
/// half.
pub(super) fn validate_sign_algorithm(params: &serde_json::Value) -> Vec<ParamIssue> {
    match string_param(params, "algorithm") {
        Ok(None) => Vec::new(),
        Ok(Some(name)) if name.parse::<SignAlgorithm>().is_ok() => Vec::new(),
        Ok(Some(name)) => vec![ParamIssue::definition(format!(
            "unknown signature algorithm '{name}'"
        ))],
        Err(message) => vec![ParamIssue::definition(message)],
    }
}

/// Decide which signature algorithm to use for a key.
///
/// Shared with `verify_signature`, which faces the same choice from the other
/// side and must reach the same answer for an unannotated step.
///
/// An explicit name is checked against the key rather than trusted: a ceremony
/// that names an algorithm the key cannot perform is a mistake worth reporting
/// before any signing is attempted, not a backend error mid-step.
pub(super) fn resolve_sign_algorithm(
    requested: Option<&str>,
    key_algorithm: KeyAlgorithm,
) -> Result<SignAlgorithm, ActionError> {
    let Some(requested) = requested else {
        return key_algorithm.default_sign_algorithm().ok_or_else(|| {
            ActionError::Failed(format!("{key_algorithm} keys cannot produce signatures"))
        });
    };

    let algorithm: SignAlgorithm = requested
        .parse()
        .map_err(|_| ActionError::Failed(format!("Unknown signature algorithm: {requested}")))?;

    if !algorithm.accepts_key(key_algorithm) {
        return Err(ActionError::Failed(format!(
            "Signature algorithm {algorithm} cannot be used with a {key_algorithm} key"
        )));
    }
    Ok(algorithm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_the_algorithm_from_the_key_when_unspecified() {
        assert_eq!(
            resolve_sign_algorithm(None, KeyAlgorithm::EcdsaP384).unwrap(),
            SignAlgorithm::EcdsaSha384
        );
        assert_eq!(
            resolve_sign_algorithm(None, KeyAlgorithm::MlDsa87).unwrap(),
            SignAlgorithm::MlDsa87
        );
    }

    /// The override exists for this case: an RSA key admits two schemes and the
    /// key alone cannot say which the ceremony wants.
    #[test]
    fn honours_an_override_the_key_supports() {
        assert_eq!(
            resolve_sign_algorithm(Some("RSA-PSS-SHA256"), KeyAlgorithm::Rsa4096).unwrap(),
            SignAlgorithm::RsaPssSha256
        );
    }

    #[test]
    fn rejects_an_override_the_key_cannot_perform() {
        let err = resolve_sign_algorithm(Some("ECDSA-SHA256"), KeyAlgorithm::Rsa2048).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("ECDSA-SHA256"), "{message}");
        assert!(message.contains("RSA-2048"), "{message}");
    }

    #[test]
    fn rejects_an_unknown_algorithm_name() {
        assert!(resolve_sign_algorithm(Some("ecdsa_sha256"), KeyAlgorithm::EcdsaP256).is_err());
    }

    /// A symmetric key reaching a signing step is a ceremony authoring error,
    /// and the message should say so rather than name a missing default.
    #[test]
    fn rejects_a_key_that_cannot_sign() {
        let err = resolve_sign_algorithm(None, KeyAlgorithm::Aes256).unwrap_err();
        assert!(err.to_string().contains("cannot produce signatures"));
    }
}

#[cfg(test)]
mod validate_tests {
    use super::validate_sign_algorithm;
    use serde_json::json;

    #[test]
    fn accepts_a_known_algorithm_name() {
        assert!(validate_sign_algorithm(&json!({"algorithm": "RSA-PSS-SHA256"})).is_empty());
    }

    #[test]
    fn rejects_an_unknown_algorithm_name() {
        let issues = validate_sign_algorithm(&json!({"algorithm": "RSA-PSS-SHA255"}));
        let [issue] = issues.as_slice() else {
            panic!("expected exactly one issue, got {issues:?}");
        };
        assert!(
            issue.message.contains("unknown signature algorithm"),
            "{}",
            issue.message
        );
    }

    #[test]
    fn an_absent_value_is_not_an_error() {
        assert!(validate_sign_algorithm(&json!({})).is_empty());
    }
}
