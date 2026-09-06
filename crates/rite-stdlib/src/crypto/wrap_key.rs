//! `wrap_key` action, wrap a backend-resident key for transport.

use rite_model::{ActionType, StepFact};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, ArtifactValue, HandlerContext, Icon,
    ParamIssue, Reporter, StepInfo, StepResult, compute_fingerprint, parse_params,
    resolve_backend_key,
};
use rite_sdk::{Backend, KeyTransportBackend, WrapAlgorithm};
use serde_json::json;

use crate::params::{WrapKeyParams, string_param};

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

    fn validate(&self, params: &serde_json::Value, _step: &StepInfo) -> Vec<ParamIssue> {
        validate_wrap_algorithm(params)
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

        let key_to_wrap = resolve_backend_key(ctx.artifacts, &key_to_wrap_id).map_err(|e| {
            ActionError::Failed(format!(
                "key_to_wrap '{}' must be a BackendKey: {e}",
                key_to_wrap_ref.display_name()
            ))
        })?;

        let key_backend = key_to_wrap.backend_name;
        let (wrapped_key, backend_fingerprint) = if let Ok(wrapping_key) =
            resolve_backend_key(ctx.artifacts, &wrapping_key_id)
        {
            let wrap_key_backend = wrapping_key.backend_name;
            if key_backend != wrap_key_backend {
                return Err(ActionError::Failed(format!(
                    "Key wrapping requires both keys on same backend (key: '{key_backend}', wrapper: '{wrap_key_backend}')"
                )));
            }
            let (transport, backend_fp) = require_transport_backend(backend, key_backend)?;
            reporter.log(Icon::Spinner, "Wrapping key using backend...")?;
            let wk = transport.wrap(key_to_wrap.key_id, wrapping_key.key_id, wrap_alg)?;
            (wk, backend_fp)
        } else {
            let recipient = crate::signatures::resolve_public_key(
                ctx.artifacts,
                &wrapping_key_id,
                wrapping_key_ref.property(),
            )
            .map_err(|e| {
                ActionError::Failed(format!(
                    "Cannot resolve wrapping key '{}' as a public key: {e}",
                    wrapping_key_ref.display_name()
                ))
            })?;
            let (transport, backend_fp) = require_transport_backend(backend, key_backend)?;
            reporter.log(
                Icon::Spinner,
                "Wrapping key to external recipient public key...",
            )?;
            let wk = transport.wrap_to_public(key_to_wrap.key_id, &recipient, wrap_alg)?;
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

/// The schemes a backend in this build can actually perform.
///
/// The remaining [`WrapAlgorithm`] variants describe raw mechanisms with no
/// implementation, so naming one parses and then fails once the step runs.
const IMPLEMENTED: &[WrapAlgorithm] = &[WrapAlgorithm::CmsRsaGcm, WrapAlgorithm::CmsRsaCbc];

/// Check an `algorithm:` value both wrapping actions accept, before either runs.
///
/// A name outside [`WrapAlgorithm`] is wrong in any build. A name inside it
/// that no backend here performs is only wrong in this one, so it carries the
/// weaker kind and a fuller build may still run the ceremony.
pub(super) fn validate_wrap_algorithm(params: &serde_json::Value) -> Vec<ParamIssue> {
    let name = match string_param(params, "algorithm") {
        Ok(None) => return Vec::new(),
        Ok(Some(name)) => name,
        Err(message) => return vec![ParamIssue::definition(message)],
    };

    let Ok(parsed) = name.parse::<WrapAlgorithm>() else {
        return vec![ParamIssue::definition(format!(
            "unknown wrapping algorithm '{name}'. {}",
            supported_schemes()
        ))];
    };

    if IMPLEMENTED.contains(&parsed) {
        return Vec::new();
    }
    vec![ParamIssue::unsupported(format!(
        "wrapping algorithm '{parsed}' has no backend in this build. {}",
        supported_schemes()
    ))]
}

/// The implemented scheme names, for the tail of a rejection message.
fn supported_schemes() -> String {
    let names: Vec<String> = IMPLEMENTED.iter().map(ToString::to_string).collect();
    format!("Supported: {}", names.join(", "))
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

#[cfg(test)]
mod tests {
    use super::validate_wrap_algorithm;
    use rite_runtime::{ParamIssue, ParamIssueKind};
    use serde_json::json;

    /// The one issue `validate_wrap_algorithm` produced, or a panic.
    fn sole_issue(algorithm: &serde_json::Value) -> ParamIssue {
        let issues = validate_wrap_algorithm(&json!({"algorithm": algorithm}));
        let [issue] = issues.as_slice() else {
            panic!("expected exactly one issue, got {issues:?}");
        };
        issue.clone()
    }

    fn sole_error(algorithm: &serde_json::Value) -> String {
        sole_issue(algorithm).message
    }

    #[test]
    fn accepts_the_two_implemented_schemes() {
        for name in ["CMS-RSA-GCM", "CMS-RSA-CBC"] {
            assert!(
                validate_wrap_algorithm(&json!({"algorithm": name})).is_empty(),
                "{name} should be accepted"
            );
        }
    }

    #[test]
    fn rejects_a_scheme_that_parses_but_has_no_backend() {
        // Without this check the step parses and then fails in the backend,
        // by which point the key to wrap has been generated.
        for name in ["AES-KW", "AES-KWP", "RSA-OAEP-SHA256"] {
            let issue = sole_issue(&json!(name));
            assert!(
                issue.message.contains("no backend in this build"),
                "unexpected message for {name}: {}",
                issue.message
            );
            // Build-relative, not a definition error: a fuller build may
            // implement it, so `check` must not condemn the ceremony.
            assert_eq!(issue.kind, ParamIssueKind::Unsupported, "{name}");
        }
    }

    #[test]
    fn rejects_a_name_outside_the_enum() {
        let issue = sole_issue(&json!("CMS-RSA-XTS"));
        assert!(
            issue.message.contains("unknown wrapping algorithm"),
            "{}",
            issue.message
        );
        // No build accepts this name, so it condemns the document.
        assert_eq!(issue.kind, ParamIssueKind::Definition);
    }

    #[test]
    fn names_the_supported_schemes_in_the_message() {
        let error = sole_error(&json!("AES-KW"));
        assert!(
            error.contains("CMS-RSA-GCM") && error.contains("CMS-RSA-CBC"),
            "a rejection must say what to use instead: {error}"
        );
    }

    #[test]
    fn rejects_a_non_string_value() {
        let error = sole_error(&json!(7));
        assert!(error.contains("must be a string"), "{error}");
    }

    #[test]
    fn an_absent_value_is_not_an_error() {
        // Absent means either unset, and defaulted at run time, or deferred to
        // an expression the checker cannot evaluate.
        assert!(validate_wrap_algorithm(&json!({})).is_empty());
    }
}
