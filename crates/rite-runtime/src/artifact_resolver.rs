//! Artifact resolution for ceremony execution.
//!
//! This module provides utilities for resolving artifacts stored in the `ExecutionState`
//! to their byte content or backend key metadata. Artifact references are pre-parsed
//! at resolution time (see `StepInputs` in rite-model), so no `${...}` parsing
//! happens here.
//!
//! ## Key Functions
//!
//! - [`resolve_artifact_bytes`] - Extract byte content from an artifact
//! - [`resolve_backend_key`] - Get backend key metadata for backend operations

use crate::actions::ArtifactValue;
use crate::executor::ExecutionError;
use rite_model::ArtifactId;
use rite_sdk::{KeyAlgorithm, KeyId};
use std::collections::HashMap;
use std::hash::BuildHasher;

/// Resolve an artifact reference to byte content.
///
/// # Arguments
/// * `artifacts` - The artifact store from `ActionContext`
/// * `artifact_id` - The artifact ID
/// * `property` - Optional subproperty (e.g., "private" or "public")
///
/// # Returns
/// The resolved bytes, or an error if resolution fails.
///
/// # Supported references
/// - `artifact_id` → full artifact content
/// - `artifact_id` + "private" → private key from keypair
/// - `artifact_id` + "public" → public key from keypair
pub fn resolve_artifact_bytes<S: BuildHasher>(
    artifacts: &HashMap<ArtifactId, ArtifactValue, S>,
    artifact_id: &ArtifactId,
    property: Option<&str>,
) -> Result<Vec<u8>, ExecutionError> {
    let artifact = artifacts.get(artifact_id).ok_or_else(|| {
        ExecutionError::InvalidParams(format!("Artifact '{artifact_id}' not found"))
    })?;

    match (artifact, property) {
        // Backend-managed key - only public key is accessible
        (
            ArtifactValue::BackendKey {
                public_key: Some(pub_key),
                ..
            },
            Some("public"),
        ) => Ok(pub_key.clone()),
        (
            ArtifactValue::BackendKey {
                public_key: None, ..
            },
            Some("public"),
        ) => {
            let id = artifact_id.as_str();
            Err(ExecutionError::InvalidParams(format!(
                "Public key for '{id}' is not exportable from backend"
            )))
        }
        (ArtifactValue::BackendKey { .. }, Some("private")) => {
            let id = artifact_id.as_str();
            Err(ExecutionError::InvalidParams(format!(
                "Cannot access private key from backend-managed key '{id}'"
            )))
        }

        // Real public key
        (ArtifactValue::PublicKey { key_data, .. }, None) => Ok(key_data.clone()),

        // Real wrapped key
        (ArtifactValue::WrappedKey { data, .. }, None) => Ok(data.clone()),

        // Materials (loaded from files or inline)
        (ArtifactValue::Bytes(bytes), None) => Ok(bytes.clone()),
        (ArtifactValue::Text(text), None) => Ok(text.as_bytes().to_vec()),

        // X.509 certificate: return DER bytes
        (ArtifactValue::Certificate { der }, None) => Ok(der.clone()),

        // Invalid combinations
        _ => Err(ExecutionError::InvalidParams(format!(
            "Cannot extract bytes from artifact '{artifact_id}' with property '{property:?}'"
        ))),
    }
}

/// Backend key metadata returned by artifact resolution.
/// Contains (`backend_name`, `key_id`, `algorithm`, `public_key`).
pub type BackendKeyMeta<'a> = (&'a str, &'a KeyId, KeyAlgorithm, Option<&'a Vec<u8>>);

/// Resolve an artifact to a backend-managed key reference.
///
/// Returns (`backend_name`, `key_id`, `algorithm`, `public_key`) tuple for backend operations.
/// This is used when actions need to perform operations on backend-managed keys.
///
/// # Errors
/// Returns an error if:
/// - The artifact doesn't exist
/// - The artifact is not a `BackendKey` variant
pub fn resolve_backend_key<'a, S: BuildHasher>(
    artifacts: &'a HashMap<ArtifactId, ArtifactValue, S>,
    artifact_id: &ArtifactId,
) -> Result<BackendKeyMeta<'a>, ExecutionError> {
    let id = artifact_id.as_str();
    let artifact = artifacts
        .get(artifact_id)
        .ok_or_else(|| ExecutionError::InvalidParams(format!("Artifact '{id}' not found")))?;

    match artifact {
        ArtifactValue::BackendKey {
            backend_name,
            key_id,
            algorithm,
            public_key,
        } => Ok((
            backend_name.as_str(),
            key_id,
            *algorithm,
            public_key.as_ref(),
        )),
        _ => Err(ExecutionError::InvalidParams(format!(
            "Artifact '{id}' is not a backend-managed key"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_bytes() {
        let mut artifacts = HashMap::new();
        artifacts.insert(
            ArtifactId::new("ksr"),
            ArtifactValue::Bytes(b"test content".to_vec()),
        );

        let result = resolve_artifact_bytes(&artifacts, &ArtifactId::new("ksr"), None).unwrap();
        assert_eq!(result, b"test content");
    }

    #[test]
    fn test_resolve_text() {
        let mut artifacts = HashMap::new();
        artifacts.insert(
            ArtifactId::new("usb_drive"),
            ArtifactValue::Text("USB Drive".to_string()),
        );

        let result =
            resolve_artifact_bytes(&artifacts, &ArtifactId::new("usb_drive"), None).unwrap();
        assert_eq!(result, b"USB Drive");
    }

    #[test]
    fn test_resolve_not_found() {
        let artifacts: HashMap<ArtifactId, ArtifactValue> = HashMap::new();
        let result = resolve_artifact_bytes(&artifacts, &ArtifactId::new("missing"), None);
        assert!(result.is_err());
    }
}
