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

use crate::actions::{ArtifactValue, Share};
use crate::executor::ExecutionError;
use rite_model::ArtifactId;
use rite_sdk::{KeyAlgorithm, KeyCheckValue, KeyId, PublicKeyDer};
use secrecy::ExposeSecret;
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
/// The bytes, borrowed from the store. A reader that only looks at them makes
/// no copy, which is what keeps opened content from being duplicated on every
/// read; one that needs to keep them copies on its own account.
///
/// # Supported references
/// - `artifact_id` → full artifact content
/// - `artifact_id` + "private" → private key from keypair
/// - `artifact_id` + "public" → public key from keypair
/// - `artifact_id` + "kcv" → key check value of a symmetric key
pub fn resolve_artifact_bytes<'a, S: BuildHasher>(
    artifacts: &'a HashMap<ArtifactId, ArtifactValue, S>,
    artifact_id: &ArtifactId,
    property: Option<&str>,
) -> Result<&'a [u8], ExecutionError> {
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
        ) => Ok(pub_key.as_bytes()),
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

        // The check value of a symmetric key, as its three raw bytes, so
        // `${artifact.kek.kcv | hex}` reads the way an operator says it.
        (
            ArtifactValue::BackendKey {
                check_value: Some(kcv),
                ..
            },
            Some("kcv"),
        ) => Ok(kcv.as_bytes()),
        (
            ArtifactValue::BackendKey {
                check_value: None,
                algorithm,
                ..
            },
            Some("kcv"),
        ) => {
            let id = artifact_id.as_str();
            Err(ExecutionError::InvalidParams(format!(
                "'{id}' is a {algorithm} key, which is named by its public half \
                 rather than by a check value"
            )))
        }

        // Real public key
        (ArtifactValue::PublicKey(key), None) => Ok(key.as_bytes()),

        // Real wrapped key
        (ArtifactValue::WrappedKey(wrapped), None) => Ok(wrapped.data()),

        // The container, as it would be written to media. What is inside it
        // needs the key, which is `decrypt_data`'s job and not this one's.
        (ArtifactValue::EncryptedData(encrypted), None) => Ok(encrypted.data()),

        // Materials (loaded from files or inline), and content a step opened.
        // The second reads like the first: what a ceremony does with opened
        // content is what it does with any bytes, and only the write to disk
        // is gated.
        (ArtifactValue::Bytes(bytes), None) => Ok(bytes),
        (ArtifactValue::Secret(bytes), None) => Ok(bytes.expose_secret()),
        (ArtifactValue::Text(text), None) => Ok(text.as_bytes()),

        // A share has no byte form to borrow; laying one out is a container's
        // job. A step that reads a share asks for the share.
        (ArtifactValue::Shares(_), _) => Err(ExecutionError::InvalidParams(format!(
            "'{artifact_id}' holds shares of a secret, which are read as shares and not as \
             bytes; only a step that shows or combines shares can name one"
        ))),

        // X.509 certificate: the whole certificate, not the key inside it.
        // `issue_certificate` reads an issuer certificate through here.
        (ArtifactValue::Certificate(certificate), None) => Ok(certificate.as_bytes()),

        // Invalid combinations
        _ => Err(ExecutionError::InvalidParams(format!(
            "Cannot extract bytes from artifact '{artifact_id}' with property '{property:?}'"
        ))),
    }
}

/// Resolve a reference to one share.
///
/// `shares.share_N` names the share evaluated at `N` in a set a split made.
/// A set holding exactly one share, as a typed-back share arrives, is named
/// without a property. Borrowed, like every read.
pub fn resolve_share<'a, S: BuildHasher>(
    artifacts: &'a HashMap<ArtifactId, ArtifactValue, S>,
    artifact_id: &ArtifactId,
    property: Option<&str>,
) -> Result<&'a Share, ExecutionError> {
    let artifact = artifacts.get(artifact_id).ok_or_else(|| {
        ExecutionError::InvalidParams(format!("Artifact '{artifact_id}' not found"))
    })?;
    let ArtifactValue::Shares(set) = artifact else {
        return Err(ExecutionError::InvalidParams(format!(
            "'{artifact_id}' is not a share; a share is one of a set 'split_secret' made, or \
             one a custodian typed back"
        )));
    };
    match property {
        Some(property) => {
            let index = share_index(property).ok_or_else(|| {
                ExecutionError::InvalidParams(format!(
                    "'{property}' is not a share of '{artifact_id}'; a share is named \
                     'share_1' through 'share_{}'",
                    set.count()
                ))
            })?;
            set.share(index).ok_or_else(|| {
                ExecutionError::InvalidParams(format!(
                    "'{artifact_id}' has shares 1 through {}, and share_{index} is not one of them",
                    set.count()
                ))
            })
        }
        None => set.only().ok_or_else(|| {
            ExecutionError::InvalidParams(format!(
                "'{artifact_id}' is a set of {} shares; name one as '{artifact_id}.share_1' \
                 through '{artifact_id}.share_{}'",
                set.count(),
                set.count()
            ))
        }),
    }
}

/// The `N` of a `share_N` property, or `None` for anything else.
///
/// `N` is one or more ASCII digits, no sign, no leading zero, from 1 to
/// 255: the one spelling of each index, so a name is a share or is not.
fn share_index(property: &str) -> Option<u8> {
    let digits = property.strip_prefix("share_")?;
    if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u8>().ok()
}

/// What an action needs to know about a backend-managed key.
///
/// Borrowed from the artifact store rather than cloned: a caller that needs an
/// owned `KeyId` or key past the borrow clones the field it needs.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct BackendKeyMeta<'a> {
    /// Backend that owns the key. A step running on another one is an error.
    pub backend_name: &'a str,
    /// The reference that backend answers to.
    pub key_id: &'a KeyId,
    /// Algorithm, for choosing a signature scheme and for the transcript.
    pub algorithm: KeyAlgorithm,
    /// Public half, absent for a key the backend does not export.
    pub public_key: Option<&'a PublicKeyDer>,
    /// Check value, present for a symmetric key and absent for a keypair.
    ///
    /// What names a key with no public half, so a step recording which key it
    /// operated on has something to record for either form.
    pub check_value: Option<&'a KeyCheckValue>,
}

/// Resolve an artifact to a backend-managed key reference.
///
/// Used when an action operates on a key the backend holds, which is every
/// action that needs a private key.
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
            check_value,
        } => Ok(BackendKeyMeta {
            backend_name: backend_name.as_str(),
            key_id,
            algorithm: *algorithm,
            public_key: public_key.as_ref(),
            check_value: check_value.as_ref(),
        }),
        _ => Err(ExecutionError::InvalidParams(format!(
            "Artifact '{id}' is not a backend-managed key"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::ShareSet;

    #[test]
    fn resolving_a_bytes_artifact_returns_its_content() {
        let mut artifacts = HashMap::new();
        artifacts.insert(
            ArtifactId::new("ksr"),
            ArtifactValue::Bytes(b"test content".to_vec()),
        );

        let result = resolve_artifact_bytes(&artifacts, &ArtifactId::new("ksr"), None).unwrap();
        assert_eq!(result, b"test content");
    }

    #[test]
    fn resolving_a_text_artifact_returns_its_utf8_bytes() {
        let mut artifacts = HashMap::new();
        artifacts.insert(
            ArtifactId::new("usb_drive"),
            ArtifactValue::Text("USB Drive".to_string()),
        );

        let result =
            resolve_artifact_bytes(&artifacts, &ArtifactId::new("usb_drive"), None).unwrap();
        assert_eq!(result, b"USB Drive");
    }

    fn two_shares() -> HashMap<ArtifactId, ArtifactValue> {
        let set = ShareSet::new(
            2,
            [
                Share::new(2, 1, vec![0x11; 4]),
                Share::new(2, 2, vec![0x22; 4]),
            ],
        );
        HashMap::from([(ArtifactId::new("shares"), ArtifactValue::Shares(set))])
    }

    #[test]
    fn a_share_set_has_no_byte_form() {
        let artifacts = two_shares();
        for property in [None, Some("share_1")] {
            let error = resolve_artifact_bytes(&artifacts, &ArtifactId::new("shares"), property)
                .expect_err("shares are read as shares")
                .to_string();
            assert!(error.contains("not as bytes"), "{error}");
        }
    }

    #[test]
    fn a_share_is_named_by_index_and_a_set_of_one_needs_no_name() {
        let artifacts = two_shares();
        let id = ArtifactId::new("shares");
        assert_eq!(
            resolve_share(&artifacts, &id, Some("share_2"))
                .unwrap()
                .index(),
            2
        );

        let missing = resolve_share(&artifacts, &id, Some("share_3"))
            .unwrap_err()
            .to_string();
        assert!(missing.contains("share_3 is not one of them"), "{missing}");
        let misspelt = resolve_share(&artifacts, &id, Some("share_02"))
            .unwrap_err()
            .to_string();
        assert!(misspelt.contains("'share_02' is not a share"), "{misspelt}");
        let unnamed = resolve_share(&artifacts, &id, None)
            .unwrap_err()
            .to_string();
        assert!(unnamed.contains("is a set of 2 shares"), "{unnamed}");

        let one = ArtifactId::new("typed_back");
        let mut artifacts = artifacts;
        artifacts.insert(
            one.clone(),
            ArtifactValue::Shares(ShareSet::new(2, [Share::new(2, 3, vec![0x33; 4])])),
        );
        assert_eq!(resolve_share(&artifacts, &one, None).unwrap().index(), 3);

        let bytes = ArtifactId::new("bytes");
        artifacts.insert(bytes.clone(), ArtifactValue::Bytes(vec![1]));
        let not_a_share = resolve_share(&artifacts, &bytes, None)
            .unwrap_err()
            .to_string();
        assert!(not_a_share.contains("is not a share"), "{not_a_share}");
    }

    #[test]
    fn a_share_property_is_digits_from_one_with_no_sign_and_no_leading_zero() {
        assert_eq!(share_index("share_1"), Some(1));
        assert_eq!(share_index("share_255"), Some(255));
        assert_eq!(share_index("share_0"), None);
        assert_eq!(share_index("share_01"), None);
        assert_eq!(share_index("share_+1"), None);
        assert_eq!(share_index("share_256"), None);
        assert_eq!(share_index("share_"), None);
        assert_eq!(share_index("share1"), None);
        assert_eq!(share_index("shares_1"), None);
    }

    #[test]
    fn resolving_an_unknown_artifact_fails() {
        let artifacts: HashMap<ArtifactId, ArtifactValue> = HashMap::new();
        let result = resolve_artifact_bytes(&artifacts, &ArtifactId::new("missing"), None);
        assert!(result.is_err());
    }
}
