//! `encrypt_data` action, encrypt content for a key the backend holds.

use rite_model::{ActionType, StepFact};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, ArtifactValue, HandlerContext, Icon,
    Reporter, StepInfo, StepResult, compute_fingerprint, parse_params, resolve_artifact_bytes,
    resolve_backend_key,
};
use rite_sdk::{Backend, DataKey, EncryptedData, KeyAlgorithm, KeyCheckValue, WrapScheme, cms};
use serde_json::json;

use crate::crypto::content;
use crate::params::EncryptDataParams;

/// Encrypt bytes into a container only the named key opens.
///
/// Envelope encryption, which is the shape every key-protection device offers:
/// the backend produces a fresh content-encryption key and a copy of it that
/// only the key-encryption key can open, the content is encrypted under the
/// first, and the container carries the second. The content itself never
/// reaches the backend.
///
/// `wrap_key` for bytes that are not a key, and deliberately a second verb. A
/// wrap says a key left a backend under protection, and the trust-boundary
/// language in the transcript exists to record that. Encrypted content makes no
/// custody claim, so it gets its own record and its own artifact type.
pub struct EncryptDataAction;

impl Action for EncryptDataAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::EncryptData,
            description: "Encrypt content under a key held by a backend",
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
        let typed: EncryptDataParams = parse_params(params)?;
        let scheme = typed.scheme.unwrap_or(WrapScheme::CmsAes256Gcm);
        if !scheme.carries_content() {
            return Err(ActionError::Failed(format!(
                "encrypt_data writes a container that carries content, and {scheme} carries \
                 a key: it encrypts the payload directly under the recipient's key, which \
                 bounds it to roughly a key's size."
            )));
        }

        let data_ref = step.required_named_input("data", "encrypt_data")?;
        let key_ref = step.required_named_input("encryption_key", "encrypt_data")?;

        let data_id = data_ref.artifact_id();
        let payload = resolve_artifact_bytes(ctx.artifacts, &data_id, data_ref.property())
            .map_err(|e| {
                ActionError::Failed(format!(
                    "Cannot read content from '{}': {e}",
                    data_ref.display_name()
                ))
            })?;

        let key_id = key_ref.artifact_id();
        let key = resolve_backend_key(ctx.artifacts, &key_id).map_err(|e| {
            ActionError::Failed(format!(
                "encryption_key '{}' must be a key held by this backend: {e}",
                key_ref.display_name()
            ))
        })?;
        let check_value = recipient_check_value(&key, &key_ref.display_name())?;
        let key_backend = key.backend_name.to_string();
        let backend_key_id = key.key_id.clone();

        reporter.log(
            Icon::Spinner,
            format!(
                "Encrypting {} bytes to '{}' under {scheme}...",
                payload.len(),
                key_ref.display_name()
            ),
        )?;

        let (transport, backend_name, backend_fingerprint) =
            crate::crypto::transport_backend(backend, &key_backend, "protect a data key")?;

        // The backend makes the content-encryption key and the copy only the
        // key-encryption key opens. Both halves come from the device that holds
        // the KEK, so nothing here has to see the KEK itself.
        let data_key = transport.generate_data_key(&backend_key_id, KeyAlgorithm::Aes256)?;
        let encrypted = seal_into_container(&data_key, &check_value, &payload)?;

        let fingerprint = compute_fingerprint(encrypted.data());
        reporter.log(Icon::Checkmark, "Content encrypted")?;

        reporter.fact(StepFact::BackendOperation {
            step: step.id.clone(),
            kind: "encrypt_data".to_string(),
            inputs: json!({
                "scheme": scheme.to_string(),
                "data": data_ref.display_name(),
                // How much was encrypted, and deliberately no digest of it.
                // Content is what a ceremony encrypts because it is secret, and
                // a hash of a secret is the shape rite#126 removed.
                "content_bytes": payload.len(),
                "encryption_key": key_ref.display_name(),
                "encryption_key_check_value": check_value.to_string(),
            }),
            outputs: produced(
                &backend_name,
                &backend_fingerprint,
                &fingerprint,
                &encrypted,
            ),
            fingerprint: Some(fingerprint.clone()),
        })?;

        let message = format!("{} bytes encrypted under {scheme}", payload.len());
        let value = ArtifactValue::EncryptedData(encrypted);

        if let Some(produces) = &step.produces {
            reporter.log(
                Icon::Info,
                format!("Encrypted content stored as artifact '{produces}'"),
            )?;
            Ok(StepResult::completed_with_artifact(
                message,
                produces.clone(),
                value,
            ))
        } else {
            Ok(StepResult::completed(message))
        }
    }
}

/// Encrypt the content under the data key and assemble the container around
/// both halves.
///
/// The result is described by reading the bytes back, never by restating what
/// was just written. A description that disagreed with the artifact is what
/// this path exists to make impossible.
fn seal_into_container(
    data_key: &DataKey,
    check_value: &KeyCheckValue,
    payload: &[u8],
) -> Result<EncryptedData, ActionError> {
    // The container has to declare the key-encryption algorithm, so a data key
    // the backend protected in its own envelope cannot go in one. Refused by
    // name: writing it under `id-aes256-wrap` anyway would produce an artifact
    // whose structure lies about it, which no CMS reader could open and which
    // `rite verify` would report as checked.
    if !data_key.protection().is_nameable_in_a_container() {
        return Err(ActionError::Failed(format!(
            "this backend protects a data key with {}, which a CMS container cannot name, so \
             the artifact could not be opened by anything but this backend",
            data_key.protection()
        )));
    }
    let sealed = content::seal(data_key.plaintext(), payload)?;
    let der = cms::write_kek_enveloped(&cms::KekEnvelope {
        key_identifier: check_value.as_bytes().to_vec(),
        wrapped_cek: data_key.wrapped().to_vec(),
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
        tag: sealed.tag,
    })
    .map_err(|e| ActionError::Failed(format!("Cannot write the CMS container: {e}")))?;

    let facts = cms::describe(&der)
        .map_err(|e| ActionError::Failed(format!("Cannot read back the container: {e}")))?;
    // Named here rather than taken, because the container this function writes
    // is the one thing it does not generalise over.
    EncryptedData::new(WrapScheme::CmsAes256Gcm, facts.description, der)
        .map_err(|e| ActionError::Failed(e.to_string()))
}

/// What came out, and what it says about itself.
///
/// The description is read out of the artifact and recorded whole, so a
/// verifier compares the one it re-derives from the blob against this one and a
/// field added to it is checked without touching either side.
fn produced(
    backend_name: &str,
    backend_fingerprint: &str,
    fingerprint: &str,
    encrypted: &EncryptedData,
) -> serde_json::Value {
    json!({
        "backend": backend_name,
        "backend_fingerprint": backend_fingerprint,
        "encrypted_data_fingerprint": fingerprint,
        "encryption": encrypted.description(),
    })
}

/// What the container names the recipient by.
///
/// `CMS-AES-256-GCM` addresses a symmetric recipient by its check value, which
/// is also what the transcript records and what a token displays, so a blob and
/// a transcript compare without either side holding the key. A key with no
/// check value has no such name, and the refusal says which key it was rather
/// than reporting a missing field.
fn recipient_check_value(
    key: &rite_runtime::BackendKeyMeta<'_>,
    display_name: &str,
) -> Result<KeyCheckValue, ActionError> {
    if key.algorithm != KeyAlgorithm::Aes256 {
        return Err(ActionError::Failed(format!(
            "{} encrypts to a 256-bit symmetric key, and '{display_name}' is {}",
            WrapScheme::CmsAes256Gcm,
            key.algorithm
        )));
    }
    key.check_value.cloned().ok_or_else(|| {
        ActionError::Failed(format!(
            "Backend '{}' gives no check value for '{display_name}', so the container has no \
             way to name its recipient",
            key.backend_name
        ))
    })
}
