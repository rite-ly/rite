//! `decrypt_data` action, recover the content of an encrypted-data artifact.

use rite_model::{ActionType, StepFact};
use rite_runtime::{
    Action, ActionError, ArtifactValue, HandlerContext, Icon, Reporter, StepInfo, StepResult,
    compute_fingerprint, resolve_backend_key,
};
use rite_sdk::{Backend, KeyCheckValue, KeyProtection, cms};
use secrecy::SecretBox;
use serde_json::{Value, json};

use crate::crypto::content::{self, SealedContent};

/// Open a container `encrypt_data` produced, back to bytes.
///
/// The container is undone in the order it was built: the backend opens the
/// data key it protected, and the content is decrypted under that. What comes
/// out is a byte artifact a later step reads the way it reads a material:
/// `import_key` lifts it into a key, `check_value` compares it, `sign_data`
/// signs it. It is held wiped in memory until the run drops it.
pub struct DecryptDataAction;

impl Action for DecryptDataAction {
    fn action_type(&self) -> ActionType {
        ActionType::DecryptData
    }

    fn execute(
        &self,
        step: &StepInfo,
        ctx: &HandlerContext,
        _params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        // No params. Which container the bytes are in and how the content was
        // encrypted are both in the artifact, and a restated value could
        // disagree with the bytes that have to be decrypted.
        let data_ref = step.required_named_input("encrypted_data", "decrypt_data")?;
        let key_ref = step.required_named_input("decryption_key", "decrypt_data")?;

        let data_id = data_ref.artifact_id();
        let artifact = ctx.artifacts.get(&data_id).ok_or_else(|| {
            ActionError::Failed(format!("Encrypted data artifact '{data_id}' not found"))
        })?;
        let ArtifactValue::EncryptedData(encrypted) = artifact else {
            return Err(ActionError::Failed(format!(
                "Artifact '{data_id}' is not encrypted content. A wrapped key is opened with \
                 'unwrap_key', which installs what comes out rather than handing it over as \
                 bytes."
            )));
        };
        let scheme = encrypted.scheme();
        let data_fingerprint = compute_fingerprint(encrypted.data());

        let key_id = key_ref.artifact_id();
        let key = resolve_backend_key(ctx.artifacts, &key_id).map_err(|e| {
            ActionError::Failed(format!(
                "decryption_key '{}' must be a key held by this backend: {e}",
                key_ref.display_name()
            ))
        })?;
        let check_value = key.check_value.cloned().ok_or_else(|| {
            ActionError::Failed(format!(
                "'{}' is a {} key, and this container is addressed to a symmetric one",
                key_ref.display_name(),
                key.algorithm
            ))
        })?;
        let key_backend = key.backend_name.to_string();
        let backend_key_id = key.key_id.clone();

        let envelope = cms::read_kek_enveloped(encrypted.data())
            .map_err(|e| ActionError::Failed(format!("Cannot read the container: {e}")))?;

        // Checked before any decrypt, because the content tag authenticates the
        // content and nothing around it. A blob addressed elsewhere would
        // otherwise fail as an unauthenticated tag, which says nothing about
        // why.
        if envelope.key_identifier != check_value.as_bytes() {
            return Err(ActionError::Failed(format!(
                "This artifact is addressed to the key with check value {}, and '{}' has {}",
                named_recipient(&envelope.key_identifier),
                key_ref.display_name(),
                check_value
            )));
        }

        reporter.log(
            Icon::Spinner,
            format!("Decrypting '{}' under {scheme}...", data_ref.display_name()),
        )?;

        let (transport, backend_name, backend_fingerprint) =
            crate::crypto::transport_backend(backend, &key_backend, "open a data key")?;

        // Taken from the container rather than assumed. The reader admits only
        // `id-aes256-wrap`, so today this is the one value it can be, and
        // passing it is what makes a container that names something else the
        // reader's problem rather than a silent decrypt under the wrong
        // mechanism.
        let data_key = transport.open_data_key(
            &backend_key_id,
            &envelope.wrapped_cek,
            KeyProtection::AesKeyWrap,
        )?;
        let mut plaintext = content::open(
            &data_key,
            &SealedContent {
                nonce: envelope.nonce,
                ciphertext: envelope.ciphertext,
                tag: envelope.tag,
            },
        )?;

        reporter.log(Icon::Checkmark, "Content decrypted")?;

        reporter.fact(StepFact::BackendOperation {
            step: step.id.clone(),
            kind: "decrypt_data".to_string(),
            inputs: json!({
                "scheme": scheme.to_string(),
                "encrypted_data": data_ref.display_name(),
                "encrypted_data_fingerprint": data_fingerprint,
                "decryption_key": key_ref.display_name(),
                "decryption_key_check_value": check_value.to_string(),
            }),
            outputs: produced(&backend_name, &backend_fingerprint, plaintext.len()),
            // The artifact that was opened, which is what links this step to
            // the encrypt that produced it. The content names itself nowhere.
            fingerprint: Some(data_fingerprint),
        })?;

        let message = format!("{} bytes decrypted", plaintext.len());
        // The buffer moves from the cipher's wiping wrapper into the artifact's
        // without a copy. What the wrapper wipes on drop is the empty vector
        // left in its place.
        let value =
            ArtifactValue::Secret(SecretBox::new(Box::new(std::mem::take(&mut *plaintext))));

        if let Some(produces) = &step.produces {
            reporter.log(
                Icon::Info,
                format!("Content stored as artifact '{produces}'"),
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

/// What came out, and from where.
///
/// The size and no digest. What came out is the secret the container existed to
/// protect, and hashing it would put a digest of a secret in the record. What
/// links this step to the encrypt that produced it is the artifact fingerprint,
/// which the fact carries on its own.
fn produced(backend_name: &str, backend_fingerprint: &str, content_bytes: usize) -> Value {
    json!({
        "backend": backend_name,
        "backend_fingerprint": backend_fingerprint,
        "content_bytes": content_bytes,
    })
}

/// Render a recipient identifier the way the transcript names that key.
///
/// A check value where the bytes are one, so the message invites a reader to
/// compare two values that are alike. Anything else is shown as hex rather than
/// claimed to be a check value it is not.
fn named_recipient(identifier: &[u8]) -> String {
    // The length is the whole of what distinguishes the two, since
    // `from_cmac` keeps the leftmost three bytes of anything at least that
    // long. Without this a twenty-byte subject key identifier would be
    // announced as a check value it is not.
    if identifier.len() == KeyCheckValue::LEN
        && let Ok(kcv) = KeyCheckValue::from_cmac(identifier)
    {
        return kcv.to_string();
    }
    base16ct::lower::encode_string(identifier)
}
