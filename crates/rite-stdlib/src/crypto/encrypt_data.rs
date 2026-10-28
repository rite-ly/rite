//! `encrypt_data` action, encrypt content for a key the backend holds or for a
//! public key.

use rite_model::{ActionType, ArtifactRef};
use rite_runtime::{
    Action, ActionError, ArtifactValue, HandlerContext, Icon, Reporter, StepInfo, StepResult,
    compute_fingerprint, parse_params, resolve_artifact_bytes, resolve_backend_key,
};
use rite_sdk::{
    Backend, DataKey, EncryptedData, KeyAlgorithm, KeyCheckValue, KeyProtection, PublicKeyDer,
    RandomBackend, WrapScheme, cms,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::content;
use rite_model::params::EncryptDataParams;

/// Encrypt bytes into a container only the named key opens.
///
/// Envelope encryption, which is the shape every key-protection device offers:
/// a fresh content-encryption key, and a copy of it that only the recipient can
/// open. The content is encrypted under the first, and the container carries
/// the second. The content itself never reaches the backend.
///
/// The input the step names selects the recipient. `encryption_key:` names a
/// key the backend holds, which produces both halves. `recipient:` names a
/// public key held elsewhere: the backend supplies the content key's random
/// bytes, and protecting it takes only the public key.
///
/// `wrap_key` for bytes that are not a key, and deliberately a second verb. A
/// wrap says a key left a backend under protection, and the trust-boundary
/// language in the transcript exists to record that. Encrypted content makes no
/// custody claim, so it gets its own record and its own artifact type.
pub struct EncryptDataAction;

impl Action for EncryptDataAction {
    fn action_type(&self) -> ActionType {
        ActionType::EncryptData
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
        let (path, key_ref) = recipient_input(step)?;

        let data_id = data_ref.artifact_id();
        let payload = resolve_artifact_bytes(ctx.artifacts, &data_id, data_ref.property())
            .map_err(|e| {
                ActionError::Failed(format!(
                    "Cannot read content from '{}': {e}",
                    data_ref.display_name()
                ))
            })?;

        reporter.log(
            Icon::Spinner,
            format!(
                "Encrypting {} bytes to '{}' under {scheme}...",
                payload.len(),
                key_ref.display_name()
            ),
        )?;
        let (data_key, addressee) = match path {
            Path::Backend => backend_data_key(ctx, key_ref, backend)?,
            Path::Recipient => {
                // Both refusals come before the recipient is recorded, so a
                // step that could not have encrypted anything does not record
                // a key as having received content.
                let random = random_source(backend)?;
                let recipient = crate::crypto::ExternalRecipient {
                    key_ref,
                    expected: typed.expect_recipient.as_deref(),
                    consequence: "Content encrypted to it would be readable by that key's \
                                  holder and not by the one intended, so this step will not run.",
                }
                .resolve(step, ctx, reporter, admits_recipient)?;
                recipient_data_key(&recipient, random)?
            }
        };
        let encrypted = seal_into_container(&data_key, &addressee, payload)?;

        let fingerprint = compute_fingerprint(encrypted.data());
        reporter.log(Icon::Checkmark, "Content encrypted")?;

        let inputs = match &addressee {
            Addressee::CheckValue(check_value) => json!({
                "scheme": scheme.to_string(),
                "data": data_ref.display_name(),
                // How much was encrypted, and deliberately no digest of it.
                // Content is what a ceremony encrypts because it is secret,
                // and a hash of a secret is the shape rite#126 removed.
                "content_bytes": payload.len(),
                "encryption_key": key_ref.display_name(),
                "encryption_key_check_value": check_value.to_string(),
            }),
            // The fingerprint is in its own fact, recorded before the
            // encryption, so the method can be published while the recipient
            // stays withheld.
            Addressee::PublicKey(_) => json!({
                "scheme": scheme.to_string(),
                "data": data_ref.display_name(),
                "content_bytes": payload.len(),
                "recipient": key_ref.display_name(),
            }),
        };
        reporter.backend_operation(
            "encrypt_data",
            inputs,
            produced(&fingerprint, &encrypted),
            Some(fingerprint.clone()),
        )?;

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

/// Which input names the recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Path {
    /// `encryption_key:`, a symmetric key this backend holds.
    Backend,
    /// `recipient:`, a public key whose private half is held elsewhere.
    Recipient,
}

/// Select the path from the input the step names.
///
/// The resolver rejects a step that names neither or both, so reaching the
/// error here means the step was built without going through resolution.
fn recipient_input(step: &StepInfo) -> Result<(Path, &ArtifactRef), ActionError> {
    match (
        step.named_input("encryption_key"),
        step.named_input("recipient"),
    ) {
        (Some(key), None) => Ok((Path::Backend, key)),
        (None, Some(key)) => Ok((Path::Recipient, key)),
        (Some(_), Some(_)) => Err(ActionError::Failed(
            "encrypt_data reads both 'encryption_key' and 'recipient'; name one".to_string(),
        )),
        (None, None) => Err(ActionError::Failed(
            "encrypt_data: missing required input 'encryption_key' or 'recipient'".to_string(),
        )),
    }
}

/// What the container names its recipient by.
enum Addressee {
    /// A symmetric key, by its check value, in a `KEKRecipientInfo`.
    CheckValue(KeyCheckValue),
    /// A public key, by the SHA-256 of its SPKI, in a `KeyTransRecipientInfo`.
    /// The same digest the transcript writes as the key's `sha256:`
    /// fingerprint, so a blob and a record compare without holding the key.
    PublicKey(Vec<u8>),
}

impl Addressee {
    /// The key protection this recipient form is written with.
    fn protection(&self) -> KeyProtection {
        match self {
            Self::CheckValue(_) => KeyProtection::AesKeyWrap,
            Self::PublicKey(_) => KeyProtection::RsaOaepSha256,
        }
    }

    fn key_identifier(&self) -> Vec<u8> {
        match self {
            Self::CheckValue(check_value) => check_value.as_bytes().to_vec(),
            Self::PublicKey(spki_digest) => spki_digest.clone(),
        }
    }
}

/// Both halves of the data key from the backend that holds `key_ref`.
///
/// Both come from the device that holds the key-encryption key, so nothing
/// here has to see that key.
fn backend_data_key(
    ctx: &HandlerContext,
    key_ref: &ArtifactRef,
    backend: Option<&mut dyn Backend>,
) -> Result<(DataKey, Addressee), ActionError> {
    let key = resolve_backend_key(ctx.artifacts, &key_ref.artifact_id()).map_err(|e| {
        ActionError::Failed(format!(
            "encryption_key '{}' must be a key held by this backend: {e}. Read it as \
             'recipient:' to encrypt to a public key instead.",
            key_ref.display_name()
        ))
    })?;
    let check_value = recipient_check_value(&key, &key_ref.display_name())?;
    let (transport, _) =
        crate::crypto::transport_backend(backend, key.backend_name, "protect a data key")?;
    let data_key = transport.generate_data_key(key.key_id, KeyAlgorithm::Aes256)?;
    Ok((data_key, Addressee::CheckValue(check_value)))
}

/// The step's backend, as the source of the content-encryption key's random
/// bytes.
///
/// The content key is key material, so its randomness comes from the backend
/// the ceremony named, as a generated key's would.
fn random_source(backend: Option<&mut dyn Backend>) -> Result<&mut dyn RandomBackend, ActionError> {
    let backend = backend.ok_or_else(|| {
        ActionError::Failed(
            "Backend required to draw the content-encryption key's random bytes".to_string(),
        )
    })?;
    let backend_name = backend.name().to_string();
    backend.as_random_mut().ok_or_else(|| {
        ActionError::Failed(format!(
            "Backend '{backend_name}' cannot generate random bytes, which the \
             content-encryption key is made from"
        ))
    })
}

/// Whether the container can address `recipient`: an RSA key of a size every
/// other path accepts, which is what a `KeyTransRecipientInfo` under
/// RSAES-OAEP takes.
fn admits_recipient(recipient: &PublicKeyDer) -> Result<(), ActionError> {
    let algorithm = recipient
        .algorithm()
        .map_err(|e| ActionError::Failed(e.to_string()))?;
    if WrapScheme::RsaOaepSha256.accepts_recipient(algorithm) {
        Ok(())
    } else {
        Err(ActionError::Failed(format!(
            "{} encrypts to an RSA-2048 or RSA-4096 public key, and the recipient is {algorithm}",
            WrapScheme::CmsAes256Gcm
        )))
    }
}

/// A data key protected for `recipient`, its bytes drawn from `random`.
///
/// Protecting it needs only the public key and happens in software.
fn recipient_data_key(
    recipient: &PublicKeyDer,
    random: &mut dyn RandomBackend,
) -> Result<(DataKey, Addressee), ActionError> {
    let cek = Zeroizing::new(random.generate_random(content::KEY_BYTES)?);
    let data_key = content::protect_for(recipient, cek)?;
    let spki_digest = Sha256::digest(recipient.as_bytes()).to_vec();
    Ok((data_key, Addressee::PublicKey(spki_digest)))
}

/// Encrypt the content under the data key and assemble the container around
/// both halves.
///
/// The result is described by reading the bytes back, never by restating what
/// was just written. A description that disagreed with the artifact is what
/// this path exists to make impossible.
fn seal_into_container(
    data_key: &DataKey,
    addressee: &Addressee,
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
    // The protection decides the recipient form, and each form takes its own
    // kind of identifier. Any other pairing would put a check value where the
    // container expects a key identifier, or the reverse.
    if data_key.protection() != addressee.protection() {
        return Err(ActionError::Failed(format!(
            "this data key is protected with {}, and a container addressed to this recipient \
             takes {}",
            data_key.protection(),
            addressee.protection()
        )));
    }
    let sealed = content::seal(data_key.plaintext(), payload)?;
    let der = cms::write_auth_enveloped(&cms::Envelope {
        protection: data_key.protection(),
        key_identifier: addressee.key_identifier(),
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
fn produced(fingerprint: &str, encrypted: &EncryptedData) -> serde_json::Value {
    json!({
        "encrypted_data_fingerprint": fingerprint,
        "encryption": encrypted.description(),
    })
}

/// What the container names a symmetric recipient by.
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
            "{} encrypts to a 256-bit symmetric key, and '{display_name}' is {}. Read it as \
             'recipient:' to encrypt to its public key instead.",
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
