//! `decrypt_data` action, recover the content of an encrypted-data artifact.

use rite_model::ActionType;
use rite_runtime::{
    Action, ActionError, ArtifactValue, BackendKeyMeta, HandlerContext, Icon, Reporter, StepInfo,
    StepResult, compute_fingerprint, resolve_backend_key,
};
use rite_sdk::{Backend, EncryptedData, KeyCheckValue, KeyProtection, WrapScheme, cms};
use secrecy::SecretBox;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::crypto::content::{self, SealedContent};

/// Open a container `encrypt_data` produced, or one supplied as a material,
/// back to bytes.
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
        let from_material;
        let encrypted = match artifact {
            ArtifactValue::EncryptedData(encrypted) => encrypted,
            // A container sealed outside the ceremony, with `openssl cms
            // -encrypt` for instance, arrives as a material's bytes. It is
            // described from those bytes, as one this ceremony produced was.
            ArtifactValue::Bytes(bytes) => {
                from_material = container_from_material(&data_id, bytes)?;
                &from_material
            }
            ArtifactValue::WrappedKey(_) => {
                return Err(ActionError::Failed(format!(
                    "Artifact '{data_id}' is a wrapped key, which is opened with 'unwrap_key': \
                     it installs what comes out rather than handing it over as bytes."
                )));
            }
            _ => {
                return Err(ActionError::Failed(format!(
                    "Artifact '{data_id}' is not encrypted content"
                )));
            }
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
        let key_backend = key.backend_name.to_string();
        let backend_key_id = key.key_id.clone();

        let envelope = cms::read_auth_enveloped(encrypted.data())
            .map_err(|e| ActionError::Failed(format!("Cannot read the container: {e}")))?;
        let own = KeyName::of(&key, envelope.protection, &key_ref.display_name())?;

        // Checked before any decrypt, because the content tag authenticates the
        // content and nothing around it. A blob addressed elsewhere would
        // otherwise fail as an unauthenticated tag, which says nothing about
        // why.
        if !own.answers_to(&envelope.key_identifier) {
            return Err(ActionError::Failed(
                own.refusal(&envelope.key_identifier, &key_ref.display_name()),
            ));
        }

        reporter.log(
            Icon::Spinner,
            format!("Decrypting '{}' under {scheme}...", data_ref.display_name()),
        )?;

        let (transport, _) =
            crate::crypto::transport_backend(backend, &key_backend, "open a data key")?;

        // Taken from the container rather than assumed, so a backend that does
        // not implement the protection the container names refuses it rather
        // than decrypting under the wrong mechanism.
        //
        // A failure here and a failure of the content tag below are reported
        // differently, which tells whoever reads the message whether the
        // padding of the protected key was valid. Using that as a padding
        // oracle takes many adaptive attempts, and a ceremony step runs once,
        // in front of its witnesses.
        let data_key =
            transport.open_data_key(&backend_key_id, &envelope.wrapped_cek, envelope.protection)?;
        if data_key.len() != content::KEY_BYTES {
            return Err(ActionError::Failed(format!(
                "The content key in this container is {} bytes, and AES-256-GCM takes {}",
                data_key.len(),
                content::KEY_BYTES
            )));
        }
        let mut plaintext = content::open(
            &data_key,
            &SealedContent {
                nonce: envelope.nonce,
                ciphertext: envelope.ciphertext,
                tag: envelope.tag,
            },
        )?;

        reporter.log(Icon::Checkmark, "Content decrypted")?;

        reporter.backend_operation(
            "decrypt_data",
            json!({
                "scheme": scheme.to_string(),
                "encrypted_data": data_ref.display_name(),
                "encrypted_data_fingerprint": data_fingerprint,
                "decryption_key": key_ref.display_name(),
                own.field(): own.recorded(),
            }),
            produced(plaintext.len()),
            // The artifact that was opened, which is what links this step to
            // the encrypt that produced it. The content names itself nowhere.
            Some(data_fingerprint),
        )?;

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
fn produced(content_bytes: usize) -> Value {
    json!({
        "content_bytes": content_bytes,
    })
}

/// Describe a material's bytes as a container this step opens.
fn container_from_material(
    data_id: &impl std::fmt::Display,
    bytes: &[u8],
) -> Result<EncryptedData, ActionError> {
    let facts = cms::describe(bytes).map_err(|e| {
        ActionError::Failed(format!(
            "Artifact '{data_id}' is neither encrypted content nor a CMS container: {e}"
        ))
    })?;
    EncryptedData::new(WrapScheme::CmsAes256Gcm, facts.description, bytes.to_vec()).map_err(|e| {
        // The algorithms the container names, so the refusal says which of
        // them the scheme does not take.
        let named = serde_json::to_string(&e.description)
            .unwrap_or_else(|_| "an unreadable description".to_string());
        ActionError::Failed(format!(
            "Artifact '{data_id}' is a CMS container that {} does not admit: it names {named}",
            e.scheme
        ))
    })
}

/// The decryption key, by the names a container may give its recipient.
enum KeyName {
    /// A symmetric key, named by its check value.
    CheckValue(KeyCheckValue),
    /// A public key. Rite names it by the SHA-256 of its SPKI, which is what
    /// the transcript records and what `encrypt_data` writes. X.509 tooling
    /// names it by the SHA-1 of RFC 5280 method 1, which is what a certificate's
    /// subject key identifier usually holds, so a container sealed to a
    /// certificate with `openssl cms -keyid` names it that way.
    PublicKey {
        fingerprint: String,
        spki_digest: Vec<u8>,
        rfc5280: Vec<u8>,
    },
}

impl KeyName {
    /// The names `key` answers to, for a container whose content key is
    /// protected with `protection`.
    fn of(
        key: &BackendKeyMeta<'_>,
        protection: KeyProtection,
        display_name: &str,
    ) -> Result<Self, ActionError> {
        match protection {
            KeyProtection::AesKeyWrap => {
                let check_value = key.check_value.ok_or_else(|| {
                    ActionError::Failed(format!(
                        "'{display_name}' is a {} key, and this container is addressed to a \
                         symmetric one",
                        key.algorithm
                    ))
                })?;
                Ok(Self::CheckValue(check_value.clone()))
            }
            KeyProtection::RsaOaepSha256 => {
                // A key of another kind is the wrong kind of key, not a
                // different key of the right kind, and the refusal says so.
                if !WrapScheme::RsaOaepSha256.accepts_recipient(key.algorithm) {
                    return Err(ActionError::Failed(format!(
                        "'{display_name}' is {}, and this container is addressed to an \
                         RSA-2048 or RSA-4096 key",
                        key.algorithm
                    )));
                }
                let public_key = key.public_key.ok_or_else(|| {
                    ActionError::Failed(format!(
                        "'{display_name}' is a {} key with no public half, and this container is \
                         addressed to an RSA public key",
                        key.algorithm
                    ))
                })?;
                Ok(Self::PublicKey {
                    fingerprint: compute_fingerprint(public_key.as_bytes()),
                    spki_digest: Sha256::digest(public_key.as_bytes()).to_vec(),
                    rfc5280: public_key
                        .rfc5280_key_identifier()
                        .map_err(|e| ActionError::Failed(e.to_string()))?,
                })
            }
            other => Err(ActionError::Failed(format!(
                "This container protects its content key with {other}, which decrypt_data does \
                 not open"
            ))),
        }
    }

    /// Whether the container's recipient identifier names this key.
    fn answers_to(&self, identifier: &[u8]) -> bool {
        match self {
            Self::CheckValue(check_value) => identifier == check_value.as_bytes(),
            Self::PublicKey {
                spki_digest,
                rfc5280,
                ..
            } => identifier == spki_digest.as_slice() || identifier == rfc5280.as_slice(),
        }
    }

    /// Why a container naming `identifier` is not this key's, with both sides
    /// rendered alike.
    fn refusal(&self, identifier: &[u8], display_name: &str) -> String {
        match self {
            Self::CheckValue(check_value) => format!(
                "This artifact is addressed to the key with check value {}, and \
                 '{display_name}' has {check_value}",
                named_check_value(identifier)
            ),
            Self::PublicKey {
                fingerprint,
                rfc5280,
                ..
            } => format!(
                "This artifact is addressed to the key with subject key identifier {}, and \
                 '{display_name}' is {fingerprint}, or {} by RFC 5280",
                named_key_identifier(identifier),
                base16ct::lower::encode_string(rfc5280)
            ),
        }
    }

    /// The transcript field this key is recorded under.
    fn field(&self) -> &'static str {
        match self {
            Self::CheckValue(_) => "decryption_key_check_value",
            Self::PublicKey { .. } => "decryption_key_fingerprint",
        }
    }

    /// The key as the transcript names it.
    fn recorded(&self) -> String {
        match self {
            Self::CheckValue(check_value) => check_value.to_string(),
            Self::PublicKey { fingerprint, .. } => fingerprint.clone(),
        }
    }
}

/// A subject key identifier, as a `sha256:` fingerprint where it is the length
/// of one and as hex otherwise, so a SHA-1 identifier is not presented as a
/// fingerprint the transcript could hold.
fn named_key_identifier(identifier: &[u8]) -> String {
    let hex = base16ct::lower::encode_string(identifier);
    if identifier.len() == 32 {
        format!("sha256:{hex}")
    } else {
        hex
    }
}

/// A `kekid.keyIdentifier`, as a check value where the bytes are one, so the
/// message invites a reader to compare two values that are alike, and hex
/// otherwise rather than a claim to be a check value it is not.
fn named_check_value(identifier: &[u8]) -> String {
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
