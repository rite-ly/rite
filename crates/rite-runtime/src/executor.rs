//! Execution-level error / outcome types and shared helpers used by
//! [`crate::runner::Executor`] when walking a resolved ceremony.

use crate::actions::ArtifactValue;
use crate::step_info::StepInfo;
use rite_model::{
    ActionType, ArtifactId, ArtifactKind, FileKind, Material, MaterialKind, MaterialSource,
    Sha256Digest, Step, StepId,
};
use rite_sdk::{BackendError, CertificateDer, PublicKeyDer, csr_from_file};
use secrecy::{ExposeSecret, SecretBox};
use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::output_config::OutputConfig;

/// Errors during ceremony execution.
#[derive(Debug, Error)]
pub enum ExecutionError {
    /// Required parameters are missing values.
    #[error("Validation failed: {0}")]
    ValidationFailed(String),

    /// The operator chose to stop the ceremony. Not an error condition: the
    /// active step (if any) is already recorded in the transcript stream, so
    /// the terminal message stays ceremony-level rather than naming a step.
    #[error("Ceremony aborted by the operator")]
    Aborted,

    /// An I/O error occurred.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// A step handler returned a failure.
    #[error("Step '{step}' failed: {reason}")]
    StepFailed {
        /// Step that failed.
        step: StepId,
        /// Failure description.
        reason: String,
    },

    /// The action type is not registered.
    #[error("Unknown action: '{0}'")]
    UnknownAction(ActionType),

    /// Invalid or missing parameters for a handler.
    #[error("Invalid params: {0}")]
    InvalidParams(String),

    /// The host operating system failed to provide entropy for the seed.
    #[error("Failed to gather machine entropy: {0}")]
    EntropyError(String),

    /// A material could not be loaded.
    #[error("Failed to load material '{name}': {reason}")]
    MaterialLoadFailed {
        /// Material name.
        name: String,
        /// Failure description.
        reason: String,
    },

    /// An output artifact could not be written.
    #[error("Failed to write output '{name}': {reason}")]
    OutputWriteFailed {
        /// Output name.
        name: String,
        /// Failure description.
        reason: String,
    },

    /// Transcript writing failed.
    #[error("Transcript error: {0}")]
    TranscriptError(String),

    /// A backend returned an error.
    #[error("Backend error: {0}")]
    BackendError(#[from] BackendError),

    /// An action produced an artifact of a kind its spec does not allow: a
    /// defect in the action, stopped before any later step reads the
    /// artifact or an output writes it.
    #[error(
        "Step '{step}': '{action}' produced '{artifact}' as {produced}, a kind it never \
         creates"
    )]
    UnexpectedArtifactKind {
        /// Step whose action produced the artifact.
        step: StepId,
        /// The action.
        action: ActionType,
        /// The artifact produced.
        artifact: ArtifactId,
        /// Its kind.
        produced: ArtifactKind,
    },
}

/// Build a `StepInfo` from a resolved `Step`.
pub(crate) fn step_info_from(step: &Step) -> StepInfo {
    StepInfo::new(
        step.id.clone(),
        step.role.clone(),
        step.backend.clone(),
        step.creates.clone(),
        step.reads_resolved.clone(),
    )
}

/// A material as the run holds it, with the digest of the file it came from.
pub(crate) struct LoadedMaterial {
    /// The artifact the material is.
    pub(crate) value: ArtifactValue,
    /// The digest of the file's bytes as read, for a file whose kind is not
    /// secret: a digest of a secret can be tested against guesses.
    pub(crate) digest: Option<Sha256Digest>,
}

/// Load a single material into an `ArtifactValue`.
///
/// A key a backend holds is not loaded here: it binds at the first step that
/// reads it.
pub(crate) fn load_material_artifact(
    name: &str,
    material: &Material,
) -> Result<LoadedMaterial, ExecutionError> {
    let unhashed = |value| LoadedMaterial {
        value,
        digest: None,
    };
    match &material.kind {
        MaterialKind::BackendKey(_) => Err(ExecutionError::MaterialLoadFailed {
            name: name.to_string(),
            reason: "a key a backend holds binds at the first step that reads it".to_string(),
        }),
        MaterialKind::Physical { identifier, .. } => {
            let text = identifier
                .as_deref()
                .or(material.title.as_deref())
                .unwrap_or(name)
                .to_string();
            Ok(unhashed(ArtifactValue::Text(text)))
        }
        MaterialKind::File { kind, source } => {
            let source = source
                .as_ref()
                .ok_or_else(|| ExecutionError::MaterialLoadFailed {
                    name: name.to_string(),
                    reason: "no file given for the material".to_string(),
                })?;
            match source {
                MaterialSource::File { file } => {
                    let bytes = fs::read(file).map_err(|e| ExecutionError::MaterialLoadFailed {
                        name: name.to_string(),
                        reason: e.to_string(),
                    })?;
                    let digest = (!kind.is_secret()).then(|| Sha256Digest::of(&bytes));
                    let value = file_material(*kind, bytes).map_err(|reason| {
                        ExecutionError::MaterialLoadFailed {
                            name: name.to_string(),
                            reason: format!("declared as '{kind}', but {reason}"),
                        }
                    })?;
                    Ok(LoadedMaterial { value, digest })
                }
                MaterialSource::Identifier { identifier } => {
                    // A file material given an identifier: treat as text content.
                    Ok(unhashed(ArtifactValue::Text(identifier.clone())))
                }
            }
        }
    }
}

/// A file's bytes as the kind it declares.
///
/// Where the bytes say what they are, they are checked: a certificate, a
/// public key and a request parse, text is UTF-8, and a PEM private key is
/// labelled as one. A checked file is still held as the bytes it holds, not
/// re-encoded: a step that signs or hashes it, and a person comparing its
/// digest with `sha256sum`, work on the file, which is also what
/// `material_digest` records. A step that needs a key or a certificate
/// parses the bytes again.
///
/// Elsewhere the kind is the author's claim, held as bytes as before kinds:
/// a signature, a wrapped key and encrypted content look like any bytes.
/// `decrypt_data` describes a container from a material's bytes; `unwrap_key`
/// takes only a wrapped key a step produced. A secret's bytes go straight
/// into the box that wipes them, before anything can fail.
fn file_material(kind: FileKind, bytes: Vec<u8>) -> Result<ArtifactValue, String> {
    let secret = |bytes: Vec<u8>| SecretBox::new(Box::new(bytes));
    Ok(match kind {
        FileKind::Bytes | FileKind::WrappedKey | FileKind::EncryptedData => {
            ArtifactValue::Bytes(bytes)
        }
        FileKind::Text => ArtifactValue::Text(
            String::from_utf8(bytes).map_err(|_| "the file is not UTF-8 text".to_string())?,
        ),
        FileKind::Secret => ArtifactValue::Secret(secret(bytes)),
        FileKind::PrivateKey => {
            let key = secret(bytes);
            check_private_key_label(key.expose_secret())?;
            ArtifactValue::PrivateKey(key)
        }
        FileKind::PublicKey => {
            PublicKeyDer::from_file(&bytes).map_err(|e| e.to_string())?;
            ArtifactValue::Bytes(bytes)
        }
        FileKind::Certificate => {
            CertificateDer::from_key_material(&bytes).map_err(|e| e.to_string())?;
            ArtifactValue::Bytes(bytes)
        }
        FileKind::Csr => {
            csr_from_file(&bytes).map_err(|e| e.to_string())?;
            ArtifactValue::Bytes(bytes)
        }
        FileKind::Signature => ArtifactValue::Signature(bytes),
    })
}

/// Refuse a PEM file whose first block names something other than a private
/// key.
///
/// Only the label is read, so nothing of the key is decoded or copied. The
/// block may follow text, as the attributes `openssl pkcs12` writes before
/// each. A file with no PEM block is taken as DER, which says nothing about
/// itself: the step that installs the key reads it.
fn check_private_key_label(bytes: &[u8]) -> Result<(), String> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    let Some(rest) = (0..bytes.len()).find_map(|at| bytes.get(at..)?.strip_prefix(BEGIN)) else {
        return Ok(());
    };
    let label = rest.split(|&b| b == b'-').next().unwrap_or_default();
    if label.ends_with(b"PRIVATE KEY") {
        Ok(())
    } else {
        Err(format!(
            "its PEM block is labelled '{}', not a private key",
            String::from_utf8_lossy(label)
        ))
    }
}

/// Write `bytes` to a freshly created file at `path`, failing if anything already exists there.
///
/// Uses `create_new` so the write cannot follow a pre-existing symlink planted at the
/// destination (which could otherwise redirect artifact bytes outside the run directory) and
/// cannot clobber an existing file. On Unix the file is created with `0o600` so artifact
/// material is not world-readable.
///
/// # Errors
///
/// Returns the I/O error if the file exists or cannot be written and synced.
pub fn write_new_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Serialize an artifact, write it to disk, and return `(path, sha256-hex, size-bytes, mime-type)`.
pub(crate) fn write_artifact_to_disk(
    artifact_id: &ArtifactId,
    artifact_value: &ArtifactValue,
    output_config: &OutputConfig,
) -> Result<(PathBuf, Sha256Digest, u64, Option<String>), ExecutionError> {
    let serialized =
        artifact_value
            .serialize(None)
            .map_err(|e| ExecutionError::OutputWriteFailed {
                name: artifact_id.as_str().to_string(),
                reason: e,
            })?;
    // The serialized copy is the one buffer this path owns. Moved into a
    // wiping wrapper rather than dropped as is, so writing opened content
    // leaves no copy of it behind in memory once the file exists.
    let bytes = Zeroizing::new(serialized.bytes);

    let path = output_config
        .artifact_path(artifact_id.as_str(), serialized.extension)
        .map_err(|e| ExecutionError::OutputWriteFailed {
            name: artifact_id.as_str().to_string(),
            reason: e.to_string(),
        })?;

    write_new_file(&path, &bytes).map_err(|e| ExecutionError::OutputWriteFailed {
        name: artifact_id.as_str().to_string(),
        reason: e.to_string(),
    })?;

    // Hashed from the buffer just written and synced, not read back from the
    // file: a read-back would be one more unwiped copy of opened content.
    let hash = Sha256Digest::of(&bytes);

    let size = fs::metadata(&path)
        .map_err(|e| ExecutionError::OutputWriteFailed {
            name: artifact_id.as_str().to_string(),
            reason: format!("metadata read failed: {e}"),
        })?
        .len();

    Ok((path, hash, size, serialized.mime_type))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rite_model::MaterialId;

    fn example(path: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/showcase")
            .join(path)
    }

    fn load(kind: FileKind, path: &str) -> Result<LoadedMaterial, ExecutionError> {
        let material = Material {
            id: MaterialId::new("m"),
            kind: MaterialKind::File {
                kind,
                source: Some(MaterialSource::File {
                    file: example(path),
                }),
            },
            title: None,
            description: None,
        };
        load_material_artifact("m", &material)
    }

    fn refusal(kind: FileKind, path: &str) -> String {
        match load(kind, path) {
            Err(ExecutionError::MaterialLoadFailed { reason, .. }) => reason,
            Err(other) => panic!("unexpected error: {other}"),
            Ok(loaded) => panic!("loaded as {}", loaded.value.kind()),
        }
    }

    /// A file loads as the kind it declares, and a secret kind has no
    /// digest.
    #[test]
    fn a_file_loads_as_its_kind() {
        // Checked, and held as the file's bytes, which the digest covers.
        let file = fs::read(example("test_keys/escrow_public.pem")).expect("readable");
        let public = load(FileKind::PublicKey, "test_keys/escrow_public.pem").expect("loads");
        assert!(matches!(&public.value, ArtifactValue::Bytes(bytes) if *bytes == file));
        assert_eq!(public.digest, Some(Sha256Digest::of(&file)));

        let private = load(FileKind::PrivateKey, "test_keys/escrow_private.pem").expect("loads");
        assert!(matches!(private.value, ArtifactValue::PrivateKey(_)));
        assert!(private.digest.is_none(), "a private key has no digest");

        let secret = load(FileKind::Secret, "test_data/secret.txt").expect("loads");
        assert!(matches!(secret.value, ArtifactValue::Secret(_)));
        assert!(secret.digest.is_none(), "a secret has no digest");

        let text = load(FileKind::Text, "test_data/release_manifest.txt").expect("loads");
        assert!(matches!(text.value, ArtifactValue::Text(_)));
    }

    /// Where the bytes say what they are, a file that is not its declared
    /// kind is refused when it loads, before the first step.
    #[test]
    fn a_file_that_is_not_its_kind_is_refused() {
        let reason = refusal(FileKind::Certificate, "test_keys/escrow_public.pem");
        assert!(
            reason.starts_with("declared as 'certificate', but"),
            "{reason}"
        );

        let reason = refusal(FileKind::PrivateKey, "test_keys/escrow_public.pem");
        assert!(reason.contains("labelled 'PUBLIC KEY'"), "{reason}");

        let reason = refusal(FileKind::Csr, "test_keys/escrow_public.pem");
        assert!(
            reason.contains("expected 'CERTIFICATE REQUEST'"),
            "{reason}"
        );

        assert!(file_material(FileKind::Text, vec![0xff, 0xfe]).is_err());
    }

    /// A private key's label is all that is read of it, and DER passes.
    #[test]
    fn a_private_key_is_checked_by_its_label_only() {
        assert!(check_private_key_label(b"-----BEGIN EC PRIVATE KEY-----\n...").is_ok());
        assert!(check_private_key_label(b"-----BEGIN ENCRYPTED PRIVATE KEY-----").is_ok());
        assert!(check_private_key_label(&[0x30, 0x82, 0x01]).is_ok());
        assert!(check_private_key_label(b"-----BEGIN CERTIFICATE-----").is_err());
        let exported = b"Bag Attributes\n    localKeyID: 01\n-----BEGIN CERTIFICATE-----\n";
        assert!(check_private_key_label(exported).is_err());
        let exported = b"Bag Attributes\n-----BEGIN PRIVATE KEY-----\n";
        assert!(check_private_key_label(exported).is_ok());
    }
}
