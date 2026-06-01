//! Execution-level error / outcome types and shared helpers used by
//! [`crate::runner::Executor`] when walking a resolved ceremony.

use crate::actions::ArtifactValue;
use crate::step_info::StepInfo;
use crate::transcript::compute_file_fingerprint;
use rite_model::{ActionType, ArtifactId, Material, MaterialKind, MaterialSource, Step, StepId};
use rite_sdk::BackendError;
use std::fs;
use std::io;
use std::path::PathBuf;
use thiserror::Error;

use crate::output_config::OutputConfig;

/// Errors during ceremony execution.
#[derive(Debug, Error)]
pub enum ExecutionError {
    /// Required parameters are missing values.
    #[error("Validation failed: {0}")]
    ValidationFailed(String),

    /// A step was aborted by the user.
    #[error("Step '{0}' was aborted by user")]
    StepAborted(StepId),

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

/// Load a single material into an `ArtifactValue`.
pub(crate) fn load_material_artifact(
    name: &str,
    material: &Material,
) -> Result<ArtifactValue, ExecutionError> {
    match &material.kind {
        MaterialKind::Physical { identifier, .. } => {
            let text = identifier
                .as_deref()
                .or(material.title.as_deref())
                .unwrap_or(name)
                .to_string();
            Ok(ArtifactValue::Text(text))
        }
        MaterialKind::Digital { source } => {
            let source = source
                .as_ref()
                .ok_or_else(|| ExecutionError::MaterialLoadFailed {
                    name: name.to_string(),
                    reason: "no source provided for digital material".to_string(),
                })?;
            match source {
                MaterialSource::File { file } => {
                    let bytes = fs::read(file).map_err(|e| ExecutionError::MaterialLoadFailed {
                        name: name.to_string(),
                        reason: e.to_string(),
                    })?;
                    Ok(ArtifactValue::Bytes(bytes))
                }
                MaterialSource::Identifier { identifier } => {
                    // Digital material with an inline identifier: treat as text content.
                    Ok(ArtifactValue::Text(identifier.clone()))
                }
            }
        }
    }
}

/// Serialize an artifact, write it to disk, and return `(path, sha256-hex, size-bytes, mime-type)`.
pub(crate) fn write_artifact_to_disk(
    artifact_id: &ArtifactId,
    artifact_value: &ArtifactValue,
    output_config: &OutputConfig,
) -> Result<(PathBuf, String, u64, Option<String>), ExecutionError> {
    let serialized =
        artifact_value
            .serialize(None)
            .map_err(|e| ExecutionError::OutputWriteFailed {
                name: artifact_id.as_str().to_string(),
                reason: e,
            })?;

    let path = output_config.artifact_path(artifact_id.as_str(), serialized.extension);

    fs::write(&path, &serialized.bytes).map_err(|e| ExecutionError::OutputWriteFailed {
        name: artifact_id.as_str().to_string(),
        reason: e.to_string(),
    })?;

    let hash = compute_file_fingerprint(&path).map_err(|e| ExecutionError::OutputWriteFailed {
        name: artifact_id.as_str().to_string(),
        reason: format!("hash computation failed: {e}"),
    })?;

    let size = fs::metadata(&path)
        .map_err(|e| ExecutionError::OutputWriteFailed {
            name: artifact_id.as_str().to_string(),
            reason: format!("metadata read failed: {e}"),
        })?
        .len();

    Ok((path, hash, size, serialized.mime_type))
}
