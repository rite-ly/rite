//! Transcript configuration and metadata builders.
//!
//! This module handles transcript file path computation and metadata
//! construction for ceremony execution transcripts.

use crate::output_config::OutputConfig;
use crate::transcript::{BinaryInfo, CeremonyInfo, InstanceInfo};
use rite_model::{Ceremony, ParamId};
use std::collections::{BTreeMap, HashMap};
use std::hash::BuildHasher;
use std::path::PathBuf;

/// Configuration for transcript generation.
///
/// `path: None` means transcripts are disabled; `Some(path)` enables them at that path.
#[derive(Debug, Clone, Default)]
pub struct TranscriptConfig {
    /// Path to write the transcript; `None` disables transcript generation.
    pub path: Option<PathBuf>,
    /// Path to the ceremony file (for fingerprinting)
    pub ceremony_file: Option<PathBuf>,
}

impl TranscriptConfig {
    /// Create a config that disables transcript generation.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Create a config from an output configuration.
    ///
    /// The transcript will be written to `<output_dir>/transcript.jsonl`.
    pub fn from_output_config(output_config: &OutputConfig) -> Self {
        Self {
            path: Some(output_config.transcript_path()),
            ceremony_file: None,
        }
    }

    /// Set the ceremony file path for fingerprinting.
    #[must_use]
    pub fn with_ceremony_file(mut self, ceremony_file: PathBuf) -> Self {
        self.ceremony_file = Some(ceremony_file);
        self
    }

    /// Build ceremony info for transcript.
    pub fn build_ceremony_info(&self, ceremony: &Ceremony) -> CeremonyInfo {
        let fingerprint = if let Some(path) = &self.ceremony_file {
            crate::transcript::compute_file_fingerprint(path)
                .unwrap_or_else(|_| "unknown".to_string())
        } else {
            // Compute from ceremony metadata
            let json = serde_json::to_string(&ceremony.metadata).unwrap_or_default();
            crate::transcript::compute_fingerprint(json.as_bytes())
        };

        CeremonyInfo {
            fingerprint,
            name: ceremony.metadata.name.clone(),
            version: "1.0".to_string(),
        }
    }

    /// Build instance info for transcript.
    ///
    /// The fingerprint is always computed from resolved parameter values.
    pub fn build_instance_info<S: BuildHasher>(
        &self,
        ceremony: &Ceremony,
        resolved_params: &HashMap<ParamId, serde_json::Value, S>,
    ) -> Option<InstanceInfo> {
        if ceremony.parameters.is_empty()
            && ceremony.materials.is_empty()
            && ceremony.outputs.is_empty()
        {
            return None;
        }

        // Convert ParamId keys to String for JSON serialization in transcript.
        // BTreeMap for deterministic ordering in transcript output.
        let string_params: BTreeMap<String, serde_json::Value> = resolved_params
            .iter()
            .map(|(id, v)| (id.as_str().to_string(), v.clone()))
            .collect();

        // Always compute fingerprint from resolved params
        let json = serde_json::to_string(&string_params).unwrap_or_default();
        let fingerprint = crate::transcript::compute_fingerprint(json.as_bytes());

        Some(InstanceInfo {
            fingerprint,
            parameters: string_params,
        })
    }
}

/// Deserialize a JSON file from disk.
///
/// Returns `None` when the file is absent or cannot be parsed.
fn read_json_file<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Option<T> {
    let contents = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&contents).ok()
}

/// Read initrd measurements from the tmpfs handoff file.
///
/// Returns `None` when not on a live USB (file absent) or if the file cannot be parsed.
/// The caller treats absence as non-fatal.
pub fn build_initrd_measurements() -> Option<crate::transcript::InitrdMeasurements> {
    read_json_file(std::path::Path::new("/run/rite/initrd-measurements.json"))
}

/// Read and parse the release manifest from the live USB medium.
///
/// Returns `None` when not running from a live USB (file absent) or if the
/// manifest cannot be parsed. The caller treats absence as non-fatal.
pub fn build_image_info() -> Option<crate::transcript::ImageManifest> {
    read_json_file(std::path::Path::new(
        "/run/live/medium/live/rite-manifest.json",
    ))
}

/// Build binary info for transcript.
pub fn build_binary_info() -> BinaryInfo {
    let fingerprint = std::env::current_exe()
        .ok()
        .and_then(|path| crate::transcript::compute_file_fingerprint(&path).ok());

    BinaryInfo {
        fingerprint,
        version: env!("CARGO_PKG_VERSION").to_string(),
    }
}
