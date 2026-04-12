//! Configuration for ceremony output directory structure.

use chrono::Utc;
use std::path::PathBuf;

/// Configuration for ceremony output directory structure.
///
/// All ceremony outputs (artifacts and transcript) are written to a structured
/// directory layout:
///
/// ```text
/// ceremony-name-20251229T143022/
/// ├── transcript.jsonl
/// └── artifacts/
///     ├── wrapped_key.bin
///     ├── public_key.pem
///     └── share_1.txt
/// ```
#[derive(Debug, Clone)]
pub struct OutputConfig {
    /// Base directory for all outputs (e.g., "./runs/ceremony-20251229T143022/")
    base_dir: PathBuf,
}

impl OutputConfig {
    /// Create a new output configuration with the given base directory.
    #[must_use]
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    /// Create output configuration for a ceremony run.
    ///
    /// Generates a timestamped directory name from the ceremony name:
    /// `<parent>/<ceremony-slug>-<YYYYMMDDTHHMMSS>/`
    ///
    /// # Arguments
    /// * `parent` - Parent directory (defaults to current directory if None)
    /// * `ceremony_name` - Human-readable ceremony name to slugify
    #[must_use]
    pub fn for_ceremony(parent: Option<PathBuf>, ceremony_name: &str) -> Self {
        let parent = parent.unwrap_or_else(|| PathBuf::from("."));
        let timestamp = Utc::now().format("%Y%m%dT%H%M%S");
        let slug = slugify(ceremony_name);
        Self {
            base_dir: parent.join(format!("{slug}-{timestamp}")),
        }
    }

    /// Returns the base output directory.
    pub fn base_dir(&self) -> &std::path::Path {
        &self.base_dir
    }

    /// Returns the path to the artifacts subdirectory.
    pub fn artifacts_dir(&self) -> PathBuf {
        self.base_dir.join("artifacts")
    }

    /// Returns the path to the transcript file.
    ///
    /// Uses JSONL format (`transcript.jsonl`) for hash-chained event log.
    pub fn transcript_path(&self) -> PathBuf {
        self.base_dir.join("transcript.jsonl")
    }

    /// Returns the path to the evidence subdirectory.
    pub fn evidence_dir(&self) -> PathBuf {
        self.base_dir.join("evidence")
    }

    /// Returns the path for an artifact with the given ID and extension.
    pub fn artifact_path(&self, id: &str, extension: &str) -> PathBuf {
        self.artifacts_dir().join(format!("{id}.{extension}"))
    }
}

/// Convert a ceremony name to a filesystem-safe slug.
fn slugify(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_config_paths() {
        let config = OutputConfig::new(PathBuf::from("/tmp/ceremony-20251229T143022"));

        assert_eq!(
            config.base_dir(),
            std::path::Path::new("/tmp/ceremony-20251229T143022")
        );
        assert_eq!(
            config.artifacts_dir(),
            PathBuf::from("/tmp/ceremony-20251229T143022/artifacts")
        );
        assert_eq!(
            config.transcript_path(),
            PathBuf::from("/tmp/ceremony-20251229T143022/transcript.jsonl")
        );
        assert_eq!(
            config.artifact_path("wrapped_key", "bin"),
            PathBuf::from("/tmp/ceremony-20251229T143022/artifacts/wrapped_key.bin")
        );
    }

    #[test]
    fn test_slugify() {
        assert_eq!(slugify("Simple Name"), "simple-name");
        assert_eq!(slugify("HSM Bootstrap"), "hsm-bootstrap");
        assert_eq!(slugify("Root CA  Signing"), "root-ca-signing");
        assert_eq!(slugify("Test_Ceremony-2024"), "test-ceremony-2024");
        assert_eq!(slugify("  Leading/Trailing  "), "leading-trailing");
    }
}
