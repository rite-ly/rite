//! The evidence bundle: a ceremony run packaged with its definition.
//!
//! A bundle is a directory with a fixed layout:
//!
//! ```text
//! bundle.json                      this index
//! transcript.jsonl                 the transcript, byte for byte as the run wrote it
//! definition/ceremony.rite.yaml    the ceremony YAML the run was resolved from
//! artifacts/<file>                 artifacts the transcript records with a digest
//! ```
//!
//! The index locates files and says what each one is. It repeats no digest:
//! every file other than the transcript is bound by a digest the transcript
//! commits to (the template digest on `CeremonyStarted`, the digest on each
//! `ArtifactWritten`), so a verifier checks files against the transcript and
//! the index adds nothing that would need protecting or redacting on its own.
//! The trust anchor is the transcript fingerprint, never the index.
//!
//! A disclosure bundle has the same layout. Its transcript withholds every
//! line above the index's threshold and folds to the same fingerprint as the
//! complete one; it carries only the artifacts whose facts it discloses, and
//! never the definition, which can name people.

use serde::{Deserialize, Serialize};

use crate::Sha256Digest;
use crate::transcript::Level;

/// Bundle format version this crate writes and reads. 0 while rite is before
/// 1.0, like [`TRANSCRIPT_FORMAT`](crate::TRANSCRIPT_FORMAT).
pub const BUNDLE_FORMAT: u32 = 0;

/// URL of the JSON Schema for the index this release writes, which the index
/// names as its `$schema` so editors validate it.
pub const BUNDLE_SCHEMA: &str = concat!(
    "https://ritely.io/schemas/",
    env!("CARGO_PKG_VERSION"),
    "/bundle.schema.json"
);

/// Name of the index file at the bundle root.
pub const INDEX_FILE: &str = "bundle.json";

/// Path of the transcript within a bundle.
pub const TRANSCRIPT_FILE: &str = "transcript.jsonl";

/// Path of the ceremony definition within a bundle.
pub const DEFINITION_FILE: &str = "definition/ceremony.rite.yaml";

/// Directory holding artifacts within a bundle.
pub const ARTIFACTS_DIR: &str = "artifacts";

/// The index at the root of a bundle.
#[non_exhaustive]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    test,
    schemars(
        description = "The bundle.json index of an evidence bundle: what kind of bundle it is \
        and which files it holds. It repeats no digest: every file other than the transcript is \
        bound by a digest the transcript records, so a verifier checks the files against the \
        transcript."
    )
)]
pub struct BundleIndex {
    /// URL of the JSON Schema the index was written against
    /// ([`BUNDLE_SCHEMA`]). Editors read it; a reader ignores it.
    #[serde(rename = "$schema", skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        test,
        schemars(
            description = "The URL of the JSON Schema this index was written against, for \
            editors. A reader ignores it.",
            extend("format" = "uri")
        )
    )]
    pub schema: Option<String>,
    /// Bundle format version ([`BUNDLE_FORMAT`]). A reader refuses a value it
    /// does not know.
    #[cfg_attr(test, schemars(description = "Version of the bundle format."))]
    pub rite_bundle: u32,
    /// Whether this is the complete record or a disclosure derived from it,
    /// written as `kind`, with a disclosure's `threshold` beside it.
    #[serde(flatten)]
    pub kind: BundleKind,
    /// Fingerprint of the transcript in the bundle. A convenience for
    /// indexing; a verifier recomputes it from the transcript.
    #[cfg_attr(
        test,
        schemars(
            description = "The fingerprint of the bundle's transcript, for indexing. A \
            verifier computes it from the transcript and compares."
        )
    )]
    pub fingerprint: Sha256Digest,
    /// Every file in the bundle other than the index, in a stable order.
    #[cfg_attr(
        test,
        schemars(description = "Every file in the bundle other than the index.")
    )]
    pub files: Vec<BundleFile>,
}

impl BundleIndex {
    /// An index for a complete bundle.
    #[must_use]
    pub fn complete(fingerprint: Sha256Digest, files: Vec<BundleFile>) -> Self {
        Self {
            schema: Some(BUNDLE_SCHEMA.to_string()),
            rite_bundle: BUNDLE_FORMAT,
            kind: BundleKind::Complete,
            fingerprint,
            files,
        }
    }

    /// An index for a disclosure: every line above `threshold` is withheld.
    #[must_use]
    pub fn disclosure(fingerprint: Sha256Digest, threshold: Level, files: Vec<BundleFile>) -> Self {
        Self {
            schema: Some(BUNDLE_SCHEMA.to_string()),
            rite_bundle: BUNDLE_FORMAT,
            kind: BundleKind::Disclosure { threshold },
            fingerprint,
            files,
        }
    }
}

/// What a bundle holds relative to the run.
#[non_exhaustive]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BundleKind {
    /// The complete transcript, with every fact.
    #[cfg_attr(
        test,
        schemars(
            description = "The complete record: the transcript with every fact, the ceremony \
            definition if it was included, and the artifacts the run kept."
        )
    )]
    Complete,
    /// A transcript with lines withheld, derived from a complete one.
    #[cfg_attr(
        test,
        schemars(
            description = "A disclosure derived from a complete bundle: every line above the \
            threshold is withheld, and only the artifacts whose facts are disclosed are included. \
            The ceremony definition is never included."
        )
    )]
    Disclosure {
        /// Every line at or below the threshold is disclosed, every line
        /// above it withheld.
        #[cfg_attr(
            test,
            schemars(
                description = "The widest level disclosed: every line at or below it is \
                disclosed, every line above it withheld."
            )
        )]
        threshold: Level,
    },
}

/// Where an artifact recorded under `file` is stored, relative to the bundle
/// or run directory: `artifacts/<file>`.
///
/// The name comes from a transcript, which is untrusted input: a name that is
/// not a single safe path component yields `None`, so a crafted transcript
/// cannot point a reader at files outside the artifacts directory.
#[must_use]
pub fn artifact_path(file: &str) -> Option<String> {
    crate::is_safe_component(file).then(|| format!("{ARTIFACTS_DIR}/{file}"))
}

/// One file in a bundle.
#[non_exhaustive]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, schemars(description = "One file in the bundle."))]
pub struct BundleFile {
    /// Path relative to the bundle root, `/`-separated.
    #[cfg_attr(
        test,
        schemars(
            description = "The file's path from the bundle root, with `/` between components."
        )
    )]
    pub path: String,
    /// What the file is, which also says what binds it.
    #[cfg_attr(test, schemars(description = "What the file is."))]
    pub role: FileRole,
    /// The artifact's name as declared in the ceremony, for an artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        test,
        schemars(description = "For an artifact, its name as declared in the ceremony.")
    )]
    pub name: Option<String>,
}

impl BundleFile {
    /// The transcript.
    #[must_use]
    pub fn transcript() -> Self {
        Self {
            path: TRANSCRIPT_FILE.to_string(),
            role: FileRole::Transcript,
            name: None,
        }
    }

    /// The ceremony definition.
    #[must_use]
    pub fn definition() -> Self {
        Self {
            path: DEFINITION_FILE.to_string(),
            role: FileRole::Definition,
            name: None,
        }
    }

    /// An artifact, stored at its [`artifact_path`].
    #[must_use]
    pub fn artifact(name: &str, path: &str) -> Self {
        Self {
            path: path.to_string(),
            role: FileRole::Artifact,
            name: Some(name.to_string()),
        }
    }
}

/// What a bundle file is.
#[non_exhaustive]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(
    test,
    schemars(description = "What a file is, which also says what binds it to the transcript.")
)]
pub enum FileRole {
    /// The transcript: the record the fingerprint identifies.
    #[cfg_attr(
        test,
        schemars(description = "The transcript, which the fingerprint identifies.")
    )]
    Transcript,
    /// The ceremony YAML, bound by the template digest on `CeremonyStarted`.
    #[cfg_attr(
        test,
        schemars(
            description = "The ceremony definition, bound by the template digest on \
            ceremony_started."
        )
    )]
    Definition,
    /// An artifact, bound by the digest on its `ArtifactWritten`.
    #[cfg_attr(
        test,
        schemars(description = "An artifact, bound by the digest on its artifact_written fact.")
    )]
    Artifact,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn index_wire_shape() {
        let index = BundleIndex::complete(
            Sha256Digest::of(b"t"),
            vec![
                BundleFile::transcript(),
                BundleFile::definition(),
                BundleFile::artifact("root_cert", "artifacts/root_cert.pem"),
            ],
        );
        assert_eq!(
            serde_json::to_value(&index).expect("serialize"),
            json!({
                "$schema": BUNDLE_SCHEMA,
                "rite_bundle": 0,
                "kind": "complete",
                "fingerprint": Sha256Digest::of(b"t").as_str(),
                "files": [
                    { "path": "transcript.jsonl", "role": "transcript" },
                    { "path": "definition/ceremony.rite.yaml", "role": "definition" },
                    { "path": "artifacts/root_cert.pem", "role": "artifact", "name": "root_cert" },
                ],
            })
        );
    }

    #[test]
    fn a_disclosure_writes_its_threshold_beside_its_kind() {
        let index = BundleIndex::disclosure(Sha256Digest::of(b"t"), Level::PUBLIC, vec![]);
        let value = serde_json::to_value(&index).expect("serialize");
        assert_eq!(value.get("kind"), Some(&json!("disclosure")));
        assert_eq!(value.get("threshold"), Some(&json!(10)));
        let back: BundleIndex = serde_json::from_value(value).expect("deserialize");
        assert_eq!(back, index);
    }

    #[test]
    fn a_disclosure_without_a_threshold_does_not_parse() {
        let value = json!({
            "rite_bundle": 0,
            "kind": "disclosure",
            "fingerprint": Sha256Digest::of(b"t").as_str(),
            "files": [],
        });
        assert!(serde_json::from_value::<BundleIndex>(value).is_err());
    }

    #[test]
    fn artifact_paths_stay_in_the_artifacts_directory() {
        assert_eq!(
            artifact_path("cert.pem").as_deref(),
            Some("artifacts/cert.pem")
        );
        assert_eq!(artifact_path("../cert.pem"), None);
        assert_eq!(artifact_path("a/b"), None);
    }
}
