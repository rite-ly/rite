//! `rite bundle`: evidence bundles, and the file operations its commands and
//! `rite verify` share.

pub mod create;
pub mod disclose;

use std::path::Path;

use clap::Subcommand;
use rite_model::Sha256Digest;
use rite_model::bundle::{
    ARTIFACTS_DIR, BUNDLE_FORMAT, BundleFile, BundleIndex, INDEX_FILE, artifact_path,
};

#[derive(Subcommand)]
pub enum Command {
    /// Package a run as an evidence bundle
    ///
    /// Copies the transcript, the ceremony definition it ran from, and the
    /// artifacts it records into a bundle directory with an index. Every file
    /// is checked against the transcript on the way in; opened content is
    /// never bundled.
    Create(create::Args),
    /// Derive a disclosure from an evidence bundle
    ///
    /// Withholds every fact recorded above a level, keeping its commitment,
    /// so the disclosed transcript verifies to the same fingerprint as the
    /// complete one. Carries only the artifacts whose facts it discloses, and
    /// never the ceremony definition.
    Disclose(disclose::Args),
}

pub fn run(command: &Command) {
    match command {
        Command::Create(args) => create::run(args),
        Command::Disclose(args) => disclose::run(args),
    }
}

/// Create `dir`, which must not exist, and run `build` in it, removing the
/// directory again if `build` fails.
pub(crate) fn with_new_dir<T>(
    dir: &Path,
    build: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    std::fs::create_dir(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let result = build();
    if result.is_err() {
        // The directory was created above, so it holds only what `build`
        // wrote into it.
        let _ = std::fs::remove_dir_all(dir);
    }
    result
}

pub(crate) fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// Write a file that must not exist yet, readable by its owner only: a bundle
/// can hold wrapped keys and other material that is not for everyone.
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    rite_runtime::write_new_file(path, bytes)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Read a bundle's index, refusing a format this version does not know.
pub(crate) fn read_index(dir: &Path) -> Result<BundleIndex, String> {
    let path = dir.join(INDEX_FILE);
    let index: BundleIndex =
        serde_json::from_slice(&read(&path)?).map_err(|e| format!("{}: {e}", path.display()))?;
    if index.rite_bundle != BUNDLE_FORMAT {
        return Err(format!(
            "unknown bundle format {} (this version reads {BUNDLE_FORMAT})",
            index.rite_bundle
        ));
    }
    Ok(index)
}

pub(crate) fn write_index(dir: &Path, index: &BundleIndex) -> Result<(), String> {
    let mut json = serde_json::to_string_pretty(index).map_err(|e| e.to_string())?;
    json.push('\n');
    write_new(&dir.join(INDEX_FILE), json.as_bytes())
}

/// Copy the artifact a transcript records as `name`, stored as `file` with
/// `digest`, from `source` to `out`, checking it against the digest on the
/// way. Returns `None` when `source` does not hold it.
pub(crate) fn copy_artifact(
    source: &Path,
    out: &Path,
    name: &str,
    file: &str,
    digest: &Sha256Digest,
) -> Result<Option<BundleFile>, String> {
    let path = artifact_path(file)
        .ok_or_else(|| format!("artifact {name} records an unsafe file name '{file}'"))?;
    let from = source.join(&path);
    if !from.is_file() {
        return Ok(None);
    }
    let bytes = read(&from)?;
    if Sha256Digest::of(&bytes) != *digest {
        return Err(format!(
            "artifact {name} does not match the digest the transcript records"
        ));
    }
    std::fs::create_dir_all(out.join(ARTIFACTS_DIR))
        .map_err(|e| format!("cannot create the artifacts directory: {e}"))?;
    write_new(&out.join(&path), &bytes)?;
    Ok(Some(BundleFile::artifact(name, &path)))
}
