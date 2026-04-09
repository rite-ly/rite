//! Material source types for the ceremony IR.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Source for a ceremony material.
///
/// A material is either a digital file (loaded at runtime) or a physical item
/// identified by a human-readable string (serial number, label, batch code).
///
/// `MaterialSource` appears in the IR's [`super::MaterialKind`] after the resolver
/// has merged ceremony defaults with `--material` CLI overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MaterialSource {
    /// Load material content from a file.
    File {
        /// Path to the file containing the material.
        file: PathBuf,
    },
    /// Human-readable identifier for a physical item (e.g., serial number).
    Identifier {
        /// Display identifier for a physical material.
        identifier: String,
    },
}
