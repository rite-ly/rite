//! A family: the steps that write one kind of artifact and the steps that
//! read it, with their own table, fixtures and coverage checks.
//!
//! What a family shares with the others is the keys, the outcome vocabulary
//! in `outcome.rs` and the harness. What it states is its own: a wrapped key
//! and a signature have nothing in common to put in one row type. Adding a
//! family is a module that exports a [`Family`], and one line in `main.rs`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use libtest_mimic::Trial;

use crate::cli::Cli;
use crate::keys::fixtures_dir;

pub struct Family {
    /// The directory under `fixtures/` holding what other implementations
    /// wrote for this family's read steps.
    pub fixtures: &'static str,
    /// Every test the family's rows make, its coverage checks included.
    pub trials: fn() -> Vec<Trial>,
    /// The file names the family's table expects in its directory, which
    /// the shared coverage check compares with the directory.
    pub fixture_files: fn() -> BTreeSet<String>,
    /// Write the fixtures of the family's table that do not exist yet, with
    /// the keys in place, naming each in the list as it is written, up to
    /// the first that fails.
    pub regenerate: fn(&Cli, &mut Vec<String>) -> Result<(), String>,
}

impl Family {
    pub fn dir(&self) -> PathBuf {
        fixtures_dir().join(self.fixtures)
    }
}

/// The name of a fixture file, as [`Family::fixture_files`] lists it.
pub fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .expect("a fixture path ends in a file name")
        .to_string()
}
