//! Smoke tests over the shipped example ceremonies.
//!
//! Every `*.rite.yaml` under `examples/` must pass `rite check` (valid syntax
//! and resolution) and complete a `rite run --dry-run` through the mock backend
//! (real software crypto, no hardware). This keeps the examples runnable, and
//! self-documenting, as the DSL and runtime evolve. New examples are covered
//! automatically: the tests discover files, they are not enumerated.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use std::path::{Path, PathBuf};

fn examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples")
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("examples dir is readable") {
        let path = entry.expect("readable dir entry").path();
        if path.is_dir() {
            collect(&path, out);
        } else if path
            .file_name()
            .is_some_and(|n| n.to_string_lossy().ends_with(".rite.yaml"))
        {
            out.push(path);
        }
    }
}

fn ceremonies() -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect(&examples_dir(), &mut out);
    out.sort();
    assert!(
        !out.is_empty(),
        "no example ceremonies found under {}",
        examples_dir().display()
    );
    out
}

#[test]
fn examples_pass_check() {
    for file in ceremonies() {
        Command::cargo_bin("rite")
            .expect("rite binary builds")
            .arg("check")
            .arg(&file)
            .assert()
            .success();
    }
}

#[test]
fn examples_complete_dry_run() {
    // One output root for all runs; each ceremony writes its own timestamped
    // subdirectory under it. The TempDir cleans everything up on drop.
    let out_root = tempfile::tempdir().expect("create output tempdir");
    for file in ceremonies() {
        Command::cargo_bin("rite")
            .expect("rite binary builds")
            // --dry-run already forces the headless driver; --no-prompt keeps
            // the run non-interactive regardless of how the test is launched.
            .args(["run", "--dry-run", "--no-prompt"])
            .arg("-o")
            .arg(out_root.path())
            .arg(&file)
            .assert()
            .success();
    }
}
