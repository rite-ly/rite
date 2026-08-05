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

/// Whether an example needs something this test binary was built without.
///
/// Two kinds of gap, both fixed at build time. Cargo features are visible
/// through `cfg!`, because feature unification builds the `rite` binary under
/// test with the same features as the test itself. Linked-library capabilities
/// are not, so those are read from the crate that owns the detection.
fn needs_unavailable_capability(path: &Path) -> bool {
    // examples/piv uses the hardware-backend actions (`piv_sign`,
    // `yubikey_attest_slot`), which are off in the default feature set.
    if !cfg!(feature = "yubikey") && path.starts_with(examples_dir().join("piv")) {
        return true;
    }

    // The post-quantum root CA needs ML-DSA, which OpenSSL only provides from
    // 3.5 onwards. Distributions still shipping 3.0 (Ubuntu 24.04, and so the
    // default CI runner) produce a binary with no ML-DSA support compiled in.
    // CI covers this example in the vendored-OpenSSL job instead.
    !rite_openssl::ML_DSA_AVAILABLE
        && path
            .file_name()
            .is_some_and(|n| n == "root_ca_post_quantum.rite.yaml")
}

fn ceremonies() -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect(&examples_dir(), &mut out);
    out.retain(|p| !needs_unavailable_capability(p));
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
