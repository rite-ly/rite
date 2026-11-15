//! Keys a backend already holds, declared as `backend_key` materials, through
//! a dry run: the mock stands in for each declared key, the first step that
//! reads one binds it, and the transcript records the binding.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// A ceremony on a card holding a P-256 signing key in 9C and a P-384
/// decryption key in 9D. `pin` is the decryption key's `fingerprint:` line,
/// or empty.
fn ceremony(pin: &str) -> String {
    format!(
        r#"version: "0.3"
name: "Keys a card already holds"
roles:
  operator:
    name: "Operator"
backends:
  token:
    provider: yubikey
  software:
    provider: openssl
materials:
  signing_key:
    type: backend_key
    backend: token
    id: "piv:9c"
    algorithm: ECDSA-P256
  decryption_key:
    type: backend_key
    backend: token
    id: "piv:9d"
    algorithm: ECDSA-P384
{pin}
  manifest:
    type: bytes
    path: "manifest.txt"
sections:
  main:
    role: ${{role.operator}}
    steps:
      sign:
        action: sign_data
        backend: token
        reads:
          key: ${{artifact.signing_key}}
          data: ${{artifact.manifest}}
        creates: signature
      check:
        action: verify_signature
        backend: software
        reads:
          key: ${{artifact.signing_key}}
          data: ${{artifact.manifest}}
          signature: ${{artifact.signature}}
      seal:
        action: encrypt_data
        backend: software
        reads:
          recipient: ${{artifact.decryption_key}}
          data: ${{artifact.manifest}}
        creates: sealed
      open:
        action: decrypt_data
        backend: token
        reads:
          encrypted_data: ${{artifact.sealed}}
          decryption_key: ${{artifact.decryption_key}}
        creates: opened
"#
    )
}

/// What a dry run of `yaml` left: its exit code, stderr, and the facts of its
/// transcript.
struct Run {
    code: Option<i32>,
    stderr: String,
    facts: Vec<serde_json::Value>,
}

/// The facts are read back through the verifying reader, so the transcript's
/// chain is checked too.
fn dry_run(yaml: &str) -> Run {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    std::fs::write(dir.join("manifest.txt"), b"release 1.0\n").unwrap();
    let file = dir.join("held.rite.yaml");
    std::fs::write(&file, yaml).unwrap();
    let out = dir.join("out");
    let output = Command::new(env!("CARGO_BIN_EXE_rite"))
        .args(["run", "--dry-run", "--no-prompt", "--output"])
        .arg(&out)
        .arg(&file)
        .stdin(Stdio::null())
        .output()
        .expect("spawn rite");
    let facts = transcript(&out)
        .map(|path| {
            rite_runtime::read_verified_transcript(&path)
                .unwrap()
                .facts
                .into_iter()
                .map(|timed| serde_json::to_value(timed.fact).unwrap())
                .collect()
        })
        .unwrap_or_default();
    Run {
        code: output.status.code(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        facts,
    }
}

/// The transcript a run wrote somewhere under `dir`.
fn transcript(dir: &Path) -> Option<PathBuf> {
    for entry in std::fs::read_dir(dir).ok()? {
        let path = entry.ok()?.path();
        if path.is_dir() {
            if let Some(found) = transcript(&path) {
                return Some(found);
            }
        } else if path.file_name().is_some_and(|n| n == "transcript.jsonl") {
            return Some(path);
        }
    }
    None
}

fn of_type<'a>(facts: &'a [serde_json::Value], kind: &str) -> Vec<&'a serde_json::Value> {
    facts.iter().filter(|fact| fact["type"] == kind).collect()
}

#[test]
fn each_held_key_binds_at_the_first_step_that_reads_it() {
    let run = dry_run(&ceremony(""));
    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);

    let bound = of_type(&run.facts, "key_bound");
    assert_eq!(bound.len(), 2, "{bound:#?}");
    let signing = bound
        .iter()
        .find(|fact| fact["name"] == "signing_key")
        .unwrap();
    assert_eq!(signing["backend"], "token");
    assert_eq!(signing["key_id"], "piv:9c");
    assert_eq!(signing["algorithm"], "ECDSA-P256");
    assert_eq!(signing["pinned"], false);
    let decryption = bound
        .iter()
        .find(|fact| fact["name"] == "decryption_key")
        .unwrap();
    assert_eq!(decryption["algorithm"], "ECDSA-P384");

    // Bound inside the step that first reads it, after the backend.
    let position =
        |pred: &dyn Fn(&serde_json::Value) -> bool| run.facts.iter().position(pred).unwrap();
    let sign_started = position(&|f| f["type"] == "step_started" && f["id"] == "sign");
    let backend_bound = position(&|f| f["type"] == "backend_bound" && f["name"] == "token");
    let key_bound = position(&|f| f["type"] == "key_bound" && f["name"] == "signing_key");
    assert!(sign_started < backend_bound && backend_bound < key_bound);
    // 9D is first read by `seal`, which seals to its public half on the
    // software backend; the binding still asks the token.
    let seal_started = position(&|f| f["type"] == "step_started" && f["id"] == "seal");
    let decryption_bound = position(&|f| f["type"] == "key_bound" && f["name"] == "decryption_key");
    assert!(seal_started < decryption_bound);

    // A held key is not a file: no digest, no material_loaded.
    assert!(
        of_type(&run.facts, "material_loaded")
            .iter()
            .all(|fact| fact["name"] == "manifest"),
        "{:#?}",
        run.facts
    );
}

#[test]
fn a_key_that_is_not_the_pinned_one_fails_the_step() {
    let pinned = format!("    fingerprint: \"sha256:{}\"", "00".repeat(32));
    let run = dry_run(&ceremony(&pinned));
    assert_ne!(run.code, Some(0), "stderr: {}", run.stderr);
    assert!(
        run.stderr.contains("not the pinned sha256:0000"),
        "stderr: {}",
        run.stderr
    );
    assert!(
        !of_type(&run.facts, "key_bound")
            .iter()
            .any(|fact| fact["name"] == "decryption_key"),
        "a key that is not the declared one is never recorded as bound"
    );
    let failed = of_type(&run.facts, "step_attempt_failed");
    assert!(
        failed.iter().any(|fact| fact["step"] == "seal"),
        "{failed:#?}"
    );
}
