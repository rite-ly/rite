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
credentials:
  card_pin:
    backend: token
    grants: user
    source: entered
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
      unlock:
        action: authenticate
        backend: token
        reads:
          credential: ${{credential.card_pin}}
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

    // The PIN step binds the backend; the key is bound inside the step that
    // first reads it.
    let position =
        |pred: &dyn Fn(&serde_json::Value) -> bool| run.facts.iter().position(pred).unwrap();
    let unlock_started = position(&|f| f["type"] == "step_started" && f["id"] == "unlock");
    let backend_bound = position(&|f| f["type"] == "backend_bound" && f["name"] == "token");
    let pin_entered =
        position(&|f| f["type"] == "backend_operation" && f["kind"] == "authenticate");
    let sign_started = position(&|f| f["type"] == "step_started" && f["id"] == "sign");
    let key_bound = position(&|f| f["type"] == "key_bound" && f["name"] == "signing_key");
    assert!(unlock_started < backend_bound && backend_bound < pin_entered);
    assert!(pin_entered < sign_started && sign_started < key_bound);
    assert_eq!(
        run.facts
            .get(pin_entered)
            .and_then(|fact| fact.pointer("/inputs/retries_before")),
        Some(&serde_json::json!(3))
    );
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

/// An RSA-2048 key held in a retired key-management slot opens a container
/// sealed to it: the key transport form, through key decryption.
///
/// The step records the key's fingerprint, the one its `key_bound` fact
/// already made public, so naming it again discloses nothing new.
#[test]
fn a_held_rsa_key_opens_what_was_sealed_to_it() {
    let yaml = r#"version: "0.3"
name: "An RSA key a card already holds"
roles:
  operator:
    name: "Operator"
backends:
  token:
    provider: yubikey
  software:
    provider: openssl
credentials:
  card_pin:
    backend: token
    grants: user
    source: entered
materials:
  decryption_key:
    type: backend_key
    backend: token
    id: "piv:82"
    algorithm: RSA-2048
  manifest:
    type: bytes
    path: "manifest.txt"
sections:
  main:
    role: ${role.operator}
    steps:
      seal:
        action: encrypt_data
        backend: software
        reads:
          recipient: ${artifact.decryption_key}
          data: ${artifact.manifest}
        creates: sealed
      unlock:
        action: authenticate
        backend: token
        reads:
          credential: ${credential.card_pin}
      open:
        action: decrypt_data
        backend: token
        reads:
          encrypted_data: ${artifact.sealed}
          decryption_key: ${artifact.decryption_key}
        creates: opened
"#;
    let run = dry_run(yaml);
    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);

    let bound = of_type(&run.facts, "key_bound");
    let [bound] = bound.as_slice() else {
        panic!("{bound:#?}")
    };
    let opened = of_type(&run.facts, "backend_operation")
        .into_iter()
        .find(|fact| fact["kind"] == "decrypt_data")
        .expect("a decrypt_data operation");
    assert_eq!(
        opened.pointer("/inputs/decryption_key_fingerprint"),
        Some(&bound["fingerprint"]),
        "{opened:#?}"
    );
}
