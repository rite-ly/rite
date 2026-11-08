//! Exit-code contract for the `rite` CLI.
//!
//! `0` success, `1` a negative result or bad input, `2` a usage error or an
//! unexpected internal fault.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::{Command, Stdio};

fn rite(args: &[&str]) -> Option<i32> {
    Command::new(env!("CARGO_BIN_EXE_rite"))
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn rite")
        .code()
}

#[test]
fn check_on_missing_file_exits_1() {
    assert_eq!(rite(&["check", "does-not-exist.rite.yaml"]), Some(1));
}

#[test]
fn verify_on_missing_transcript_exits_1() {
    assert_eq!(rite(&["verify", "does-not-exist"]), Some(1));
}

#[test]
fn missing_required_argument_is_a_usage_error_exits_2() {
    // `check` requires a <FILE>; omitting it is a clap usage error.
    assert_eq!(rite(&["check"]), Some(2));
}

/// A ceremony whose one backend is a YubiKey, for a build without one.
#[cfg(not(feature = "yubikey"))]
const NEEDS_A_YUBIKEY: &str = r#"version: "0.3"
name: "Needs a YubiKey"
roles:
  officer:
    person: "Alice"
backends:
  yk:
    provider: yubikey
sections:
  main:
    role: ${role.officer}
    steps:
      gen:
        action: generate_key
        backend: yk
        with:
          algorithm: ECDSA-P256
        creates: key
"#;

/// Run `rite run <extra> --no-transcript` on [`NEEDS_A_YUBIKEY`]: the exit
/// code, stderr, and whether the output directory was created.
#[cfg(not(feature = "yubikey"))]
fn run_needing_a_yubikey(tag: &str, extra: &[&str]) -> (Option<i32>, String, bool) {
    let dir = std::env::temp_dir().join(format!("rite-unbuilt-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ceremony = dir.join("yubikey.rite.yaml");
    std::fs::write(&ceremony, NEEDS_A_YUBIKEY).unwrap();
    let out = dir.join("out");
    let output = Command::new(env!("CARGO_BIN_EXE_rite"))
        .arg("run")
        .args(extra)
        .args(["--no-transcript", "--output"])
        .arg(&out)
        .arg(&ceremony)
        .stdin(Stdio::null())
        .output()
        .expect("spawn rite");
    let created = out.exists();
    std::fs::remove_dir_all(&dir).ok();
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        created,
    )
}

/// A provider this build lacks is refused before the first step, rather
/// than when the step that uses the backend is reached.
#[cfg(not(feature = "yubikey"))]
#[test]
fn a_provider_this_build_lacks_is_refused_before_the_run() {
    let (code, stderr, created) = run_needing_a_yubikey("run", &["--no-prompt"]);
    assert_eq!(code, Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("Backend 'yk': provider 'yubikey' is not in this build"),
        "stderr: {stderr}"
    );
    assert!(!created, "nothing is created before the refusal");
}

/// A dry run swaps in the mock, so it rehearses the ceremony anyway, and
/// warns that the real run on this build would stop.
#[cfg(not(feature = "yubikey"))]
#[test]
fn a_dry_run_warns_about_a_provider_this_build_lacks() {
    let (code, stderr, _) = run_needing_a_yubikey("dry", &["--dry-run", "--no-prompt"]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("could not run this ceremony for real")
            && stderr.contains("Backend 'yk': provider 'yubikey' is not in this build"),
        "stderr: {stderr}"
    );
}
