//! Exit-code contract for the `rite` CLI.
//!
//! `0` success, `1` a negative result or bad input, `2` a usage error or an
//! unexpected internal fault.

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
