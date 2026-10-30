//! `--stdin`: a ceremony read from stdin, named by the file it belongs to.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use std::path::Path;

/// A ceremony whose one step shows a value, so `rite script` has worksheets
/// to write.
fn ceremony(name: &str, action: &str) -> String {
    format!(
        r#"version: "0.3"
name: "{name}"
roles:
  custodian: {{}}
sections:
  s:
    role: ${{role.custodian}}
    steps:
      type:
        action: enter_share
        with:
          message: "Share"
          length: 35
        creates: share
      show:
        action: {action}
        reads:
          value: ${{artifact.share}}
        with:
          message: "Share"
          length: 35
"#
    )
}

fn rite(dir: &Path, args: &[&str], stdin: &str) -> Command {
    let mut cmd = Command::cargo_bin("rite").unwrap();
    cmd.current_dir(dir).args(args).write_stdin(stdin);
    cmd
}

fn file_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// The script is rendered from stdin, not from the file on disk, and nothing
/// is written beside the file when the script goes to stdout.
#[test]
fn script_renders_the_ceremony_from_stdin() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("c.rite.yaml"),
        ceremony("On Disk", "reveal"),
    )
    .unwrap();

    let output = rite(
        dir.path(),
        &["script", "c.rite.yaml", "--stdin", "-o", "-"],
        &ceremony("In The Buffer", "reveal"),
    )
    .output()
    .unwrap();

    assert!(output.status.success(), "{output:?}");
    let html = String::from_utf8(output.stdout).unwrap();
    assert!(html.contains("In The Buffer"));
    assert!(!html.contains("On Disk"));
    assert_eq!(file_names(dir.path()), ["c.rite.yaml"]);
}

/// The worksheets of a ceremony from stdin are written where `--worksheets`
/// names.
#[test]
fn script_writes_stdin_worksheets_only_where_named() {
    let dir = tempfile::tempdir().unwrap();

    rite(
        dir.path(),
        &[
            "script",
            "c.rite.yaml",
            "--stdin",
            "-o",
            "-",
            "--worksheets",
            "sheets.html",
        ],
        &ceremony("In The Buffer", "reveal"),
    )
    .assert()
    .success();

    assert_eq!(file_names(dir.path()), ["sheets.html"]);
}

/// A mistake in the ceremony from stdin is reported against FILE, which
/// need not exist.
#[test]
fn check_reports_a_stdin_mistake_against_the_named_file() {
    let dir = tempfile::tempdir().unwrap();

    let output = rite(
        dir.path(),
        &["check", "unsaved.rite.yaml", "--stdin"],
        &ceremony("Test", "revael"),
    )
    .output()
    .unwrap();

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("unsaved.rite.yaml:16:"),
        "the error names the file and line: {stderr}"
    );

    rite(
        dir.path(),
        &["check", "unsaved.rite.yaml", "--stdin"],
        &ceremony("Test", "reveal"),
    )
    .assert()
    .success();
}
