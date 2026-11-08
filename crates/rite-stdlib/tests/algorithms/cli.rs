//! The `openssl` command line, as a reader independent of Rite.
//!
//! A write Rite then reads back proves the two halves agree with each other.
//! Only another implementation opening it proves the bytes are the standard
//! structure. The command line is found once, from `RITE_OPENSSL_CLI` or the
//! `PATH`, and a case that needs a newer one than is installed is skipped by
//! name rather than passed.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// An `openssl` binary and its version.
#[derive(Debug)]
pub struct Cli {
    path: PathBuf,
    major: u32,
    minor: u32,
}

impl Cli {
    /// The command line, if one is installed. `LibreSSL`, which macOS ships as
    /// `/usr/bin/openssl`, writes and reads CMS differently and is not used.
    pub fn get() -> Option<&'static Cli> {
        static CLI: OnceLock<Option<Cli>> = OnceLock::new();
        CLI.get_or_init(|| {
            let path = std::env::var_os("RITE_OPENSSL_CLI")
                .map_or_else(|| PathBuf::from("openssl"), PathBuf::from);
            let output = Command::new(&path).arg("version").output().ok()?;
            let version = String::from_utf8(output.stdout).ok()?;
            let number = version
                .strip_prefix("OpenSSL ")?
                .split_whitespace()
                .next()?;
            let mut parts = number.split('.').map(str::parse::<u32>);
            let major = parts.next()?.ok()?;
            let minor = parts.next()?.ok()?;
            Some(Cli { path, major, minor })
        })
        .as_ref()
    }

    pub fn at_least(&self, major: u32, minor: u32) -> bool {
        (self.major, self.minor) >= (major, minor)
    }

    pub fn version(&self) -> String {
        format!("{}.{}", self.major, self.minor)
    }

    /// Run `openssl` with `args`, returning stdout, or the command and its
    /// stderr when it fails.
    pub fn run(&self, args: &[&str]) -> Result<Vec<u8>, String> {
        let output = Command::new(&self.path)
            .args(args)
            .output()
            .map_err(|e| format!("cannot run {}: {e}", self.path.display()))?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(format!(
                "openssl {} failed:\n{}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }
}

/// A path as an argument.
pub fn arg(path: &Path) -> &str {
    path.to_str().expect("test paths are UTF-8")
}
