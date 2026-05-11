//! Ceremony output formatting utilities.
//!
//! This module provides formatting functions for ceremony execution output,
//! including headers, footers, and step progress display.

use rite_model::Ceremony;
use std::io::{self, Write};

/// Print the ceremony execution header.
pub fn print_header<W: Write>(
    writer: &mut W,
    ceremony: &Ceremony,
    dry_run: bool,
) -> Result<(), io::Error> {
    writeln!(writer)?;
    let name = &ceremony.metadata.name;
    writeln!(writer, "{name}")?;
    if let Some(desc) = &ceremony.metadata.description {
        writeln!(writer, "{desc}")?;
    }
    let step_count = ceremony.execution_plan.len();
    let mut info_parts = vec![format!("{step_count} steps")];
    if dry_run {
        info_parts.push("dry run".to_string());
    }
    let info = info_parts.join(" · ");
    writeln!(writer, "{info}")?;
    writeln!(writer)?;
    Ok(())
}

fn space_hex_pairs(hex: &str) -> String {
    hex.as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap_or("??"))
        .collect::<Vec<_>>()
        .join(" ")
}

// TODO: this prefix length could become a config option later.
const FINGERPRINT_PREFIX_BYTES: usize = 16;
const FINGERPRINT_PREFIX_HEX: usize = FINGERPRINT_PREFIX_BYTES * 2;
pub(crate) const ANSI_BOLD: &str = "\x1b[1m";
pub(crate) const ANSI_RESET: &str = "\x1b[0m";

/// Print the transcript fingerprint prominently and prompt the operator to record it.
///
/// Displays the first 16 bytes (32 hex characters) in bold. The full hash is shown for
/// reference. Does not read from stdin; the caller is responsible for blocking until confirmed.
pub fn print_transcript_fingerprint<W: Write>(
    writer: &mut W,
    fingerprint: &str,
) -> Result<(), io::Error> {
    writeln!(writer, "Transcript fingerprint")?;

    let display = fingerprint
        .strip_prefix("sha256:")
        .filter(|hex| hex.len() >= FINGERPRINT_PREFIX_HEX)
        .map_or_else(
            || fingerprint.to_owned(),
            |hex| {
                let (prefix, rest) = hex.split_at(FINGERPRINT_PREFIX_HEX);
                format!(
                    "sha256:{ANSI_BOLD}{}{ANSI_RESET}  {}",
                    space_hex_pairs(prefix),
                    space_hex_pairs(rest)
                )
            },
        );

    writeln!(writer, "{display}")?;
    writeln!(writer, "Record this fingerprint on paper")?;

    writeln!(writer)?;
    writeln!(writer, "Press Enter after recording the fingerprint...")?;
    writeln!(writer)?;
    Ok(())
}
