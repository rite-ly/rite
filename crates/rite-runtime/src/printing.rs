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

/// Print the ceremony completion footer.
pub fn print_footer<W: Write>(
    writer: &mut W,
    ceremony: &Ceremony,
    completed: usize,
) -> Result<(), io::Error> {
    writeln!(writer)?;
    writeln!(writer, "──")?;
    writeln!(writer)?;
    let name = &ceremony.metadata.name;
    writeln!(writer, "✓ Ceremony '{name}' completed")?;
    writeln!(writer, "{completed} steps executed")?;
    writeln!(writer)?;
    Ok(())
}
