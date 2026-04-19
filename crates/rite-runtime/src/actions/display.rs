//! Display utilities for action handlers.
//!
//! This module provides helper functions for consistent TUI output across actions.
//! All display output should go through these helpers to ensure:
//! - Consistent visual style
//! - Easy migration to a TUI library later
//! - Restricted output capabilities for actions

// These helpers are used by action handlers in downstream crates (rite-stdlib).
#![allow(dead_code)]

use crate::step_ui::{Icon, StepUI};
use std::io;

/// Prompt for yes/no confirmation.
///
/// Returns `Ok(true)` if user confirms, `Ok(false)` if user declines.
pub fn prompt_yes_no(ui: &mut dyn StepUI, prompt: &str) -> io::Result<bool> {
    ui.prompt_confirm(prompt)
}

/// Prompt for specific text input (e.g., "attest").
///
/// Retries until input matches expected (case-insensitive). Always returns `Ok(true)`.
pub fn prompt_exact(ui: &mut dyn StepUI, prompt: &str, expected: &str) -> io::Result<bool> {
    ui.prompt_literal(prompt, expected)
}

/// Read a line of input with a prompt.
///
/// Returns the trimmed input string.
pub fn prompt_input(ui: &mut dyn StepUI, prompt: &str) -> io::Result<String> {
    ui.prompt_text(prompt)
}

/// Read sensitive input with echo suppression.
///
/// The value is not recorded in transcript evidence.
pub fn prompt_secret(ui: &mut dyn StepUI, prompt: &str) -> io::Result<String> {
    ui.prompt_secret(prompt)
}

/// Write a dry-run notice.
///
/// # Example output
/// ```text
/// [DRY RUN - auto-confirming]
/// ```
#[allow(clippy::unnecessary_wraps)]
pub fn write_dry_run(ui: &mut dyn StepUI, action: &str) -> io::Result<()> {
    ui.log(Icon::Info, &format!("[DRY RUN - {action}]"));
    Ok(())
}

/// Write a line of text.
#[allow(clippy::unnecessary_wraps)]
pub fn write_line(ui: &mut dyn StepUI, text: &str) -> io::Result<()> {
    ui.log(Icon::Info, text);
    Ok(())
}

/// Write an empty line (no-op for `StepUI` - formatting handled by renderer).
#[allow(clippy::unnecessary_wraps)]
pub fn write_blank(_ui: &mut dyn StepUI) -> io::Result<()> {
    // StepUI doesn't need explicit blank lines - the TUI handles spacing
    Ok(())
}

/// Write a success indicator.
///
/// # Example output
/// ```text
/// ✓ Operation completed successfully
/// ```
#[allow(clippy::unnecessary_wraps)]
pub fn write_success(ui: &mut dyn StepUI, message: &str) -> io::Result<()> {
    ui.log(Icon::Checkmark, message);
    Ok(())
}

/// Write a PASS indicator for machine-verified checks.
///
/// # Example output
/// ```text
/// ✓ Binary integrity check
/// ```
#[allow(clippy::unnecessary_wraps)]
pub fn write_pass(ui: &mut dyn StepUI, message: &str) -> io::Result<()> {
    ui.log(Icon::Checkmark, message);
    Ok(())
}

/// Write a FAIL indicator for machine-verified checks.
///
/// # Example output
/// ```text
/// ✗ FAIL: Binary integrity check
/// ```
#[allow(clippy::unnecessary_wraps)]
pub fn write_fail(ui: &mut dyn StepUI, message: &str) -> io::Result<()> {
    ui.log(Icon::Cross, &format!("FAIL: {message}"));
    Ok(())
}

/// Write an in-progress indicator (for operations that will be updated).
#[allow(clippy::unnecessary_wraps)]
pub fn write_progress(ui: &mut dyn StepUI, message: &str) -> io::Result<()> {
    ui.log(Icon::Spinner, message);
    Ok(())
}

/// Update the last log line (for progress updates).
#[allow(clippy::unnecessary_wraps)]
pub fn update_progress(ui: &mut dyn StepUI, icon: Icon, message: &str) -> io::Result<()> {
    ui.update_last_log(icon, message);
    Ok(())
}
