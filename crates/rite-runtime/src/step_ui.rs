//! Step UI abstraction for ceremony execution.
//!
//! This module provides the [`StepUI`] trait that abstracts the presentation layer
//! from action execution. Actions interact with the user through this trait,
//! allowing different implementations (TUI, headless, testing).
//!
//! The display model is intentionally constrained - actions can only:
//! - Log messages with icons
//! - Request specific prompt types
//!
//! This constraint ensures consistent UI presentation and makes the
//! interaction model explicit and auditable.

use std::io;

/// Icon type for log entries.
///
/// Icons provide visual cues about the nature of each log entry.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icon {
    /// Operation in progress (animated in TUI)
    Spinner,
    /// Success / completion
    Checkmark,
    /// Failure / error
    Cross,
    /// Informational message
    Info,
    /// Warning (non-fatal)
    Warning,
}

impl std::fmt::Display for Icon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Icon::Spinner => "⠋",
            Icon::Checkmark => "✓",
            Icon::Cross => "✗",
            Icon::Info => "ℹ",
            Icon::Warning => "⚠",
        };
        write!(f, "{s}")
    }
}

/// Presentation abstraction for step execution.
///
/// Actions call these methods to interact with the user. The trait implementation
/// decides how to render the UI (TUI, text, headless for testing).
///
/// # Design Principles
///
/// - **Constrained**: Actions can't render arbitrary content
/// - **Semantic**: Methods describe intent, not presentation
/// - **Blocking**: Prompt methods block until user responds
///
/// # Example
///
/// ```ignore
/// fn execute(&self, ui: &mut dyn StepUI, ...) -> Result<...> {
///     ui.log(Icon::Spinner, "Generating keypair...");
///     let keypair = generate()?;
///     ui.log(Icon::Checkmark, &format!("Generated: {}", keypair.id));
///
///     if ui.prompt_confirm("Proceed with wrapping?")? {
///         // ...
///     }
///     Ok(...)
/// }
/// ```
pub trait StepUI: Send {
    /// Add an entry to the step's log area.
    ///
    /// Log entries are displayed in order and persist for the step's duration.
    /// The TUI may animate spinner icons.
    fn log(&mut self, icon: Icon, text: &str);

    /// Prompt user to press Enter to continue.
    ///
    /// Used for pacing - ensures user has read the content before proceeding.
    /// Returns `Ok(())` when user presses Enter.
    fn prompt_continue(&mut self, message: &str) -> io::Result<()>;

    /// Prompt for yes/no confirmation.
    ///
    /// Returns `true` for yes, `false` for no.
    /// The TUI typically shows a `[y/n]` prompt.
    fn prompt_confirm(&mut self, message: &str) -> io::Result<bool>;

    /// Prompt user to type exact text to proceed.
    ///
    /// Used for high-stakes confirmations (attestations, destructive operations).
    /// Returns `true` if user typed the expected text exactly.
    fn prompt_literal(&mut self, message: &str, expected: &str) -> io::Result<bool>;

    /// Prompt for free-form text input.
    ///
    /// Returns the entered text (trimmed).
    fn prompt_text(&mut self, prompt: &str) -> io::Result<String>;

    /// Prompt for sensitive input (PIN, password) without terminal echo.
    ///
    /// Like `prompt_text`, but the implementation must suppress character echo.
    /// The TUI renders masked characters (e.g., `●●●●●●`).
    fn prompt_secret(&mut self, prompt: &str) -> io::Result<String>;

    /// Update a previous spinner entry to show completion.
    ///
    /// This is optional - implementations may ignore it.
    /// Used to update "Generating..." to "✓ Generated" after async work.
    fn update_last_log(&mut self, _icon: Icon, _text: &str) {
        // Default: no-op (implementations can override)
    }
}

/// Minimal `StepUI` implementation for dry-run and headless execution.
///
/// Auto-confirms all prompts and logs to stderr. Used when:
/// - Running with `--dry-run` flag
/// - TUI feature is not enabled
/// - Running in CI/testing environments
pub struct MinimalStepUI {
    /// Whether to print log entries to stderr
    verbose: bool,
}

impl MinimalStepUI {
    /// Create a new minimal UI.
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }

    /// Create a silent UI (no output).
    pub fn silent() -> Self {
        Self { verbose: false }
    }
}

impl Default for MinimalStepUI {
    fn default() -> Self {
        Self::new(true)
    }
}

impl StepUI for MinimalStepUI {
    fn log(&mut self, icon: Icon, text: &str) {
        if self.verbose {
            eprintln!("[{icon}] {text}");
        }
    }

    fn prompt_continue(&mut self, _message: &str) -> io::Result<()> {
        // Auto-continue in dry-run
        Ok(())
    }

    fn prompt_confirm(&mut self, _message: &str) -> io::Result<bool> {
        // Auto-confirm in dry-run
        Ok(true)
    }

    fn prompt_literal(&mut self, _message: &str, _expected: &str) -> io::Result<bool> {
        // Auto-accept in dry-run
        Ok(true)
    }

    fn prompt_text(&mut self, _prompt: &str) -> io::Result<String> {
        // Return placeholder in dry-run
        Ok("[dry-run]".to_string())
    }

    fn prompt_secret(&mut self, _prompt: &str) -> io::Result<String> {
        // Return distinct placeholder in dry-run
        Ok("[secret-dry-run]".to_string())
    }
}

/// Console `StepUI` implementation for interactive terminal use.
///
/// Provides traditional stdin/stdout interaction without TUI rendering.
/// Used when the TUI is not available or not desired.
pub struct ConsoleStepUI<'a, R, W> {
    reader: &'a mut R,
    writer: &'a mut W,
}

impl<'a, R: io::BufRead, W: io::Write> ConsoleStepUI<'a, R, W> {
    /// Create a new console UI with custom reader/writer.
    pub fn new(reader: &'a mut R, writer: &'a mut W) -> Self {
        Self { reader, writer }
    }
}

impl<R: io::BufRead + Send, W: io::Write + Send> StepUI for ConsoleStepUI<'_, R, W> {
    fn log(&mut self, icon: Icon, text: &str) {
        let _ = writeln!(self.writer, "{icon} {text}");
        let _ = self.writer.flush();
    }

    fn prompt_continue(&mut self, message: &str) -> io::Result<()> {
        write!(self.writer, "{message} [press Enter] ")?;
        self.writer.flush()?;
        let mut line = String::new();
        self.reader.read_line(&mut line)?;
        Ok(())
    }

    fn prompt_confirm(&mut self, message: &str) -> io::Result<bool> {
        loop {
            write!(self.writer, "{message} [y/n]: ")?;
            self.writer.flush()?;
            let mut input = String::new();
            let bytes_read = self.reader.read_line(&mut input)?;

            // Detect EOF (stdin closed)
            if bytes_read == 0 && input.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "stdin closed (no input available)",
                ));
            }

            let trimmed = input.trim();
            if trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes") {
                return Ok(true);
            } else if trimmed.eq_ignore_ascii_case("n") || trimmed.eq_ignore_ascii_case("no") {
                return Ok(false);
            }
            let _ = writeln!(self.writer, "Invalid input. Please enter 'y' or 'n'.");
        }
    }

    fn prompt_literal(&mut self, message: &str, expected: &str) -> io::Result<bool> {
        loop {
            write!(self.writer, "{message}: ")?;
            self.writer.flush()?;
            let mut input = String::new();
            let bytes_read = self.reader.read_line(&mut input)?;

            // Detect EOF
            if bytes_read == 0 && input.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "stdin closed (no input available)",
                ));
            }

            if input.trim().eq_ignore_ascii_case(expected) {
                return Ok(true);
            }
            let _ = writeln!(
                self.writer,
                "Invalid input. Please type '{expected}' exactly."
            );
        }
    }

    fn prompt_text(&mut self, prompt: &str) -> io::Result<String> {
        write!(self.writer, "{prompt}: ")?;
        self.writer.flush()?;
        let mut input = String::new();
        let bytes_read = self.reader.read_line(&mut input)?;

        // Detect EOF
        if bytes_read == 0 && input.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "stdin closed (no input available)",
            ));
        }

        Ok(input.trim().to_string())
    }

    fn prompt_secret(&mut self, prompt: &str) -> io::Result<String> {
        write!(self.writer, "{prompt}: ")?;
        self.writer.flush()?;
        // rpassword reads from /dev/tty directly, bypassing self.reader.
        // This is correct for echo suppression but means secret input
        // cannot be unit-tested with mock I/O.
        rpassword::read_password()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icon_display() {
        assert_eq!(format!("{}", Icon::Checkmark), "✓");
        assert_eq!(format!("{}", Icon::Cross), "✗");
        assert_eq!(format!("{}", Icon::Spinner), "⠋");
    }

    #[test]
    fn test_minimal_ui_auto_confirms() {
        let mut ui = MinimalStepUI::silent();

        assert!(ui.prompt_confirm("test?").unwrap());
        assert!(ui.prompt_literal("type CONFIRM", "CONFIRM").unwrap());
        assert_eq!(ui.prompt_text("name?").unwrap(), "[dry-run]");
        assert_eq!(ui.prompt_secret("PIN?").unwrap(), "[secret-dry-run]");
        assert!(ui.prompt_continue("press enter").is_ok());
    }

    #[test]
    fn test_minimal_ui_prompt_secret() {
        let mut ui = MinimalStepUI::silent();
        let result = ui.prompt_secret("Enter PIN").unwrap();
        assert_eq!(result, "[secret-dry-run]");
    }

    #[test]
    fn test_console_ui_confirm_yes() {
        let mut input = io::Cursor::new(b"y\n");
        let mut output = Vec::new();

        let mut ui = ConsoleStepUI::new(&mut input, &mut output);
        assert!(ui.prompt_confirm("Proceed?").unwrap());

        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("Proceed?"));
    }

    #[test]
    fn test_console_ui_confirm_no() {
        let mut input = io::Cursor::new(b"n\n");
        let mut output = Vec::new();

        let mut ui = ConsoleStepUI::new(&mut input, &mut output);
        assert!(!ui.prompt_confirm("Proceed?").unwrap());
    }

    #[test]
    fn test_console_ui_prompt_text() {
        let mut input = io::Cursor::new(b"hello world\n");
        let mut output = Vec::new();

        let mut ui = ConsoleStepUI::new(&mut input, &mut output);
        assert_eq!(ui.prompt_text("Enter value").unwrap(), "hello world");
    }
}
