//! Visual span assertion helpers shared by test modules.
//!
//! `span_text` extracts the exact characters a span covers; `annotate` renders
//! a two-line caret diagram. Use them so assertions read like
//! `assert_eq!(span_text(yaml, span), "${role.ghost}")` rather than asserting
//! line/column/length numbers.

use crate::diagnostic::Span;

#[allow(clippy::arithmetic_side_effects)]
pub(crate) fn span_text(yaml: &str, span: Span) -> &str {
    let line = yaml.lines().nth(span.line.saturating_sub(1)).unwrap_or("");
    let start = span.column.saturating_sub(1);
    let end = start + span.length.unwrap_or(0);
    line.get(start..end).unwrap_or("")
}

pub(crate) fn annotate(yaml: &str, span: Span) -> String {
    let line = yaml.lines().nth(span.line.saturating_sub(1)).unwrap_or("");
    let col0 = span.column.saturating_sub(1);
    let carets = span.length.unwrap_or(0).max(1);
    format!("{}\n{}{}", line, " ".repeat(col0), "^".repeat(carets))
}
