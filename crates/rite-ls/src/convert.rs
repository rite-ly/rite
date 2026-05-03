//! Convert rite-resolver types to LSP types.

use rite_resolver::{Diagnostic, Severity, Span};
use tower_lsp_server::ls_types::{
    Diagnostic as LspDiagnostic, DiagnosticSeverity, Position, Range,
};

/// Convert a rite-resolver span (1-indexed) to an LSP position (0-indexed).
pub fn span_to_position(span: Span) -> Position {
    Position {
        line: span.line.saturating_sub(1) as u32,
        character: span.column.saturating_sub(1) as u32,
    }
}

/// Construct a zero-width LSP range (start == end) at the given position.
///
/// Used for declaration sites where token length is not tracked. Editors extend
/// point ranges to word boundaries for highlighting.
pub fn point_range(pos: Position) -> Range {
    Range {
        start: pos,
        end: pos,
    }
}

/// Convert a rite-resolver span to an LSP range.
///
/// When `span.length` is set the range covers the exact token; otherwise falls
/// back to a point range that editors extend to the word boundary.
pub fn span_to_range(span: Span) -> Range {
    let start = span_to_position(span);
    let end = span.length.map_or(start, |len| Position {
        line: start.line,
        character: start.character + len as u32,
    });
    Range { start, end }
}

/// Extract the word (alphanumeric + `_`) at the given cursor position.
///
/// Returns `None` if the cursor is between words or out of bounds.
pub fn word_at_position(text: &str, pos: Position) -> Option<String> {
    let line = text.lines().nth(pos.line as usize)?;
    let char_idx = pos.character as usize;
    let chars: Vec<char> = line.chars().collect();
    if char_idx > chars.len() {
        return None;
    }
    let is_word = |c: char| c.is_alphanumeric() || c == '_';
    let start = (0..char_idx)
        .rev()
        .find(|&i| !is_word(chars[i]))
        .map_or(0, |i| i + 1);
    let end = (char_idx..chars.len())
        .find(|&i| !is_word(chars[i]))
        .unwrap_or(chars.len());
    if start == end {
        return None;
    }
    Some(chars[start..end].iter().collect())
}

/// Convert a rite-resolver diagnostic to an LSP diagnostic.
///
/// Spans are 1-indexed in rite; LSP uses 0-indexed line/character.
/// When `span.length` is set the diagnostic covers the exact token; otherwise
/// a point range is used and editors extend it to the word boundary.
pub fn to_lsp_diagnostic(d: &Diagnostic) -> LspDiagnostic {
    let range = d.span.map(span_to_range).unwrap_or_default();

    LspDiagnostic {
        range,
        severity: Some(match d.severity {
            Severity::Error => DiagnosticSeverity::ERROR,
            Severity::Warning => DiagnosticSeverity::WARNING,
        }),
        message: d.message.clone(),
        source: Some("rite-ls".into()),
        ..Default::default()
    }
}
