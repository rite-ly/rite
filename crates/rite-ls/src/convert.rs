//! Convert rite-resolver types to LSP types.

use rite_resolver::{Diagnostic, Severity, Span};
use tower_lsp_server::ls_types::{
    Diagnostic as LspDiagnostic, DiagnosticSeverity, Position, Range,
};

/// A count as an LSP `u32`, saturating: no document reaches 4 G lines or
/// columns.
pub fn to_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// The part of `line` before its `n`th character, or all of it when it is
/// shorter.
///
/// The server counts columns in characters. The LSP default counts UTF-16
/// units, which differ only after a character outside the Basic
/// Multilingual Plane, such as an emoji.
pub fn line_prefix(line: &str, n: usize) -> &str {
    line.char_indices()
        .nth(n)
        .map_or(line, |(end, _)| line.get(..end).unwrap_or(line))
}

/// Convert a rite-resolver span (1-indexed) to an LSP position (0-indexed).
pub fn span_to_position(span: Span) -> Position {
    Position {
        line: to_u32(span.line.saturating_sub(1)),
        character: to_u32(span.column.saturating_sub(1)),
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
        character: start.character.saturating_add(to_u32(len)),
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
    let (before, after) = chars.split_at_checked(char_idx)?;
    let not_word = |c: &char| !(c.is_alphanumeric() || *c == '_');
    // Each split yields at least one run, possibly empty.
    let head = before.rsplit(not_word).next().unwrap_or_default();
    let tail = after.split(not_word).next().unwrap_or_default();
    let word: String = head.iter().chain(tail).collect();
    (!word.is_empty()).then_some(word)
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

#[cfg(test)]
mod diagnostic_tests {
    use super::to_lsp_diagnostic;
    use tower_lsp_server::ls_types::DiagnosticSeverity;

    /// A bad `with:` value has to reach the editor, not only `rite check`.
    ///
    /// The server links the resolver and no backend, so this holds only while
    /// the rules that decide it live in the model rather than in an action
    /// handler.
    #[test]
    fn an_invalid_with_value_becomes_an_editor_diagnostic() {
        let yaml = r#"
version: "0.3"
name: "Bad algorithm"
roles:
  officer:
    person: "Alice"
backends:
  openssl:
    provider: openssl
sections:
  main:
    role: ${role.officer}
    steps:
      gen:
        action: generate_key
        backend: openssl
        with:
          algorithm: RSA-9999
        creates: key
"#;
        let (_resolved, _spans, diags) = rite_resolver::analyze_str(None, yaml);
        let published: Vec<_> = diags.iter().map(to_lsp_diagnostic).collect();
        let found = published
            .iter()
            .find(|d| d.message.contains("'with.algorithm' must be one of"))
            .expect("the editor is told about the bad algorithm");

        assert_eq!(found.severity, Some(DiagnosticSeverity::ERROR));
        assert!(
            found.range.end > found.range.start,
            "an empty range gives the editor nothing to underline"
        );
    }
}

#[cfg(test)]
mod word_tests {
    use super::word_at_position;
    use tower_lsp_server::ls_types::Position;

    fn word(text: &str, line: u32, character: u32) -> Option<String> {
        word_at_position(text, Position { line, character })
    }

    #[test]
    fn the_word_around_the_cursor_is_found_from_either_edge() {
        let text = "first\nrole: key_officer here";
        assert_eq!(word(text, 1, 8).as_deref(), Some("key_officer"));
        assert_eq!(word(text, 1, 6).as_deref(), Some("key_officer"));
        assert_eq!(word(text, 1, 17).as_deref(), Some("key_officer"));
        assert_eq!(word(text, 1, 22).as_deref(), Some("here"));
        assert_eq!(word(text, 0, 0).as_deref(), Some("first"));
    }

    #[test]
    fn nothing_is_found_between_words_or_past_the_text() {
        let text = "a :  b";
        assert_eq!(word(text, 0, 3), None);
        assert_eq!(word(text, 0, 7), None);
        assert_eq!(word(text, 1, 0), None);
    }

    #[test]
    fn the_cursor_counts_characters_not_bytes() {
        assert_eq!(word("é clé", 0, 3).as_deref(), Some("clé"));
    }
}
