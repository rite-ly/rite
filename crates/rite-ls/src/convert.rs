//! Convert rite-resolver types to LSP types.
//!
//! The resolver and this server count columns in characters. The LSP counts
//! them in UTF-16 units, its default and the one encoding every client
//! supports, so the server negotiates no other. The two differ after a
//! character outside the Basic Multilingual Plane, such as an emoji: one
//! character, two units. [`LineIndex`] converts at the boundary: a position
//! from the client becomes a [`CharPos`] through [`LineIndex::in_characters`],
//! and a position or range for it is built by [`LineIndex`].

use rite_resolver::{Diagnostic, Severity, Span};
use tower_lsp_server::ls_types::{
    Diagnostic as LspDiagnostic, DiagnosticSeverity, Position, Range,
};

/// A count as an LSP `u32`, saturating: no document reaches 4 G lines or
/// columns.
fn to_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// The part of `line` before its `n`th character, or all of it when it is
/// shorter.
pub fn line_prefix(line: &str, n: usize) -> &str {
    line.char_indices()
        .nth(n)
        .map_or(line, |(end, _)| line.get(..end).unwrap_or(line))
}

/// A position in a document, 0-indexed, with its column counted in
/// characters. One from the client is made by [`LineIndex::in_characters`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CharPos {
    pub line: usize,
    pub column: usize,
}

impl CharPos {
    /// The line and column 1-indexed, as the resolver's spans count them.
    pub fn one_indexed(self) -> (usize, usize) {
        (self.line.saturating_add(1), self.column.saturating_add(1))
    }
}

/// A document's lines, to convert between the columns of the resolver and
/// this server, in characters, and the LSP's, in UTF-16 units.
pub struct LineIndex<'a> {
    lines: Vec<&'a str>,
}

impl<'a> LineIndex<'a> {
    pub fn new(text: &'a str) -> Self {
        Self {
            lines: text.lines().collect(),
        }
    }

    /// The text of a 0-indexed line, or nothing past the last.
    pub fn line(&self, line: usize) -> &'a str {
        self.lines.get(line).copied().unwrap_or("")
    }

    /// The LSP position of a 0-indexed line and character column. Past the
    /// end of the line, each column counts one unit.
    pub fn position(&self, line: usize, column: usize) -> Position {
        let text = self.line(line);
        let within: usize = text.chars().take(column).map(char::len_utf16).sum();
        let past = column.saturating_sub(text.chars().count());
        Position {
            line: to_u32(line),
            character: to_u32(within.saturating_add(past)),
        }
    }

    /// `pos`, from the client, with its column counted in characters. A
    /// column inside a character's pair of units falls before that
    /// character; past the end of the line, each unit counts one column.
    pub fn in_characters(&self, pos: Position) -> CharPos {
        let line = pos.line as usize;
        let mut left = pos.character as usize;
        let mut column = 0usize;
        for c in self.line(line).chars() {
            let Some(rest) = left.checked_sub(c.len_utf16()) else {
                left = 0;
                break;
            };
            left = rest;
            column = column.saturating_add(1);
        }
        CharPos {
            line,
            column: column.saturating_add(left),
        }
    }

    /// The point range where `span`, 1-indexed, starts. Editors extend it to
    /// the word boundary, for a declaration whose length is not tracked.
    pub fn span_point(&self, span: Span) -> Range {
        let start = self.position(span.line.saturating_sub(1), span.column.saturating_sub(1));
        Range { start, end: start }
    }

    /// The LSP range `span` covers. Without a length it is a point range,
    /// which editors extend to the word boundary.
    pub fn span_range(&self, span: Span) -> Range {
        let start = self.span_point(span).start;
        let end = span.length.map_or(start, |len| {
            self.position(
                span.line.saturating_sub(1),
                span.column.saturating_sub(1).saturating_add(len),
            )
        });
        Range { start, end }
    }

    /// `d` as an LSP diagnostic, covering its span.
    pub fn diagnostic(&self, d: &Diagnostic) -> LspDiagnostic {
        LspDiagnostic {
            range: d.span.map(|span| self.span_range(span)).unwrap_or_default(),
            severity: Some(match d.severity {
                Severity::Error => DiagnosticSeverity::ERROR,
                Severity::Warning => DiagnosticSeverity::WARNING,
            }),
            message: d.message.clone(),
            source: Some("rite-ls".into()),
            ..Default::default()
        }
    }

    /// The word (alphanumeric and `_`) at `pos`, or `None` between words
    /// or out of bounds.
    pub fn word_at(&self, pos: CharPos) -> Option<String> {
        let chars: Vec<char> = self.lines.get(pos.line)?.chars().collect();
        let (before, after) = chars.split_at_checked(pos.column)?;
        let not_word = |c: &char| !(c.is_alphanumeric() || *c == '_');
        // Each split yields at least one run, possibly empty.
        let head = before.rsplit(not_word).next().unwrap_or_default();
        let tail = after.split(not_word).next().unwrap_or_default();
        let word: String = head.iter().chain(tail).collect();
        (!word.is_empty()).then_some(word)
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::LineIndex;
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
        let lines = LineIndex::new(yaml);
        let published: Vec<_> = diags.iter().map(|d| lines.diagnostic(d)).collect();
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
    use super::{CharPos, LineIndex};

    fn word(text: &str, line: usize, column: usize) -> Option<String> {
        LineIndex::new(text).word_at(CharPos { line, column })
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

#[cfg(test)]
mod line_index_tests {
    use super::{CharPos, LineIndex};
    use tower_lsp_server::ls_types::Position;

    fn at(line: u32, character: u32) -> Position {
        Position { line, character }
    }

    // `é` is one character and one UTF-16 unit; `🔑` is one character and two.
    const TEXT: &str = "plain\nné 🔑 x";

    #[test]
    fn character_columns_become_utf16_columns() {
        let lines = LineIndex::new(TEXT);
        assert_eq!(lines.position(0, 3), at(0, 3));
        assert_eq!(lines.position(1, 3), at(1, 3));
        assert_eq!(lines.position(1, 4), at(1, 5));
        assert_eq!(lines.position(1, 6), at(1, 7));
        // Past the end of the line, one unit per column.
        assert_eq!(lines.position(1, 9), at(1, 10));
        assert_eq!(lines.position(5, 2), at(5, 2));
    }

    #[test]
    fn utf16_columns_from_the_client_become_character_columns() {
        let lines = LineIndex::new(TEXT);
        assert_eq!(
            lines.in_characters(at(1, 3)),
            CharPos { line: 1, column: 3 }
        );
        assert_eq!(
            lines.in_characters(at(1, 5)),
            CharPos { line: 1, column: 4 }
        );
        assert_eq!(
            lines.in_characters(at(1, 7)),
            CharPos { line: 1, column: 6 }
        );
        // Inside the key's pair of units: before the key.
        assert_eq!(
            lines.in_characters(at(1, 4)),
            CharPos { line: 1, column: 3 }
        );
        assert_eq!(
            lines.in_characters(at(1, 10)),
            CharPos { line: 1, column: 9 }
        );
    }
}
