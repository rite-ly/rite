//! Semantic token emission for the LSP.
//!
//! Three categories:
//!   - Identifier (variable): the actual entity name, both inside `${...}`
//!     and at bare-reference sites (`backend: openssl`, `act: opening`).
//!   - Expression wrapper (function): the `${prefix.` and `}` punctuation
//!     plus the type prefix. All expressions share this style regardless
//!     of what they reference.
//!   - Enum value (enum): the value scalars on `action:` and `provider:`
//!     fields. These pick from a fixed registry rather than referencing
//!     a declared identifier; the resolver records their spans in
//!     `SpanMap.enum_values`.

use crate::convert::span_to_position;
use rite_resolver::{Span, SpanMap};
use tower_lsp_server::ls_types::{SemanticToken, SemanticTokenType};

/// Token kinds. The `repr(u32)` discriminant is the index into `LEGEND`.
#[derive(Clone, Copy)]
#[repr(u32)]
enum Kind {
    Ident = 0,
    Wrapper = 1,
    EnumValue = 2,
}

impl Kind {
    const fn index(self) -> u32 {
        self as u32
    }
}

pub const LEGEND: &[SemanticTokenType] = &[
    SemanticTokenType::VARIABLE, // Kind::Ident
    SemanticTokenType::FUNCTION, // Kind::Wrapper
    SemanticTokenType::ENUM,     // Kind::EnumValue (action / provider)
];

/// Build a delta-encoded semantic-token stream from the document's span map.
pub fn tokens_for(span_map: &SpanMap) -> Vec<SemanticToken> {
    let mut entries: Vec<TokenEntry> =
        Vec::with_capacity(span_map.references.len() * 3 + span_map.enum_values.len());

    for e in &span_map.references {
        if e.span.length.is_some() {
            push_reference_tokens(&mut entries, &e.value, e.span);
        }
    }

    for span in &span_map.enum_values {
        if span.length.is_some() {
            entries.push(TokenEntry {
                span: *span,
                kind: Kind::EnumValue,
            });
        }
    }

    entries.sort_by_key(|t| (t.span.line, t.span.column));

    encode(&entries)
}

#[derive(Clone, Copy)]
struct TokenEntry {
    span: Span,
    kind: Kind,
}

/// Emit one or three tokens for a reference scalar.
///
/// `${...}` produces three tokens: the opening `${` and closing `}` as
/// wrapper, the contents as a single identifier-style token. Any other
/// form is a single identifier token at the full span.
fn push_reference_tokens(out: &mut Vec<TokenEntry>, value: &str, span: Span) {
    let Some(len) = span.length else { return };
    let at = |col_delta: usize, length: usize, kind: Kind| TokenEntry {
        span: Span {
            line: span.line,
            column: span.column + col_delta,
            length: Some(length),
        },
        kind,
    };
    if let Some(inside_len) = expression_inside_len(value) {
        out.push(at(0, 2, Kind::Wrapper));
        out.push(at(2, inside_len, Kind::Ident));
        out.push(at(2 + inside_len, 1, Kind::Wrapper));
    } else {
        out.push(at(0, len, Kind::Ident));
    }
}

/// Return the byte length of the contents inside `${...}`, or `None` if
/// the value is not a `${...}` expression or is empty inside.
fn expression_inside_len(value: &str) -> Option<usize> {
    let inside = value.strip_prefix("${")?.strip_suffix('}')?;
    if inside.is_empty() {
        None
    } else {
        Some(inside.len())
    }
}

/// Convert sorted entries to LSP's delta-encoded representation.
fn encode(entries: &[TokenEntry]) -> Vec<SemanticToken> {
    let mut tokens = Vec::with_capacity(entries.len());
    let mut prev_line: u32 = 0;
    let mut prev_col: u32 = 0;

    for e in entries {
        let pos = span_to_position(e.span);
        let length = u32::try_from(e.span.length.unwrap_or(0)).unwrap_or(u32::MAX);

        let delta_line = pos.line.saturating_sub(prev_line);
        let delta_start = if delta_line == 0 {
            pos.character.saturating_sub(prev_col)
        } else {
            pos.character
        };

        tokens.push(SemanticToken {
            delta_line,
            delta_start,
            length,
            token_type: e.kind.index(),
            token_modifiers_bitset: 0,
        });

        prev_line = pos.line;
        prev_col = pos.character;
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::{Kind, LEGEND, expression_inside_len, tokens_for};
    use rite_resolver::analyze_str;
    use tower_lsp_server::ls_types::SemanticTokenType;

    fn analyze(text: &str) -> Vec<super::SemanticToken> {
        let (_, span_map, _) = analyze_str(None, text);
        tokens_for(&span_map)
    }

    #[test]
    fn legend_order_matches_kinds() {
        assert_eq!(
            LEGEND[Kind::Ident.index() as usize],
            SemanticTokenType::VARIABLE
        );
        assert_eq!(
            LEGEND[Kind::Wrapper.index() as usize],
            SemanticTokenType::FUNCTION
        );
        assert_eq!(
            LEGEND[Kind::EnumValue.index() as usize],
            SemanticTokenType::ENUM
        );
    }

    #[test]
    fn expression_splits_into_three_tokens() {
        let text = r#"
version: "0.2"
name: "T"
roles:
  alice:
    person: "Alice"
sections:
  s:
    role: ${role.alice}
    steps:
      hello:
        action: confirm
        with:
          message: "hi"
"#;
        let tokens = analyze(text);
        let kinds: Vec<u32> = tokens.iter().map(|t| t.token_type).collect();
        let wrapper = Kind::Wrapper.index();
        let ident = Kind::Ident.index();
        let found = kinds.windows(3).any(|w| w == [wrapper, ident, wrapper]);
        assert!(found, "expected wrapper/ident/wrapper trio in {kinds:?}");
    }

    #[test]
    fn bare_reference_is_a_single_ident_token() {
        let text = r#"
version: "0.2"
name: "T"
backends:
  openssl:
    provider: openssl
roles:
  op:
    person: "Op"
sections:
  s:
    role: ${role.op}
    steps:
      gen:
        action: generate_keypair
        backend: openssl
        with:
          algorithm: RSA-4096
        creates: key
"#;
        let tokens = analyze(text);
        let ident = Kind::Ident.index();
        assert!(
            tokens.iter().any(|t| t.token_type == ident),
            "missing ident token: {tokens:?}"
        );
    }

    #[test]
    fn action_and_provider_values_get_enum_tokens() {
        let text = r#"
version: "0.2"
name: "T"
backends:
  openssl:
    provider: openssl
roles:
  alice:
    person: "Alice"
sections:
  s:
    role: ${role.alice}
    steps:
      hello:
        action: confirm
        with:
          message: "hi"
"#;
        let tokens = analyze(text);
        let enum_value = Kind::EnumValue.index();
        let count = tokens.iter().filter(|t| t.token_type == enum_value).count();
        assert!(
            count >= 2,
            "expected action and provider enum tokens, got {count}: {tokens:?}"
        );
    }

    #[test]
    fn enum_tokens_ignore_action_text_inside_block_scalars() {
        // An `action:` line embedded inside a block scalar must not produce
        // an enum token. The resolver only records spans for real YAML keys.
        let text = r#"
version: "0.2"
name: "T"
roles:
  alice:
    person: "Alice"
sections:
  s:
    role: ${role.alice}
    steps:
      hello:
        action: confirm
        description: |
          The operator should follow this checklist:
            action: take_a_break
            provider: coffee_machine
        with:
          message: "hi"
"#;
        let tokens = analyze(text);
        // Exactly one action and zero provider tokens for this ceremony.
        let enum_value = Kind::EnumValue.index();
        let count = tokens.iter().filter(|t| t.token_type == enum_value).count();
        assert_eq!(count, 1, "expected 1 enum token, got {count}: {tokens:?}");
    }

    #[test]
    fn expression_inside_len_handles_all_forms() {
        // The split treats the inside as one unit, so prefix shape doesn't matter.
        assert_eq!(expression_inside_len("${role.alice}"), Some(10));
        assert_eq!(expression_inside_len("${artifact.key}"), Some(12));
        assert_eq!(expression_inside_len("${role}"), Some(4));
        assert_eq!(expression_inside_len("${.alice}"), Some(6));
        assert_eq!(expression_inside_len("${role.}"), Some(5));
        // Empty inside and non-expressions are rejected.
        assert_eq!(expression_inside_len("${}"), None);
        assert_eq!(expression_inside_len("role.alice"), None);
    }
}
