//! Completion logic for ceremony YAML.
//!
//! Implemented:
//! - `action:` field value completions (ActionType variants)
//! - `${...}` expression completions (roles, params, materials from SpanMap)
//! - `section:`, `role:`, `act:`, `backend:` field value completions from declarations
//! - `retry:` field value completions (the `never` keyword and the `{ attempts: N }` form)

use crate::actions;
use rite_model::Ceremony;
use rite_resolver::SpanMap;
use tower_lsp_server::ls_types::{
    CompletionItem, CompletionItemKind, CompletionTextEdit, Position, Range, TextEdit,
};

/// Context detected from the line at the cursor position.
pub enum CompletionContext {
    /// Cursor is after `action:`; offer `ActionType` values.
    Action,
    /// Cursor is inside a `${...}` expression; offer entity references.
    Expression {
        /// Text typed after `${`, e.g. `""`, `"r"`, `"role."`, `"role.op"`.
        typed: String,
        /// 0-indexed column of the `$` character.
        dollar_col: usize,
        /// 0-indexed column of the cursor.
        cursor_col: usize,
        /// 0-indexed line number.
        cursor_line: u32,
    },
    /// Cursor is after `section:`; offer declared section IDs.
    SectionRef { typed: String },
    /// Cursor is after `role:`; offer declared role IDs.
    RoleRef { typed: String },
    /// Cursor is after `act:`; offer declared act IDs.
    ActRef { typed: String },
    /// Cursor is after `backend:`; offer declared backend names.
    BackendRef { typed: String },
    /// Cursor is after `retry:`; offer the `never` keyword and the
    /// `{ attempts: N }` form.
    RetryRef { typed: String },
}

/// Detect what completion context applies on the given line.
///
/// `col` is the 0-indexed cursor column (LSP convention).
/// `cursor_line` is the 0-indexed line number (for building TextEdits).
pub fn detect_context(line: &str, col: usize, cursor_line: u32) -> Option<CompletionContext> {
    if line.trim_start().starts_with("action:") {
        return Some(CompletionContext::Action);
    }

    // Look for the last `${` before the cursor.
    let before = &line[..col.min(line.len())];
    if let Some(dollar_pos) = before.rfind("${") {
        let typed = before[dollar_pos + 2..].to_string();
        return Some(CompletionContext::Expression {
            typed,
            dollar_col: dollar_pos,
            cursor_col: col,
            cursor_line,
        });
    }

    // Detect `section:`, `role:`, `act:`, `backend:` field value completions.
    // Checked after expression so `role: ${...}` still triggers Expression context.
    let trimmed = before.trim_start();
    if let Some(rest) = trimmed.strip_prefix("section: ") {
        return Some(CompletionContext::SectionRef {
            typed: rest.to_string(),
        });
    }
    if let Some(rest) = trimmed.strip_prefix("role: ") {
        return Some(CompletionContext::RoleRef {
            typed: rest.to_string(),
        });
    }
    if let Some(rest) = trimmed.strip_prefix("act: ") {
        return Some(CompletionContext::ActRef {
            typed: rest.to_string(),
        });
    }
    if let Some(rest) = trimmed.strip_prefix("backend: ") {
        return Some(CompletionContext::BackendRef {
            typed: rest.to_string(),
        });
    }
    if let Some(rest) = trimmed.strip_prefix("retry: ") {
        return Some(CompletionContext::RetryRef {
            typed: rest.to_string(),
        });
    }

    None
}

/// Build completion items for the detected context.
pub fn completions_for(
    ctx: CompletionContext,
    span_map: &SpanMap,
    resolved: Option<&Ceremony>,
) -> Vec<CompletionItem> {
    match ctx {
        CompletionContext::Action => action_completions(),
        CompletionContext::Expression {
            typed,
            dollar_col,
            cursor_col,
            cursor_line,
        } => expression_completions(&typed, dollar_col, cursor_col, cursor_line, span_map),
        CompletionContext::SectionRef { typed } => {
            declaration_completions(span_map.sections.keys().map(|id| id.as_str()), &typed)
        }
        CompletionContext::RoleRef { typed } => {
            declaration_completions(span_map.roles.keys().map(|id| id.as_str()), &typed)
        }
        CompletionContext::ActRef { typed } => {
            declaration_completions(span_map.acts.keys().map(|id| id.as_str()), &typed)
        }
        CompletionContext::BackendRef { typed } => {
            if let Some(res) = resolved {
                declaration_completions(res.backends.keys().map(|s| s.as_str()), &typed)
            } else {
                declaration_completions(span_map.backends.keys().map(|s| s.as_str()), &typed)
            }
        }
        CompletionContext::RetryRef { typed } => retry_completions(&typed),
    }
}

/// The two valid `retry:` values: the bare `never` keyword and the inline
/// `{ attempts: N }` mapping. Static, since the set is fixed by the schema.
fn retry_completions(typed: &str) -> Vec<CompletionItem> {
    [
        ("never", "Forbid retries on this step"),
        ("{ attempts: 3 }", "Cap retries at N total attempts"),
    ]
    .into_iter()
    .filter(|(value, _)| value.starts_with(typed))
    .map(|(value, detail)| CompletionItem {
        label: value.to_string(),
        detail: Some(detail.to_string()),
        kind: Some(CompletionItemKind::VALUE),
        ..Default::default()
    })
    .collect()
}

fn declaration_completions<'a>(
    candidates: impl Iterator<Item = &'a str>,
    typed: &str,
) -> Vec<CompletionItem> {
    candidates
        .filter(|id| id.starts_with(typed))
        .map(|id| CompletionItem {
            label: id.to_string(),
            kind: Some(CompletionItemKind::VALUE),
            ..Default::default()
        })
        .collect()
}

fn action_completions() -> Vec<CompletionItem> {
    actions::ALL
        .iter()
        .map(|a| CompletionItem {
            label: a.name.into(),
            detail: Some(a.short.into()),
            kind: Some(CompletionItemKind::VALUE),
            ..Default::default()
        })
        .collect()
}

fn expression_completions(
    typed: &str,
    dollar_col: usize,
    cursor_col: usize,
    cursor_line: u32,
    span_map: &SpanMap,
) -> Vec<CompletionItem> {
    // Build (namespace, id) pairs from the SpanMap. The namespace is the one a
    // ceremony writes, so a material is offered as `artifact.<id>`: it is read
    // the same way a step output is, and there is no `material` namespace.
    let mut candidates: Vec<(&str, &str)> = Vec::new();
    for id in span_map.roles.keys() {
        candidates.push(("role", id.as_str()));
    }
    for id in span_map.params.keys() {
        candidates.push(("param", id.as_str()));
    }
    for id in span_map.materials.keys() {
        candidates.push(("artifact", id.as_str()));
    }
    for id in span_map.artifacts.keys() {
        candidates.push(("artifact", id.as_str()));
    }

    // The replace range covers only the text after `${` up to the cursor.
    // This lets VS Code use the typed prefix (e.g. "role.") for client-side
    // filtering against item labels like "role.operator", while new_text
    // inserts the completion with a closing `}` (the `${` already in the doc
    // is left untouched).
    let replace_range = Range {
        start: Position {
            line: cursor_line,
            character: (dollar_col + 2) as u32,
        },
        end: Position {
            line: cursor_line,
            character: cursor_col as u32,
        },
    };

    candidates
        .into_iter()
        .filter(|(cat, id)| format!("{cat}.{id}").starts_with(typed))
        .map(|(cat, id)| {
            let full = format!("{cat}.{id}");
            CompletionItem {
                label: full.clone(),
                kind: Some(CompletionItemKind::REFERENCE),
                text_edit: Some(CompletionTextEdit::Edit(TextEdit {
                    range: replace_range,
                    // `${` is already in the document; append `}` to close.
                    new_text: format!("{full}}}"),
                })),
                ..Default::default()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rite_model::{MaterialId, ParamId, RoleId};
    use rite_resolver::{Span, SpanMap};

    fn dummy_span() -> Span {
        Span {
            line: 1,
            column: 1,
            length: None,
        }
    }

    /// Build a SpanMap with only the given role IDs.
    fn span_map_roles(roles: &[&str]) -> SpanMap {
        let mut map = SpanMap::default();
        for &r in roles {
            map.roles.insert(RoleId::new(r), dummy_span());
        }
        map
    }

    /// Mixed SpanMap: two roles, one param, one material.
    fn span_map_mixed() -> SpanMap {
        let mut map = SpanMap::default();
        map.roles.insert(RoleId::new("operator"), dummy_span());
        map.roles.insert(RoleId::new("witness"), dummy_span());
        map.params.insert(ParamId::new("threshold"), dummy_span());
        map.materials.insert(MaterialId::new("card"), dummy_span());
        map
    }

    fn sorted_labels(items: &[CompletionItem]) -> Vec<String> {
        let mut labels: Vec<_> = items.iter().map(|i| i.label.clone()).collect();
        labels.sort();
        labels
    }

    fn get_text_edit(item: &CompletionItem) -> &TextEdit {
        match item.text_edit.as_ref().expect("text_edit should be set") {
            CompletionTextEdit::Edit(e) => e,
            _ => panic!("expected Edit variant"),
        }
    }

    // ── detect_context ────────────────────────────────────────────────────────

    #[test]
    fn detect_action_context() {
        assert!(matches!(
            detect_context("  action: ", 10, 0),
            Some(CompletionContext::Action)
        ));
    }

    #[test]
    fn detect_expression_empty_typed() {
        // Cursor right after `${` on column 10 (0-indexed).
        let line = "  role: ${";
        let col = line.len();
        match detect_context(line, col, 2) {
            Some(CompletionContext::Expression {
                typed,
                dollar_col,
                cursor_col,
                cursor_line,
            }) => {
                assert_eq!(typed, "");
                assert_eq!(dollar_col, 8);
                assert_eq!(cursor_col, col);
                assert_eq!(cursor_line, 2);
            }
            _ => panic!("expected Expression context"),
        }
    }

    #[test]
    fn detect_expression_with_category_prefix() {
        let line = "  role: ${role.op";
        let col = line.len();
        match detect_context(line, col, 0) {
            Some(CompletionContext::Expression { typed, .. }) => {
                assert_eq!(typed, "role.op");
            }
            _ => panic!("expected Expression context"),
        }
    }

    #[test]
    fn detect_none_for_plain_value() {
        assert!(detect_context("  name: foo", 11, 0).is_none());
    }

    #[test]
    fn detect_retry_context() {
        match detect_context("    retry: ", 11, 0) {
            Some(CompletionContext::RetryRef { typed }) => assert_eq!(typed, ""),
            _ => panic!("expected RetryRef context"),
        }
    }

    #[test]
    fn retry_offers_both_forms_when_empty() {
        let items = completions_for(
            CompletionContext::RetryRef {
                typed: String::new(),
            },
            &SpanMap::default(),
            None,
        );
        assert_eq!(sorted_labels(&items), ["never", "{ attempts: 3 }"]);
    }

    #[test]
    fn retry_filters_by_typed_prefix() {
        let items = completions_for(
            CompletionContext::RetryRef { typed: "ne".into() },
            &SpanMap::default(),
            None,
        );
        assert_eq!(sorted_labels(&items), ["never"]);
    }

    #[test]
    fn detect_none_when_cursor_before_dollar() {
        // Cursor at col 5, before the `${` which starts at col 8.
        let line = "  role: ${op";
        assert!(detect_context(line, 5, 0).is_none());
    }

    // ── expression completions ────────────────────────────────────────────────

    #[test]
    fn empty_typed_returns_all_entities() {
        let map = span_map_mixed();
        let ctx = CompletionContext::Expression {
            typed: "".into(),
            dollar_col: 8,
            cursor_col: 10,
            cursor_line: 0,
        };
        let items = completions_for(ctx, &map, None);
        assert_eq!(
            sorted_labels(&items),
            [
                // The `card` material, offered under the namespace that reads it.
                "artifact.card",
                "param.threshold",
                "role.operator",
                "role.witness"
            ]
        );
    }

    #[test]
    fn category_prefix_filters_to_that_category() {
        let map = span_map_mixed();
        let ctx = CompletionContext::Expression {
            typed: "role.".into(),
            dollar_col: 8,
            cursor_col: 15,
            cursor_line: 0,
        };
        let items = completions_for(ctx, &map, None);
        assert_eq!(sorted_labels(&items), ["role.operator", "role.witness"]);
    }

    #[test]
    fn single_letter_prefix_filters_by_category_start() {
        let map = span_map_mixed();
        // "r" matches role.*, "p" would match param.*, "m" would match material.*
        let ctx = CompletionContext::Expression {
            typed: "p".into(),
            dollar_col: 8,
            cursor_col: 11,
            cursor_line: 0,
        };
        let items = completions_for(ctx, &map, None);
        assert_eq!(sorted_labels(&items), ["param.threshold"]);
    }

    #[test]
    fn partial_id_narrows_within_category() {
        let map = span_map_mixed();
        let ctx = CompletionContext::Expression {
            typed: "role.op".into(),
            dollar_col: 8,
            cursor_col: 17,
            cursor_line: 0,
        };
        let items = completions_for(ctx, &map, None);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "role.operator");
    }

    #[test]
    fn no_match_returns_empty() {
        let map = span_map_mixed();
        let ctx = CompletionContext::Expression {
            typed: "xyz".into(),
            dollar_col: 8,
            cursor_col: 11,
            cursor_line: 0,
        };
        assert!(completions_for(ctx, &map, None).is_empty());
    }

    #[test]
    fn text_edit_range_starts_after_dollar_brace() {
        // `$` at col 8 → range.start.character = 10 (after `${`)
        let map = span_map_roles(&["operator"]);
        let ctx = CompletionContext::Expression {
            typed: "role.".into(),
            dollar_col: 8,
            cursor_col: 15,
            cursor_line: 3,
        };
        let items = completions_for(ctx, &map, None);
        assert_eq!(items.len(), 1);
        let edit = get_text_edit(&items[0]);
        assert_eq!(edit.range.start.line, 3);
        assert_eq!(edit.range.start.character, 10); // dollar_col + 2
        assert_eq!(edit.range.end.character, 15); // cursor_col
    }

    #[test]
    fn new_text_has_closing_brace_but_no_dollar_brace_open() {
        // new_text should be "role.operator}"; `${` is already in the doc.
        let map = span_map_roles(&["operator"]);
        let ctx = CompletionContext::Expression {
            typed: "".into(),
            dollar_col: 8,
            cursor_col: 10,
            cursor_line: 0,
        };
        let items = completions_for(ctx, &map, None);
        assert_eq!(items.len(), 1);
        assert_eq!(get_text_edit(&items[0]).new_text, "role.operator}");
    }

    #[test]
    fn all_items_have_reference_kind() {
        let map = span_map_mixed();
        let ctx = CompletionContext::Expression {
            typed: "".into(),
            dollar_col: 0,
            cursor_col: 2,
            cursor_line: 0,
        };
        for item in completions_for(ctx, &map, None) {
            assert_eq!(item.kind, Some(CompletionItemKind::REFERENCE));
        }
    }
}
