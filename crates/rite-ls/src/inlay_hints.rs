//! Inlay hint emission for the LSP.
//!
//! One hint per step, showing the same step label that `rite script`
//! prints and `rite run` reports (`1.1`, `2.3`, ... when there are
//! multiple acts; flat `1`, `2`, ... when there is only one). The hint
//! lets a reader cross-reference YAML source with transcript and
//! checklist output without counting steps by hand.
//!
//! Labels come from `Ceremony.execution_plan`; we look up each step by
//! ID and anchor the hint past the colon that follows the step ID so
//! it reads as a trailing annotation. When the document fails to
//! resolve no hints are emitted, since partial labels would mislead.

use crate::convert::span_to_range;
use rite_model::{Ceremony, StepId};
use rite_resolver::SpanMap;
use std::collections::HashMap;
use tower_lsp_server::ls_types::{InlayHint, InlayHintLabel};

/// Build the inlay hints for a document. Returns an empty vec when the
/// document failed to resolve, since partial labels would mislead the
/// reader.
pub fn hints_for(span_map: &SpanMap, ceremony: Option<&Ceremony>) -> Vec<InlayHint> {
    let Some(ceremony) = ceremony else {
        return Vec::new();
    };

    let labels: HashMap<&StepId, &str> = ceremony
        .execution_plan
        .iter()
        .map(|step| (&step.id, step.step_label.as_str()))
        .collect();

    span_map
        .steps
        .iter()
        .filter_map(|(id, span)| {
            let label = labels.get(id)?;
            // Anchor past the colon that follows the step ID so the hint
            // reads as a trailing annotation rather than splitting the key.
            let mut position = span_to_range(*span).end;
            position.character = position.character.saturating_add(1);
            Some(InlayHint {
                position,
                label: InlayHintLabel::String((*label).to_string()),
                kind: None,
                text_edits: None,
                tooltip: None,
                padding_left: Some(true),
                padding_right: None,
                data: None,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::hints_for;
    use rite_resolver::analyze_str;
    use tower_lsp_server::ls_types::InlayHintLabel;

    fn labels_in_source_order(text: &str) -> Vec<String> {
        let (ceremony, span_map, _) = analyze_str(None, text);
        let mut hints = hints_for(&span_map, ceremony.as_ref());
        hints.sort_by_key(|h| (h.position.line, h.position.character));
        hints
            .into_iter()
            .map(|h| match h.label {
                InlayHintLabel::String(s) => s,
                _ => panic!("expected string label"),
            })
            .collect()
    }

    #[test]
    fn single_act_uses_flat_numbering() {
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
      first:
        action: confirm
        with:
          message: "1"
      second:
        action: confirm
        with:
          message: "2"
"#;
        assert_eq!(labels_in_source_order(text), vec!["1", "2"]);
    }

    #[test]
    fn multiple_acts_use_dotted_numbering() {
        let text = r#"
version: "0.2"
name: "T"
roles:
  alice:
    person: "Alice"
acts:
  - id: opening
  - id: closing
sections:
  open_s:
    act: opening
    role: ${role.alice}
    steps:
      a:
        action: confirm
        with:
          message: "1"
      b:
        action: confirm
        with:
          message: "2"
  close_s:
    act: closing
    role: ${role.alice}
    steps:
      c:
        action: confirm
        with:
          message: "3"
"#;
        assert_eq!(labels_in_source_order(text), vec!["1.1", "1.2", "2.1"]);
    }

    #[test]
    fn hint_is_anchored_past_the_colon() {
        // `first:` starts at column 7 (1-indexed), length 5, so the colon
        // is at column 12. LSP positions are 0-indexed; the hint anchors
        // one column past the colon → character == 12.
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
      first:
        action: confirm
        with:
          message: "hi"
"#;
        let (ceremony, span_map, _) = analyze_str(None, text);
        let hints = hints_for(&span_map, ceremony.as_ref());
        let hint = hints.first().expect("expected one hint");
        assert_eq!(hint.position.character, 12);
    }

    #[test]
    fn unresolved_document_emits_no_hints() {
        let (_, span_map, _) = analyze_str(None, "not a ceremony");
        assert!(hints_for(&span_map, None).is_empty());
    }
}
