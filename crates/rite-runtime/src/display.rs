//! Line-oriented rendering of protocol events for live frontends.
//!
//! The console driver and the TUI both surface the same `StepFact` and
//! `UiSignal` stream; this module is the single source of truth for the
//! short one-line summary each variant produces. Frontends pick how to
//! style and place the line (stdout vs ratatui log feed), but the icon
//! and text are aligned.
//!
//! Returns `None` for variants intentionally suppressed from the live
//! feed (currently `StepFact::PromptAnswered`, since the prompt itself
//! was already surfaced by `AwaitPrompt` and the operator typed the
//! answer in front of them).

use rite_model::{ErrorClass, StepFact};

use crate::protocol::{Icon, UiSignal};

/// What a fact with no summary of its own falls back to.
const UNSUMMARISED: &str = "unknown fact variant";

/// One-line summary of a [`StepFact`] for live-frontend display.
///
/// Returns `None` for facts the live UI shouldn't surface:
/// - `PromptAnswered`: the operator just typed it.
/// - `BackendOperation` / `AttestationRecorded`: the surrounding action
///   handler already calls `Reporter::log` with its own narrative line.
/// - `CeremonyCompleted`: the frontend renders a dedicated completion
///   screen with the fingerprint.
#[must_use]
pub fn fact_summary(fact: &StepFact) -> Option<(Icon, String)> {
    match fact {
        StepFact::CeremonyStarted { name, .. } => Some((Icon::Info, format!("Ceremony: {name}"))),
        StepFact::ActStarted { label, .. } => Some((Icon::Info, format!("Act: {label}"))),
        StepFact::StepStarted {
            id,
            label,
            role_name,
            ..
        } => Some((
            Icon::Info,
            format!("Step {label} ({id}), role: {role_name}"),
        )),
        StepFact::PromptAnswered { .. }
        | StepFact::BackendOperation { .. }
        | StepFact::AttestationRecorded { .. }
        | StepFact::CeremonyCompleted { .. } => None,
        StepFact::ArtifactWritten { path, .. } => Some((
            Icon::Checkmark,
            format!("Artifact written: {}", path.display()),
        )),
        StepFact::DeviationRecorded { text, .. } => {
            Some((Icon::Warning, format!("Deviation: {text}")))
        }
        StepFact::StepCompleted { outcome, .. } => match outcome {
            rite_model::StepOutcome::Completed { message } => {
                Some((Icon::Checkmark, message.clone()))
            }
            _ => Some((Icon::Checkmark, "Step completed".to_string())),
        },
        StepFact::StepAttemptFailed { attempt, error, .. } => Some((
            Icon::Cross,
            format!("Attempt {attempt} failed: {}", error.message),
        )),
        StepFact::CeremonyFailed { error, .. } => match error.class {
            // An abort is a deliberate operator decision, not a failure: show it
            // neutrally rather than with the failure cross.
            ErrorClass::Abort => Some((Icon::Info, error.message.clone())),
            _ => Some((Icon::Cross, format!("Ceremony failed: {}", error.message))),
        },
        StepFact::EntropySeeded { source, .. } => {
            Some((Icon::Info, format!("Entropy source seeded ({source})")))
        }
        StepFact::EntropyContributed { epoch, .. } => Some((
            Icon::Info,
            format!("Entropy contribution folded (epoch {epoch})"),
        )),
        StepFact::EntropyDrawn { path, .. } => {
            Some((Icon::Info, format!("Random value drawn: {path}")))
        }
        // Who the wrap is addressed to is the operator's last chance to stop a
        // wrap they cannot undo, so the fingerprint is shown, not summarised
        // away.
        StepFact::WrapRecipientRecorded {
            source,
            fingerprint,
            declared,
            ..
        } => Some((
            Icon::Info,
            if *declared {
                format!("Recipient {source} matches the declared {fingerprint}")
            } else {
                format!("Recipient {source} is {fingerprint}, undeclared")
            },
        )),
        // `StepFact` is `#[non_exhaustive]`, so this arm is unavoidable in a
        // crate downstream of the one defining it. A variant reaching it is a
        // variant added without a line of its own, which an operator sees
        // mid-ceremony; give every new variant an arm above.
        _ => Some((Icon::Info, UNSUMMARISED.to_string())),
    }
}

/// One-line summary of a [`UiSignal`] for live-frontend display.
///
/// Returns `None` for the structured signals that frontends handle
/// out-of-band ([`UiSignal::CeremonyOverview`], [`UiSignal::SystemInfo`],
/// [`UiSignal::Environment`]), which populate structured fields rather than a
/// single narration line.
#[must_use]
pub fn signal_summary(signal: &UiSignal) -> Option<(Icon, String)> {
    match signal {
        UiSignal::LogLine { icon, text, .. } => Some((*icon, text.clone())),
        UiSignal::Progress {
            phase, fraction, ..
        } => {
            let text = match fraction {
                Some(f) => format!("{phase}: {:>5.1}%", f * 100.0),
                None => format!("{phase}…"),
            };
            Some((Icon::Spinner, text))
        }
        UiSignal::CeremonyOverview { .. } | UiSignal::SystemInfo(_) | UiSignal::Environment(_) => {
            None
        }
    }
}

/// Truncate a string to at most `max_chars` Unicode scalar values, appending
/// `"..."` when truncation occurs.
///
/// Safe on multibyte input: never slices inside a UTF-8 code point.
#[must_use]
pub fn truncate_for_display(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        Some((boundary, _)) => format!("{}...", &s[..boundary]),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{UNSUMMARISED, fact_summary, truncate_for_display};
    use rite_model::{StepFact, StepId};

    /// A fact with no arm of its own reaches the operator as a placeholder in
    /// the middle of a ceremony, which is worse than saying nothing.
    #[test]
    fn the_wrap_recipient_carries_its_fingerprint() {
        let (_, line) = fact_summary(&StepFact::WrapRecipientRecorded {
            step: StepId::new("wrap"),
            source: "escrow_pubkey".to_string(),
            fingerprint: "sha256:abcd".to_string(),
            declared: false,
        })
        .expect("the live feed surfaces the recipient");
        assert_ne!(line, UNSUMMARISED);
        assert!(line.contains("escrow_pubkey"), "{line}");
        assert!(line.contains("sha256:abcd"), "{line}");
    }

    #[test]
    fn truncate_passes_through_short_input() {
        assert_eq!(truncate_for_display("short", 10), "short");
    }

    #[test]
    fn truncate_adds_ellipsis_when_too_long() {
        assert_eq!(
            truncate_for_display("this is a long string", 10),
            "this is a ..."
        );
    }

    #[test]
    fn truncate_respects_utf8_code_point_boundaries() {
        // Each emoji is a 4-byte UTF-8 sequence; naive byte slicing panics.
        let s = "🦀🦀🦀🦀🦀";
        assert_eq!(truncate_for_display(s, 2), "🦀🦀...");
        assert_eq!(truncate_for_display(s, 5), "🦀🦀🦀🦀🦀");
    }
}
