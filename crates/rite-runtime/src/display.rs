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

use rite_model::StepFact;

use crate::protocol::{Icon, UiSignal};

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
        StepFact::CeremonyFailed { error, .. } => {
            Some((Icon::Cross, format!("Ceremony failed: {}", error.message)))
        }
        // `StepFact` is `#[non_exhaustive]`; future variants may carry
        // payloads the live UI shouldn't blindly Debug-print. Surface a
        // typed placeholder until each new variant is given a summary.
        _ => Some((Icon::Info, "unknown fact variant".to_string())),
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
    use super::truncate_for_display;

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
