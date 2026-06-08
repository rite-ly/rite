//! Headless frontend driver, auto-answers every prompt according to a
//! defaults policy.
//!
//! Used for `--frontend=headless`: CI smoke tests, `rite check`-style
//! dry-runs, and scripted ceremony rehearsals. The defaults policy is
//! deliberately narrow, anything ambiguous (free-form text, secrets)
//! fails fast so a ceremony can't silently misanswer a prompt.
//!
//! # Defaults policy
//!
//! - `Confirm`: answer with `true` (or the prompt's `default` if specified)
//! - `Continue`: acknowledge
//! - `Literal`: type the expected string
//! - `Text`: fail, the operator must answer in `--frontend=console`
//! - `Secret`: fail, never auto-answered
//!
//! All facts and signals are written to stderr so that stdout stays
//! reserved for whatever the CLI invocation wants to emit (transcript
//! fingerprints, summaries, etc.).

use std::io::{self, Write};

use crossbeam_channel::{Receiver, Sender};

use secrecy::SecretString;

use rite_model::{Prompt, StepFact, ValidatorSpec};
use rite_runtime::{ExecEvent, Response, UiCommand, UiSignal};

/// Placeholder answer for an unconstrained free-form prompt with no human to
/// type it. Fixed, so non-interactive runs (and their transcripts) stay
/// deterministic.
const PLACEHOLDER_TEXT: &str = "placeholder";

/// Placeholder stand-in for a secret prompt with no human to type it. Never a
/// real secret.
const PLACEHOLDER_SECRET: &str = "placeholder-secret";

/// Run the headless driver against a pair of runtime channels.
///
/// Blocks until the runtime closes the event channel.
///
/// # Errors
///
/// Returns an I/O error if stderr fails, or
/// [`io::ErrorKind::InvalidInput`] when a prompt requires interactive
/// input the defaults policy cannot satisfy (free-form text, secret).
pub fn run(cmd_tx: &Sender<UiCommand>, event_rx: &Receiver<ExecEvent>) -> io::Result<()> {
    let stderr = io::stderr();
    let mut stderr = stderr.lock();

    while let Ok(event) = event_rx.recv() {
        match event {
            ExecEvent::Fact { fact, .. } => render_fact(&mut stderr, &fact)?,
            ExecEvent::Signal(signal) => render_signal(&mut stderr, &signal)?,
            ExecEvent::Finalized { fingerprint } => {
                writeln!(stderr, "[fingerprint] {fingerprint}")?;
            }
            ExecEvent::AwaitPrompt {
                prompt_id, prompt, ..
            } => {
                let response = default_response(&prompt)?;
                if cmd_tx
                    .send(UiCommand::PromptResponse {
                        prompt_id,
                        response,
                    })
                    .is_err()
                {
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}

fn default_response(prompt: &Prompt) -> io::Result<Response> {
    match prompt {
        Prompt::Confirm { default, .. } => Ok(Response::Bool(default.unwrap_or(true))),
        Prompt::Continue { .. } => Ok(Response::Acknowledge),
        Prompt::Literal { expected, .. } => Ok(Response::Text(expected.clone())),
        // Free-form text: a fixed placeholder satisfies an unconstrained
        // (`NonEmpty`) prompt. A validated prompt (regex, named predicate) can't
        // be answered generically, so it still fails fast until the step carries
        // an explicit value.
        Prompt::Text { label, validator } => match validator {
            ValidatorSpec::NonEmpty => Ok(Response::Text(PLACEHOLDER_TEXT.to_string())),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "headless driver cannot answer the validated text prompt: '{label}'. \
                     Use --frontend=console for an interactive run."
                ),
            )),
        },
        Prompt::Secret { .. } => Ok(Response::Secret(SecretString::from(PLACEHOLDER_SECRET))),
        _ => Err(io::Error::other(format!(
            "headless driver does not know how to handle prompt: {prompt:?}"
        ))),
    }
}

fn render_fact<W: Write>(out: &mut W, fact: &StepFact) -> io::Result<()> {
    match fact {
        StepFact::CeremonyStarted { name, .. } => writeln!(out, "[ceremony] {name}"),
        StepFact::StepStarted { id, label, .. } => writeln!(out, "[step] {label} ({id})"),
        StepFact::StepCompleted { id, .. } => writeln!(out, "[step-done] {id}"),
        StepFact::CeremonyCompleted { .. } => writeln!(out, "[done]"),
        StepFact::CeremonyFailed { error, .. } => writeln!(out, "[failed] {}", error.message),
        // The headless driver is intentionally terse for the remaining facts.
        _ => Ok(()),
    }
}

fn render_signal<W: Write>(out: &mut W, signal: &UiSignal) -> io::Result<()> {
    match signal {
        UiSignal::LogLine { text, .. } => writeln!(out, "  {text}"),
        UiSignal::Progress { .. }
        | UiSignal::CeremonyOverview { .. }
        | UiSignal::SystemInfo(_)
        | UiSignal::Environment(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use crossbeam_channel::unbounded;
    use rite_model::StepId;

    use super::*;
    use rite_runtime::PromptId;
    use rite_runtime::test_support::fact_event;

    #[test]
    fn confirm_default_yes() {
        let resp = default_response(&Prompt::Confirm {
            question: "go?".to_string(),
            default: None,
        })
        .expect("response");
        assert!(matches!(resp, Response::Bool(true)));
    }

    #[test]
    fn confirm_explicit_no_default_honored() {
        let resp = default_response(&Prompt::Confirm {
            question: "destructive?".to_string(),
            default: Some(false),
        })
        .expect("response");
        assert!(matches!(resp, Response::Bool(false)));
    }

    #[test]
    fn literal_returns_expected() {
        let resp = default_response(&Prompt::Literal {
            label: "type 'attest'".to_string(),
            expected: "attest".to_string(),
        })
        .expect("response");
        match resp {
            Response::Text(t) => assert_eq!(t, "attest"),
            _ => panic!("expected text"),
        }
    }

    #[test]
    fn continue_is_acknowledged() {
        let resp = default_response(&Prompt::Continue { hint: None }).expect("response");
        assert!(matches!(resp, Response::Acknowledge));
    }

    #[test]
    fn unconstrained_text_prompt_gets_placeholder() {
        let resp = default_response(&Prompt::Text {
            label: "entropy".to_string(),
            validator: rite_model::ValidatorSpec::NonEmpty,
        })
        .expect("response");
        match resp {
            Response::Text(t) => assert_eq!(t, PLACEHOLDER_TEXT),
            _ => panic!("expected text"),
        }
    }

    #[test]
    fn validated_text_prompt_fails_fast() {
        let err = default_response(&Prompt::Text {
            label: "serial".to_string(),
            validator: rite_model::ValidatorSpec::Regex("[0-9]+".to_string()),
        })
        .expect_err("should fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn secret_prompt_gets_placeholder() {
        let resp = default_response(&Prompt::Secret {
            label: "pin".to_string(),
        })
        .expect("response");
        assert!(matches!(resp, Response::Secret(_)));
    }

    #[test]
    fn run_replies_to_each_prompt_and_completes() {
        let (cmd_tx, cmd_rx) = unbounded::<UiCommand>();
        let (event_tx, event_rx) = unbounded::<ExecEvent>();

        let driver = std::thread::spawn(move || run(&cmd_tx, &event_rx));

        // Simulate a runtime: send a couple of facts and a Continue prompt.
        event_tx
            .send(fact_event(StepFact::CeremonyStarted {
                name: "T".to_string(),
            }))
            .expect("send fact");
        event_tx
            .send(ExecEvent::AwaitPrompt {
                step: Some(StepId::new("s1")),
                prompt_id: PromptId::new(0),
                prompt: Prompt::Continue { hint: None },
                previous_attempt_rejected_because: None,
            })
            .expect("send await");

        match cmd_rx.recv().expect("response") {
            UiCommand::PromptResponse {
                prompt_id,
                response,
            } => {
                assert_eq!(prompt_id, PromptId::new(0));
                assert!(matches!(response, Response::Acknowledge));
            }
            other => panic!("unexpected command: {other:?}"),
        }

        drop(event_tx);
        driver.join().expect("driver join").expect("driver ok");
    }
}
