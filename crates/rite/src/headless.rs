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
        // Free-form text: a placeholder that satisfies the prompt's rule
        // where one can be built. A pattern can't be answered generically, so
        // it fails fast rather than being refused and asked again without end.
        Prompt::Text { label, validator } => placeholder(validator, PLACEHOLDER_TEXT)
            .map(Response::Text)
            .ok_or_else(|| cannot_answer("text", label)),
        Prompt::Secret { label, validator } => placeholder(validator, PLACEHOLDER_SECRET)
            .map(|value| Response::Secret(SecretString::from(value)))
            .ok_or_else(|| cannot_answer("secret", label)),
        _ => Err(io::Error::other(format!(
            "headless driver does not know how to handle prompt: {prompt:?}"
        ))),
    }
}

/// A fixed stand-in that satisfies the rule, if one can be built from it.
///
/// A format is answered with the format's own placeholder at its shortest
/// length, so a dry run walks through a PIN prompt the way it walks through
/// any other. What is typed there is never a real secret, so the value is
/// chosen to be obviously not one.
fn placeholder(validator: &ValidatorSpec, unconstrained: &str) -> Option<String> {
    match validator {
        ValidatorSpec::NonEmpty => Some(unconstrained.to_string()),
        ValidatorSpec::Format {
            format,
            min_length,
            max_length,
        } => format.placeholder(min_length.or(*max_length).unwrap_or(1).max(1)),
        // A pattern and a named predicate, and whatever the model adds next.
        _ => None,
    }
}

fn cannot_answer(kind: &str, label: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "headless driver cannot answer the validated {kind} prompt: '{label}'. \
             Use --frontend=console for an interactive run."
        ),
    )
}

fn render_fact<W: Write>(out: &mut W, fact: &StepFact) -> io::Result<()> {
    match fact {
        StepFact::CeremonyStarted { name, .. } => writeln!(out, "[ceremony] {name}"),
        StepFact::StepStarted { id, label, .. } => writeln!(out, "[step] {label} ({id})"),
        StepFact::StepCompleted { id, .. } => writeln!(out, "[step-done] {id}"),
        StepFact::CeremonyCompleted { .. } => writeln!(out, "[done]"),
        StepFact::CeremonyFailed { error, .. } => match error.class {
            rite_model::ErrorClass::Abort => writeln!(out, "[aborted] {}", error.message),
            _ => writeln!(out, "[failed] {}", error.message),
        },
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
    use secrecy::ExposeSecret;

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
            validator: rite_model::ValidatorSpec::NonEmpty,
        })
        .expect("response");
        assert!(matches!(resp, Response::Secret(_)));
    }

    #[test]
    fn formatted_secret_prompt_gets_a_placeholder_of_that_format() {
        for (format, min, max) in [
            (rite_model::Format::Digits, Some(6), Some(8)),
            (rite_model::Format::Base64, Some(32), None),
            (rite_model::Format::Hex, None, None),
        ] {
            let validator = rite_model::ValidatorSpec::Format {
                format,
                min_length: min,
                max_length: max,
            };
            let resp = default_response(&Prompt::Secret {
                label: "pin".to_string(),
                validator: validator.clone(),
            })
            .expect("response");
            let Response::Secret(value) = resp else {
                panic!("expected a secret");
            };
            assert!(validator.check(value.expose_secret()).is_ok(), "{format:?}");
        }
    }

    #[test]
    fn oversized_secret_prompt_fails_fast() {
        let err = default_response(&Prompt::Secret {
            label: "blob".to_string(),
            validator: rite_model::ValidatorSpec::Format {
                format: rite_model::Format::Text,
                min_length: Some(rite_model::PLACEHOLDER_LIMIT + 1),
                max_length: None,
            },
        })
        .expect_err("a stand-in that size is not built");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn patterned_secret_prompt_fails_fast() {
        let err = default_response(&Prompt::Secret {
            label: "pin".to_string(),
            validator: rite_model::ValidatorSpec::Regex("[0-9]{6}".to_string()),
        })
        .expect_err("a placeholder cannot satisfy a pattern");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
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
