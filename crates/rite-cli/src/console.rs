//! Console frontend driver, consumes the runtime protocol on stdin/stdout.
//!
//! This is a straight-line loop, not a TEA application: events are printed
//! as they arrive, prompts read a response from stdin, and the only
//! out-of-band command we send back to the runtime is a prompt response.
//! Abort and deviation logging are not surfaced through this driver yet;
//! they belong to the TUI.
//!
//! The driver is intentionally minimal so it acts as the reference
//! implementation of the protocol, anyone porting another frontend
//! (headless, third-party TUI) can read this file to see the smallest
//! viable shape.
//!
//! # Output style
//!
//! Each [`ExecEvent::Fact`] and [`ExecEvent::Signal`] renders as a single
//! line with a leading icon. Facts that are mostly machine-readable
//! (`BackendOperation`, `ArtifactWritten`) are summarized in one line ,
//! the full structure lives in the JSONL transcript.
//!
//! # Errors
//!
//! Returns an error if stdin closes mid-prompt or the runtime channel
//! disconnects unexpectedly.

use std::io::{self, BufRead, Write};

use crossbeam_channel::{Receiver, Sender};
use secrecy::SecretString;

use rite_model::{Prompt, StepFact};
use rite_runtime::{
    ExecEvent, Icon, MaterialOverview, MaterialOverviewKind, Response, UiCommand, UiSignal,
    fact_summary, signal_summary,
};

/// Console glyph for an [`Icon`]. Owned by the frontend so the runtime
/// stays presentation-free.
fn glyph(icon: Icon) -> &'static str {
    match icon {
        Icon::Spinner => "⠋",
        Icon::Checkmark => "✓",
        Icon::Cross => "✗",
        // Info/Warning use ASCII so they align with ✓/✗ and never render as
        // emoji. The symbol forms (ℹ U+2139, ⚠ U+26A0) draw as double-width
        // colour emoji in some renderers (e.g. agg), and the circled/triangle
        // alternatives sit at a different cell width and misalign the column.
        Icon::Info => "i",
        Icon::Warning => "!",
    }
}

/// Run the console driver against a pair of runtime channels.
///
/// Blocks until the runtime closes the event channel.
///
/// # Errors
///
/// Returns an I/O error if stdin / stdout fail. Channel disconnects are
/// treated as normal end-of-run (the executor has finished).
pub fn run(cmd_tx: &Sender<UiCommand>, event_rx: &Receiver<ExecEvent>) -> io::Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    let stdin = io::stdin();
    let mut stdin = stdin.lock();

    while let Ok(event) = event_rx.recv() {
        match event {
            ExecEvent::Fact(fact) => render_fact(&mut stdout, &fact)?,
            ExecEvent::Signal(signal) => render_signal(&mut stdout, &signal)?,
            ExecEvent::Finalized { fingerprint } => {
                writeln!(
                    stdout,
                    "{} Transcript fingerprint: {fingerprint}",
                    glyph(Icon::Checkmark),
                )?;
            }
            ExecEvent::AwaitPrompt {
                prompt_id,
                prompt,
                previous_attempt_rejected_because,
                ..
            } => {
                if let Some(reason) = &previous_attempt_rejected_because {
                    writeln!(stdout, "{} {reason}", glyph(Icon::Warning))?;
                }
                let response = read_response(&mut stdin, &mut stdout, &prompt)?;
                if cmd_tx
                    .send(UiCommand::PromptResponse {
                        prompt_id,
                        response,
                    })
                    .is_err()
                {
                    // Runtime is gone; nothing more to do.
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}

fn render_fact<W: Write>(out: &mut W, fact: &StepFact) -> io::Result<()> {
    match fact_summary(fact) {
        Some((icon, text)) => writeln!(out, "{} {text}", glyph(icon)),
        None => Ok(()),
    }
}

/// One-line description of a declared material for the console feed.
/// Mirrors the TUI's Overview rendering at a coarser granularity.
fn material_summary(material: &MaterialOverview) -> String {
    let title = material.display_title();
    let kind = match &material.kind {
        MaterialOverviewKind::Digital => "digital".to_string(),
        MaterialOverviewKind::Physical {
            identifier,
            quantity,
        } => {
            let mut parts = vec!["physical".to_string()];
            if let Some(q) = quantity {
                parts.push(format!("x{q}"));
            }
            if let Some(id) = identifier {
                parts.push(id.clone());
            }
            parts.join(" ")
        }
        _ => "unknown".to_string(),
    };
    match &material.description {
        Some(desc) => format!("{title} ({kind}), {desc}"),
        None => format!("{title} ({kind})"),
    }
}

fn render_signal<W: Write>(out: &mut W, signal: &UiSignal) -> io::Result<()> {
    // The overview signal carries structured pre-ceremony metadata; print
    // it as a bulleted preamble so the operator sees the same context the
    // TUI shows on its Overview tab.
    if let UiSignal::CeremonyOverview {
        description,
        materials,
        step_count,
    } = signal
    {
        if let Some(desc) = description {
            writeln!(out, "  {desc}")?;
        }
        let step_noun = if *step_count == 1 { "step" } else { "steps" };
        writeln!(out, "  {step_count} {step_noun}")?;
        if !materials.is_empty() {
            writeln!(out, "  Materials:")?;
            for material in materials {
                writeln!(out, "    - {}", material_summary(material))?;
            }
        }
        return Ok(());
    }
    match signal_summary(signal) {
        Some((icon, text)) => writeln!(out, "{} {text}", glyph(icon)),
        None => Ok(()),
    }
}

fn read_response<R: BufRead, W: Write>(
    stdin: &mut R,
    stdout: &mut W,
    prompt: &Prompt,
) -> io::Result<Response> {
    match prompt {
        Prompt::Confirm { question, default } => {
            let suffix = match default {
                Some(true) => " [Y/n] ",
                Some(false) => " [y/N] ",
                None => " [y/n] ",
            };
            write!(stdout, "{question}{suffix}")?;
            stdout.flush()?;
            let line = read_line(stdin)?;
            let answered = match line.trim().to_lowercase().as_str() {
                "y" | "yes" => true,
                "" => default.unwrap_or(false),
                _ => false,
            };
            Ok(Response::Bool(answered))
        }
        Prompt::Text { label, .. } | Prompt::Literal { label, .. } => {
            write!(stdout, "{label}: ")?;
            stdout.flush()?;
            let line = read_line(stdin)?;
            Ok(Response::Text(line.trim().to_string()))
        }
        Prompt::Secret { label } => {
            let value = rpassword::prompt_password(format!("{label}: "))?;
            Ok(Response::Secret(SecretString::from(value)))
        }
        Prompt::Continue { hint } => {
            match hint {
                Some(h) => write!(stdout, "{h} ")?,
                None => write!(stdout, "Press Enter to continue… ")?,
            }
            stdout.flush()?;
            let _ = read_line(stdin)?;
            Ok(Response::Acknowledge)
        }
        // Unknown future variants: refuse with an io::Error so the
        // runtime sees the rejection and we don't silently misanswer.
        _ => Err(io::Error::other(format!(
            "console driver does not know how to handle prompt: {prompt:?}"
        ))),
    }
}

fn read_line<R: BufRead>(stdin: &mut R) -> io::Result<String> {
    let mut buf = String::new();
    let n = stdin.read_line(&mut buf)?;
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "stdin closed mid-prompt",
        ));
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use crossbeam_channel::unbounded;
    use rite_model::{ResponseRecord, StepId};

    use super::*;
    use rite_runtime::PromptId;

    #[test]
    fn renders_each_fact_kind_without_panicking() {
        let mut buf: Vec<u8> = Vec::new();
        let facts = vec![
            StepFact::CeremonyStarted {
                name: "T".to_string(),
                started_at: Utc::now(),
            },
            StepFact::StepStarted {
                id: StepId::new("a"),
                label: "Step A".to_string(),
                role: rite_model::RoleId::new("op"),
                role_name: "Operator".to_string(),
                started_at: Utc::now(),
            },
            StepFact::PromptAnswered {
                step: Some(StepId::new("a")),
                prompt: Prompt::Confirm {
                    question: "ok?".to_string(),
                    default: None,
                },
                response: ResponseRecord::Bool { value: true },
                at: Utc::now(),
            },
            StepFact::StepCompleted {
                id: StepId::new("a"),
                outcome: rite_model::StepOutcome::Completed {
                    message: "done".to_string(),
                },
                completed_at: Utc::now(),
            },
            StepFact::CeremonyCompleted {
                completed_at: Utc::now(),
            },
        ];
        for fact in &facts {
            render_fact(&mut buf, fact).expect("render");
        }
        let out = String::from_utf8(buf).expect("utf8");
        assert!(out.contains("Ceremony: T"));
        assert!(out.contains("Step Step A"));
        assert!(out.contains("done"));
    }

    #[test]
    fn confirm_prompt_with_yes_default_and_empty_input() {
        let mut stdin = std::io::Cursor::new(b"\n".to_vec());
        let mut stdout: Vec<u8> = Vec::new();
        let prompt = Prompt::Confirm {
            question: "go?".to_string(),
            default: Some(true),
        };
        let resp = read_response(&mut stdin, &mut stdout, &prompt).expect("response");
        assert!(matches!(resp, Response::Bool(true)));
        assert!(String::from_utf8(stdout).expect("utf8").contains("[Y/n]"));
    }

    #[test]
    fn text_prompt_round_trip() {
        let mut stdin = std::io::Cursor::new(b"Alice Smith\n".to_vec());
        let mut stdout: Vec<u8> = Vec::new();
        let prompt = Prompt::Text {
            label: "name".to_string(),
            validator: rite_model::ValidatorSpec::NonEmpty,
        };
        let resp = read_response(&mut stdin, &mut stdout, &prompt).expect("response");
        match resp {
            Response::Text(t) => assert_eq!(t, "Alice Smith"),
            _ => panic!("expected text"),
        }
    }

    #[test]
    fn continue_prompt_consumes_line_and_returns_acknowledge() {
        let mut stdin = std::io::Cursor::new(b"\n".to_vec());
        let mut stdout: Vec<u8> = Vec::new();
        let prompt = Prompt::Continue { hint: None };
        let resp = read_response(&mut stdin, &mut stdout, &prompt).expect("response");
        assert!(matches!(resp, Response::Acknowledge));
    }

    #[test]
    fn await_prompt_drives_one_response_round_trip() {
        let (cmd_tx, cmd_rx) = unbounded::<UiCommand>();
        let (event_tx, event_rx) = unbounded::<ExecEvent>();

        // Use a piped stdin via a fake by hand: we cannot easily inject
        // stdin into `run`, so we exercise the inner helpers separately.
        // Send only events the helper sees:
        let prompt_id = PromptId::new(7);
        event_tx
            .send(ExecEvent::Fact(StepFact::CeremonyStarted {
                name: "T".to_string(),
                started_at: Utc::now(),
            }))
            .expect("send fact");
        event_tx
            .send(ExecEvent::AwaitPrompt {
                step: Some(StepId::new("a")),
                prompt_id,
                prompt: Prompt::Continue { hint: None },
                previous_attempt_rejected_because: None,
            })
            .expect("send await");
        drop(event_tx);

        // Drain in a worker, replying to the prompt via a synthetic
        // sender on the cmd channel.
        let cmd_tx_clone = cmd_tx.clone();
        std::thread::spawn(move || {
            for event in &event_rx {
                if let ExecEvent::AwaitPrompt { prompt_id, .. } = event {
                    cmd_tx_clone
                        .send(UiCommand::PromptResponse {
                            prompt_id,
                            response: Response::Acknowledge,
                        })
                        .expect("send response");
                }
            }
        })
        .join()
        .expect("worker join");

        match cmd_rx.recv().expect("response") {
            UiCommand::PromptResponse {
                prompt_id: id,
                response,
            } => {
                assert_eq!(id, prompt_id);
                assert!(matches!(response, Response::Acknowledge));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }
}
