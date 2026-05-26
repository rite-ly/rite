//! Pure `update(model, msg) -> Vec<Cmd>`.
//!
//! The only function in the crate allowed to mutate the model. No I/O,
//! no terminal access, no thread spawning, everything that touches the
//! outside world is returned as a [`Cmd`] for the runtime loop to
//! interpret.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use rite_model::{Prompt, StepFact};
use rite_runtime::{
    ExecEvent, PromptId, Response, UiCommand, UiSignal, fact_summary, signal_summary,
};

use crate::model::{
    DEVIATION_INPUT_MAX, DeviationView, LogLine, Model, PendingPrompt, RunningState, Screen,
    StepTab, StepView,
};
use crate::msg::{Cmd, Msg};

/// Number of ticks (each [`super::runtime::TICK_INTERVAL`] long,
/// 100ms today) between successive pops from the drip queue. `1`
/// gives ~100ms between log lines, which reads as a brisk type-out
/// for a burst of facts. Set to `0` to apply events immediately and
/// disable the effect.
const LOG_DRIP_TICKS: u64 = 1;

/// Apply a [`Msg`] to the model and return any side effects to perform.
pub fn update(model: &mut Model, msg: Msg) -> Vec<Cmd> {
    match msg {
        Msg::Tick => {
            model.tick = model.tick.wrapping_add(1);
            model.now = chrono::Local::now();
            if drip_due(model)
                && let Some(event) = model.pending_events.pop_front()
            {
                return handle_exec_event(model, event);
            }
            Vec::new()
        }
        Msg::Key(key) => handle_key(model, key),
        // Don't apply executor events directly: queue them so a burst of
        // facts from a single step types out one log line at a time.
        // `Msg::Tick` drains the queue at `LOG_DRIP_TICKS` cadence.
        Msg::Exec(event) => {
            model.pending_events.push_back(event);
            Vec::new()
        }
        // The forwarder sends Msg::Quit when the executor's channel
        // closes, which happens right after the terminal fact. Don't
        // tear the TUI down underneath the operator before they've
        // read the Completed/Failed screen; require an explicit key.
        Msg::Quit => {
            if model.screen.is_terminal() {
                Vec::new()
            } else {
                vec![Cmd::Quit]
            }
        }
        Msg::Resize { .. } | Msg::Mouse(_) => Vec::new(),
    }
}

/// Whether the current tick should drain one event from the drip queue.
fn drip_due(model: &Model) -> bool {
    if model.pending_events.is_empty() {
        return false;
    }
    LOG_DRIP_TICKS == 0 || model.tick.is_multiple_of(LOG_DRIP_TICKS)
}

fn handle_key(model: &mut Model, key: KeyEvent) -> Vec<Cmd> {
    // Global shortcuts first.
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
        // Ctrl+C is treated as a quit request, distinct from `q` (graceful)
        // and `a` (executor abort). Closes the channel; the executor will
        // see the disconnect and unwind.
        return vec![Cmd::Quit];
    }

    // Per-screen routing. The order matters: terminal screens take
    // precedence over modals, modals over the regular step screen.
    if model.screen.is_terminal() {
        return handle_terminal_key(key);
    }
    match &model.screen {
        Screen::DeviationModal { .. } => return handle_deviation_modal_key(model, key),
        Screen::AbortConfirm => return handle_abort_confirm_key(model, key),
        _ => {}
    }

    // Tab and scroll keys take precedence over the pending prompt: the
    // operator must be able to look back at history mid-prompt without
    // first answering it. Both tabs share the same `log_scroll` so the
    // view position carries across when switching with Tab.
    if matches!(key.code, KeyCode::Tab)
        && let Screen::Step { tab } = &mut model.screen
    {
        *tab = match *tab {
            StepTab::Ceremony => StepTab::Deviations,
            StepTab::Deviations => StepTab::Ceremony,
        };
        return Vec::new();
    }
    if matches!(
        &model.screen,
        Screen::Step {
            tab: StepTab::Ceremony
        }
    ) && handle_log_scroll(model, key.code)
    {
        return Vec::new();
    }

    // Prompt routing only fires on the Ceremony tab. On the Deviations
    // tab the prompt is paused; the operator switches back via Tab to
    // answer.
    if model.pending_prompt.is_some()
        && matches!(
            &model.screen,
            Screen::Step {
                tab: StepTab::Ceremony
            }
        )
    {
        return handle_prompt_key(model, key);
    }

    // Default key bindings on the step screen.
    match key.code {
        KeyCode::Char('q') => vec![Cmd::Quit],
        KeyCode::Char('a') | KeyCode::Esc => {
            model.open_modal(Screen::AbortConfirm);
            Vec::new()
        }
        KeyCode::Char('d') => {
            model.open_modal(Screen::DeviationModal {
                input: String::new(),
            });
            Vec::new()
        }
        _ => Vec::new(),
    }
}

/// Coarse page step for `PgUp` / `PgDn` on the Log tab. The view's actual
/// height isn't visible from `update`; ten lines is a usable default for
/// the terminal sizes we care about.
const LOG_PAGE_STEP: usize = 10;

/// Handle Log-tab scroll keys. Returns `true` if the key was consumed.
fn handle_log_scroll(model: &mut Model, code: KeyCode) -> bool {
    match code {
        KeyCode::Up => {
            let max = model.log.len();
            model.log_scroll = model.log_scroll.saturating_add(1).min(max);
            true
        }
        KeyCode::Down => {
            model.log_scroll = model.log_scroll.saturating_sub(1);
            true
        }
        KeyCode::PageUp => {
            let max = model.log.len();
            model.log_scroll = model.log_scroll.saturating_add(LOG_PAGE_STEP).min(max);
            true
        }
        KeyCode::PageDown => {
            model.log_scroll = model.log_scroll.saturating_sub(LOG_PAGE_STEP);
            true
        }
        KeyCode::Home => {
            model.log_scroll = model.log.len();
            true
        }
        KeyCode::End => {
            model.log_scroll = 0;
            true
        }
        _ => false,
    }
}

fn handle_terminal_key(key: KeyEvent) -> Vec<Cmd> {
    match key.code {
        KeyCode::Char('q') | KeyCode::Enter | KeyCode::Esc => vec![Cmd::Quit],
        _ => Vec::new(),
    }
}

fn handle_deviation_modal_key(model: &mut Model, key: KeyEvent) -> Vec<Cmd> {
    // Borrow input through the screen variant; only this screen has it.
    let Screen::DeviationModal { input } = &mut model.screen else {
        return Vec::new();
    };
    match key.code {
        KeyCode::Esc => {
            model.close_modal();
            Vec::new()
        }
        KeyCode::Char(c) => {
            if input.len() < DEVIATION_INPUT_MAX {
                input.push(c);
            }
            Vec::new()
        }
        KeyCode::Backspace => {
            input.pop();
            Vec::new()
        }
        KeyCode::Enter => {
            if input.trim().is_empty() {
                return Vec::new();
            }
            let text = std::mem::take(input);
            model.close_modal();
            // No optimistic local push: the runtime echoes a
            // `DeviationRecorded` fact (handled in `handle_fact`) and
            // that single source keeps the list in sync with the
            // transcript without producing a duplicate.
            vec![Cmd::SendCommand(UiCommand::LogDeviation { text })]
        }
        _ => Vec::new(),
    }
}

fn handle_abort_confirm_key(model: &mut Model, key: KeyEvent) -> Vec<Cmd> {
    match key.code {
        KeyCode::Char('y' | 'Y') => {
            model.running = RunningState::Aborting;
            model.close_modal();
            vec![Cmd::SendCommand(UiCommand::Abort)]
        }
        KeyCode::Char('n' | 'N') | KeyCode::Esc => {
            model.close_modal();
            Vec::new()
        }
        _ => Vec::new(),
    }
}

/// Decision computed from a single key event when a prompt is pending.
///
/// Two-step shape (decide → apply) avoids holding a mutable borrow on
/// `pending_prompt` across calls that need mutable access to the model.
enum PromptAction {
    SubmitBool(bool),
    SubmitText,
    SubmitSecret,
    SubmitAcknowledge,
    PushChar(char),
    Backspace,
    Ignore,
}

fn handle_prompt_key(model: &mut Model, key: KeyEvent) -> Vec<Cmd> {
    use PromptAction as Action;

    // Esc during a pending prompt is the universal "I want out" escape
    // hatch, open the abort-confirm modal. The pending prompt stays
    // installed; the operator can press `n` to back out and resume.
    if matches!(key.code, KeyCode::Esc) {
        model.open_modal(Screen::AbortConfirm);
        return Vec::new();
    }

    let action = {
        let Some(pending) = model.pending_prompt.as_ref() else {
            return Vec::new();
        };
        match &pending.prompt {
            Prompt::Confirm { default, .. } => match key.code {
                KeyCode::Char('y' | 'Y') => Action::SubmitBool(true),
                KeyCode::Char('n' | 'N') => Action::SubmitBool(false),
                KeyCode::Enter => Action::SubmitBool(default.unwrap_or(true)),
                _ => Action::Ignore,
            },
            Prompt::Continue { .. } => match key.code {
                KeyCode::Enter | KeyCode::Char(' ') => Action::SubmitAcknowledge,
                _ => Action::Ignore,
            },
            Prompt::Text { .. } | Prompt::Literal { .. } => match key.code {
                KeyCode::Char(c) => Action::PushChar(c),
                KeyCode::Backspace => Action::Backspace,
                KeyCode::Enter => Action::SubmitText,
                _ => Action::Ignore,
            },
            Prompt::Secret { .. } => match key.code {
                KeyCode::Char(c) => Action::PushChar(c),
                KeyCode::Backspace => Action::Backspace,
                KeyCode::Enter => Action::SubmitSecret,
                _ => Action::Ignore,
            },
            _ => Action::Ignore,
        }
    };

    match action {
        Action::SubmitBool(b) => send_response(model, Response::Bool(b)),
        Action::SubmitAcknowledge => send_response(model, Response::Acknowledge),
        Action::SubmitText => {
            let value = model
                .pending_prompt
                .as_mut()
                .map(|p| std::mem::take(&mut p.input))
                .unwrap_or_default();
            send_response(model, Response::Text(value))
        }
        Action::SubmitSecret => {
            let value = model
                .pending_prompt
                .as_mut()
                .map(|p| std::mem::take(&mut p.input))
                .unwrap_or_default();
            send_response(model, Response::Secret(secrecy::SecretString::from(value)))
        }
        Action::PushChar(c) => {
            if let Some(pending) = model.pending_prompt.as_mut() {
                pending.input.push(c);
            }
            Vec::new()
        }
        Action::Backspace => {
            if let Some(pending) = model.pending_prompt.as_mut() {
                pending.input.pop();
            }
            Vec::new()
        }
        Action::Ignore => Vec::new(),
    }
}

fn send_response(model: &mut Model, response: Response) -> Vec<Cmd> {
    let Some(pending) = model.pending_prompt.take() else {
        return Vec::new();
    };
    vec![Cmd::SendCommand(UiCommand::PromptResponse {
        prompt_id: pending.prompt_id,
        response,
    })]
}

fn handle_exec_event(model: &mut Model, event: ExecEvent) -> Vec<Cmd> {
    match event {
        ExecEvent::Fact(fact) => handle_fact(model, &fact),
        ExecEvent::Signal(signal) => handle_signal(model, &signal),
        ExecEvent::AwaitPrompt {
            prompt_id,
            prompt,
            previous_attempt_rejected_because,
            ..
        } => {
            install_prompt(model, prompt_id, prompt, previous_attempt_rejected_because);
            Vec::new()
        }
        ExecEvent::Finalized { fingerprint } => {
            if let Screen::Completed {
                fingerprint: fp, ..
            } = &mut model.screen
            {
                *fp = Some(fingerprint);
            }
            Vec::new()
        }
    }
}

fn install_prompt(
    model: &mut Model,
    prompt_id: PromptId,
    prompt: Prompt,
    rejection: Option<String>,
) {
    model.pending_prompt = Some(PendingPrompt {
        prompt_id,
        prompt,
        input: String::new(),
        rejection,
    });
}

fn handle_fact(model: &mut Model, fact: &StepFact) -> Vec<Cmd> {
    // Model-specific side-effects first (header, dividers, screen
    // transitions, deviation list). The log feed is fed afterwards from
    // the shared `fact_summary`, so the live log mirrors the console
    // driver line-for-line, except for StepStarted which the divider
    // already represents.
    match fact {
        StepFact::CeremonyStarted { name, .. } => {
            model.ceremony_name = Some(name.clone());
        }
        StepFact::ActStarted { label, .. } => {
            model.push_log(LogLine::ActDivider {
                label: label.clone(),
            });
        }
        StepFact::StepStarted {
            id,
            label,
            role_name,
            ..
        } => {
            model.push_log(LogLine::StepDivider {
                label: label.clone(),
                role_name: role_name.clone(),
            });
            model.current_step = Some(StepView {
                id: id.clone(),
                label: label.clone(),
                role_name: role_name.clone(),
            });
            model.pending_prompt = None;
        }
        StepFact::StepCompleted { .. } => {
            model.pending_prompt = None;
        }
        StepFact::DeviationRecorded { step, text, at } => {
            model.deviations.push(DeviationView {
                step: Some(step.clone()),
                text: text.clone(),
                at: at.with_timezone(&chrono::Local),
            });
        }
        StepFact::CeremonyCompleted { .. } => {
            model.screen = Screen::Completed { fingerprint: None };
            model.running = RunningState::Done;
        }
        StepFact::CeremonyFailed { error, .. } => {
            model.screen = Screen::Failed {
                reason: error.message.clone(),
            };
            model.running = RunningState::Done;
        }
        _ => {}
    }

    // Mirror the console driver's line in the log feed. Skip the facts
    // that already get a dedicated visual divider so we don't echo them
    // as a plain log line right after the divider.
    if !matches!(
        fact,
        StepFact::StepStarted { .. } | StepFact::ActStarted { .. }
    ) && let Some((icon, text)) = fact_summary(fact)
    {
        model.push_entry(icon, text);
    }

    Vec::new()
}

fn handle_signal(model: &mut Model, signal: &UiSignal) -> Vec<Cmd> {
    if let Some((icon, text)) = signal_summary(signal) {
        model.push_entry(icon, text);
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use rite_model::StepId;

    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::empty())
    }

    /// Push an exec event and drain it from the drip queue with a tick
    /// so unit tests don't have to drive both messages explicitly.
    fn apply_exec(model: &mut Model, event: ExecEvent) -> Vec<Cmd> {
        let _ = update(model, Msg::Exec(event));
        update(model, Msg::Tick)
    }

    #[test]
    fn tick_advances_frame_counter() {
        let mut model = Model::new();
        let cmds = update(&mut model, Msg::Tick);
        assert!(cmds.is_empty());
        assert_eq!(model.tick, 1);
    }

    #[test]
    fn quit_returns_cmd_quit() {
        let mut model = Model::new();
        let cmds = update(&mut model, Msg::Key(key(KeyCode::Char('q'))));
        assert!(matches!(cmds.as_slice(), [Cmd::Quit]));
    }

    #[test]
    fn pressing_a_opens_abort_confirm_modal_without_aborting_yet() {
        let mut model = Model::new();
        let cmds = update(&mut model, Msg::Key(key(KeyCode::Char('a'))));
        assert!(cmds.is_empty());
        assert!(matches!(model.screen, Screen::AbortConfirm));
        assert!(matches!(model.running, RunningState::Active));
    }

    #[test]
    fn abort_confirm_yes_sends_abort_and_closes_modal() {
        let mut model = Model::new();
        // Open the modal.
        let _ = update(&mut model, Msg::Key(key(KeyCode::Char('a'))));
        // Confirm.
        let cmds = update(&mut model, Msg::Key(key(KeyCode::Char('y'))));
        assert!(matches!(model.running, RunningState::Aborting));
        assert!(matches!(
            cmds.as_slice(),
            [Cmd::SendCommand(UiCommand::Abort)]
        ));
        assert!(matches!(model.screen, Screen::Step { .. }));
    }

    #[test]
    fn abort_confirm_no_cancels() {
        let mut model = Model::new();
        let _ = update(&mut model, Msg::Key(key(KeyCode::Char('a'))));
        let cmds = update(&mut model, Msg::Key(key(KeyCode::Char('n'))));
        assert!(cmds.is_empty());
        assert!(matches!(model.screen, Screen::Step { .. }));
        assert!(matches!(model.running, RunningState::Active));
    }

    #[test]
    fn deviation_modal_collects_input_then_submits_on_enter() {
        let mut model = Model::new();
        model.current_step = Some(StepView {
            id: StepId::new("step1"),
            label: "L".to_string(),
            role_name: "Operator".to_string(),
        });
        // Open the deviation modal.
        let _ = update(&mut model, Msg::Key(key(KeyCode::Char('d'))));
        assert!(matches!(model.screen, Screen::DeviationModal { .. }));
        // Type text.
        for c in "phone rang".chars() {
            let _ = update(&mut model, Msg::Key(key(KeyCode::Char(c))));
        }
        // Submit.
        let cmds = update(&mut model, Msg::Key(key(KeyCode::Enter)));
        match cmds.as_slice() {
            [Cmd::SendCommand(UiCommand::LogDeviation { text })] => {
                assert_eq!(text, "phone rang");
            }
            other => panic!("expected LogDeviation, got {other:?}"),
        }
        assert!(matches!(model.screen, Screen::Step { .. }));
        // The runtime's DeviationRecorded fact (echoed via Msg::Exec)
        // is the single source for the list; the modal submit does not
        // push locally. So the list stays empty until the fact arrives.
        assert!(model.deviations.is_empty());
    }

    #[test]
    fn deviation_modal_escape_cancels_without_emitting() {
        let mut model = Model::new();
        let _ = update(&mut model, Msg::Key(key(KeyCode::Char('d'))));
        let _ = update(&mut model, Msg::Key(key(KeyCode::Char('x'))));
        let cmds = update(&mut model, Msg::Key(key(KeyCode::Esc)));
        assert!(cmds.is_empty());
        assert!(matches!(model.screen, Screen::Step { .. }));
        assert!(model.deviations.is_empty());
    }

    #[test]
    fn deviation_modal_empty_input_does_not_submit() {
        let mut model = Model::new();
        let _ = update(&mut model, Msg::Key(key(KeyCode::Char('d'))));
        let cmds = update(&mut model, Msg::Key(key(KeyCode::Enter)));
        assert!(cmds.is_empty());
        // Still in the modal.
        assert!(matches!(model.screen, Screen::DeviationModal { .. }));
    }

    #[test]
    fn step_started_pushes_a_divider_into_the_log_feed() {
        let mut model = Model::new();
        let _ = apply_exec(
            &mut model,
            ExecEvent::Fact(StepFact::StepStarted {
                id: StepId::new("s1"),
                label: "2.1".to_string(),
                role: rite_model::RoleId::new("crypto_officer"),
                role_name: "Crypto Officer".to_string(),
                started_at: Utc::now(),
            }),
        );
        assert!(matches!(model.screen, Screen::Step { .. }));
        match model.log.front() {
            Some(LogLine::StepDivider { label, role_name }) => {
                assert_eq!(label, "2.1");
                assert_eq!(role_name, "Crypto Officer");
            }
            other => panic!("expected StepDivider, got {other:?}"),
        }
    }

    #[test]
    fn tab_switches_step_tabs() {
        let mut model = Model::new();
        let _ = update(&mut model, Msg::Key(key(KeyCode::Tab)));
        assert!(matches!(
            model.screen,
            Screen::Step {
                tab: StepTab::Deviations
            }
        ));
        let _ = update(&mut model, Msg::Key(key(KeyCode::Tab)));
        assert!(matches!(
            model.screen,
            Screen::Step {
                tab: StepTab::Ceremony
            }
        ));
    }

    #[test]
    fn step_started_installs_current_step() {
        let mut model = Model::new();
        let fact = StepFact::StepStarted {
            id: StepId::new("s1"),
            label: "Step One".to_string(),
            role: rite_model::RoleId::new("op"),
            role_name: "Operator".to_string(),
            started_at: Utc::now(),
        };
        let _ = apply_exec(&mut model, ExecEvent::Fact(fact));
        let s = model.current_step.expect("current step");
        assert_eq!(s.id, StepId::new("s1"));
        assert_eq!(s.label, "Step One");
    }

    #[test]
    fn confirm_y_responds_with_true() {
        let mut model = Model::new();
        install_prompt(
            &mut model,
            PromptId::new(1),
            Prompt::Confirm {
                question: "ok?".to_string(),
                default: None,
            },
            None,
        );
        let cmds = update(&mut model, Msg::Key(key(KeyCode::Char('y'))));
        match cmds.as_slice() {
            [
                Cmd::SendCommand(UiCommand::PromptResponse {
                    prompt_id,
                    response: Response::Bool(true),
                }),
            ] => assert_eq!(*prompt_id, PromptId::new(1)),
            _ => panic!("expected Bool(true) response"),
        }
        assert!(model.pending_prompt.is_none());
    }

    #[test]
    fn text_prompt_collects_input_then_sends_on_enter() {
        let mut model = Model::new();
        install_prompt(
            &mut model,
            PromptId::new(2),
            Prompt::Text {
                label: "name".to_string(),
                validator: rite_model::ValidatorSpec::NonEmpty,
            },
            None,
        );
        for c in "Alice".chars() {
            let _ = update(&mut model, Msg::Key(key(KeyCode::Char(c))));
        }
        let cmds = update(&mut model, Msg::Key(key(KeyCode::Enter)));
        match cmds.as_slice() {
            [
                Cmd::SendCommand(UiCommand::PromptResponse {
                    response: Response::Text(t),
                    ..
                }),
            ] => assert_eq!(t, "Alice"),
            _ => panic!("expected Text response"),
        }
    }

    #[test]
    fn ceremony_completed_then_finalized_populates_fingerprint() {
        let mut model = Model::new();
        let fact = StepFact::CeremonyCompleted {
            completed_at: Utc::now(),
        };
        let _ = apply_exec(&mut model, ExecEvent::Fact(fact));
        assert!(matches!(
            model.screen,
            Screen::Completed {
                fingerprint: None,
                ..
            }
        ));
        assert!(matches!(model.running, RunningState::Done));

        let _ = apply_exec(
            &mut model,
            ExecEvent::Finalized {
                fingerprint: "sha256:abc".to_string(),
            },
        );
        match &model.screen {
            Screen::Completed {
                fingerprint: Some(fp),
                ..
            } => assert_eq!(fp, "sha256:abc"),
            other => panic!("expected fingerprinted Completed, got {other:?}"),
        }
    }

    #[test]
    fn exec_event_queues_until_next_tick() {
        let mut model = Model::new();
        let signal = UiSignal::LogLine {
            step: None,
            icon: rite_runtime::Icon::Info,
            text: "queued".to_string(),
        };
        // Msg::Exec alone leaves the log empty and the queue non-empty.
        let _ = update(&mut model, Msg::Exec(ExecEvent::Signal(signal)));
        assert!(model.log.is_empty());
        assert_eq!(model.pending_events.len(), 1);

        // The next Tick drains one event.
        let _ = update(&mut model, Msg::Tick);
        assert!(model.pending_events.is_empty());
        assert_eq!(model.log.len(), 1);
    }

    #[test]
    fn log_signal_pushes_log_line() {
        let mut model = Model::new();
        let signal = UiSignal::LogLine {
            step: None,
            icon: rite_runtime::Icon::Info,
            text: "hi".to_string(),
        };
        let _ = apply_exec(&mut model, ExecEvent::Signal(signal));
        assert_eq!(model.log.len(), 1);
        match model.log.front() {
            Some(LogLine::Entry { text, .. }) => assert_eq!(text, "hi"),
            other => panic!("expected Entry, got {other:?}"),
        }
    }
}
