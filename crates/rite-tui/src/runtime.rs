//! Main loop: terminal init, channel multiplexing, `update` → `view`.
//!
//! This is the only part of the crate that touches the terminal directly.
//! It owns the [`ratatui::Terminal`] instance, spawns the input and tick
//! threads, and interprets the [`Cmd`]s returned by [`update`].
//!
//! [`update`]: crate::update::update

use std::io;
use std::thread;
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender, unbounded};
use crossterm::event::{self, Event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use rite_runtime::{ExecEvent, UiCommand};

use crate::model::Model;
use crate::msg::{Cmd, Msg};
use crate::update::update;
use crate::view::view;

/// Tick interval driving spinner animation.
const TICK_INTERVAL: Duration = Duration::from_millis(100);

/// Crossterm polling interval. Must be short enough that the input
/// thread keeps the terminal responsive.
const INPUT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Drive the TUI against a pair of runtime channels.
///
/// Initializes the terminal in raw / alternate-screen mode, runs the
/// event loop until either the executor channel closes or the user
/// quits, and restores the terminal on exit (including on panic via the
/// `RawTerminalGuard`).
///
/// # Errors
///
/// Returns an I/O error if terminal initialization fails or the
/// channels disconnect unexpectedly.
pub fn run(cmd_tx: &Sender<UiCommand>, event_rx: Receiver<ExecEvent>) -> io::Result<()> {
    let _guard = RawTerminalGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let (msg_tx, msg_rx) = unbounded::<Msg>();
    spawn_input_thread(msg_tx.clone());
    spawn_tick_thread(msg_tx.clone());
    spawn_exec_forwarder(event_rx, msg_tx);

    let mut model = Model::new();
    terminal.draw(|frame| view(&model, frame))?;

    'main: loop {
        let Ok(msg) = msg_rx.recv() else { break 'main };
        let needs_redraw = !matches!(msg, Msg::Tick) || model.needs_animation();

        for cmd in update(&mut model, msg) {
            match cmd {
                Cmd::SendCommand(c) => {
                    if cmd_tx.send(c).is_err() {
                        break 'main;
                    }
                }
                Cmd::Quit => break 'main,
            }
        }

        if needs_redraw {
            terminal.draw(|frame| view(&model, frame))?;
        }
    }

    Ok(())
}

/// Reads crossterm input events and forwards them as [`Msg`]s.
fn spawn_input_thread(msg_tx: Sender<Msg>) {
    thread::spawn(move || {
        loop {
            // Poll so the thread can exit when the channel drops.
            match event::poll(INPUT_POLL_INTERVAL) {
                Ok(true) => {
                    let send_result = match event::read() {
                        Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                            msg_tx.send(Msg::Key(key))
                        }
                        Ok(Event::Resize(cols, rows)) => msg_tx.send(Msg::Resize { cols, rows }),
                        Ok(Event::Mouse(m)) => msg_tx.send(Msg::Mouse(m)),
                        _ => Ok(()),
                    };
                    if send_result.is_err() {
                        return;
                    }
                }
                Ok(false) => {}
                Err(_) => return,
            }
        }
    });
}

/// Periodic tick for spinner / time-driven redraws.
fn spawn_tick_thread(msg_tx: Sender<Msg>) {
    thread::spawn(move || {
        loop {
            thread::sleep(TICK_INTERVAL);
            if msg_tx.send(Msg::Tick).is_err() {
                return;
            }
        }
    });
}

/// Forwards each [`ExecEvent`] from the runtime as a [`Msg::Exec`].
///
/// Forwarding through `msg_tx` keeps the main loop's single-stream
/// invariant: one receiver, one `Msg` at a time.
fn spawn_exec_forwarder(event_rx: Receiver<ExecEvent>, msg_tx: Sender<Msg>) {
    thread::spawn(move || {
        while let Ok(event) = event_rx.recv() {
            if msg_tx.send(Msg::Exec(event)).is_err() {
                return;
            }
        }
        let _ = msg_tx.send(Msg::Quit);
    });
}

/// RAII guard that enters raw mode + alternate screen on construction
/// and restores the terminal on drop (including during panics).
struct RawTerminalGuard;

impl RawTerminalGuard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}
