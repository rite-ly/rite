//! Interactive terminal frontend for Rite ceremonies, built on
//! [`ratatui`] and shaped as a TEA (The Elm Architecture) application.
//!
//! The crate exposes a single entry point, [`run`], that the CLI invokes
//! after spawning the executor thread. Inside, the loop merges three
//! input sources into a single [`Msg`] stream:
//!
//! - keyboard / resize events from `crossterm`
//! - executor events from the runtime channel
//! - timer ticks for spinner animation
//!
//! `update(model, msg)` is pure and the only place state changes; it
//! returns a list of [`Cmd`]s the runtime interprets (sending commands
//! back to the executor, quitting). `view(model, frame)` is pure and the
//! only place rendering happens.

#![warn(missing_docs)]

mod model;
mod msg;
mod runtime;
mod update;
mod view;

pub use model::{Model, RunningState, Screen, StepTab};
pub use msg::{Cmd, Msg};
pub use runtime::run;
