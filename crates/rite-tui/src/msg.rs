//! `Msg` and `Cmd`, the inputs and outputs of `update`.

use crossterm::event::{KeyEvent, MouseEvent};
use rite_runtime::{ExecEvent, UiCommand};

/// Input to the pure [`update`] function.
///
/// Every state transition in the UI corresponds to exactly one `Msg`,
/// which makes the audit surface a single enum.
///
/// [`update`]: crate::update::update
#[derive(Debug)]
pub enum Msg {
    /// Key press from the terminal.
    Key(KeyEvent),
    /// Mouse event from the terminal (currently unused, reserved).
    Mouse(MouseEvent),
    /// Terminal resize.
    Resize {
        /// New width in cells.
        cols: u16,
        /// New height in cells.
        rows: u16,
    },
    /// Timer tick for spinners and time-driven redraws.
    Tick,
    /// Event from the runtime executor.
    Exec(ExecEvent),
    /// Explicit quit signal.
    Quit,
}

/// Side effect produced by [`update`]. The runtime loop interprets these
/// after every `update` call.
///
/// [`update`]: crate::update::update
#[derive(Debug)]
pub enum Cmd {
    /// Send a command back to the executor thread.
    SendCommand(UiCommand),
    /// Stop the loop.
    Quit,
}
