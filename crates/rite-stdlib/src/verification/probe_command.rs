//! Running a system tool for a probe.
//!
//! Every probe that runs a tool goes through [`run_probe`], so the rules hold
//! in one place:
//!
//! - **Absolute path, no shell.** The caller names the binary by its full
//!   path, never through the inherited `PATH`, where a shim could forge the
//!   evidence; any other path is refused. Arguments go to the program as
//!   they are.
//! - **Empty environment, C locale.** The tool gets no copy of a secret held
//!   in an environment variable, no `LD_PRELOAD`, and prints the English
//!   labels the parsers expect.
//! - **No terminal.** Stdin is empty and stderr discarded, so the tool never
//!   reads from or writes to the terminal the TUI holds.
//! - **A deadline.** A tool that hangs (a stuck daemon behind
//!   `system_profiler`) is killed, and the probe reads unknown instead of
//!   holding up the run.
//!
//! Unix only: on Windows, an empty environment loses `SystemRoot`, which
//! many system tools need, and their output follows the display language,
//! not `LC_ALL`.

use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// How long a tool may run. Most answer in milliseconds; `system_profiler`
/// takes 0.2 s once warm, and several seconds on a first call after boot.
const TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for a killed tool to go. One stuck in the kernel does not
/// die, and must not hold up the run either.
const REAP: Duration = Duration::from_millis(100);

/// How often to check whether the tool has exited.
const POLL: Duration = Duration::from_millis(10);

/// The standard output of `program` run with `args`, when it exits with
/// success within the deadline. `None` when `program` is not an absolute
/// path, or when it cannot start, fails, or runs past the deadline (it is
/// then killed).
pub(super) fn run_probe(program: &str, args: &[&str]) -> Option<String> {
    run_with_timeout(program, args, TIMEOUT)
}

fn run_with_timeout(program: &str, args: &[&str], timeout: Duration) -> Option<String> {
    // A bare name would be looked up in the inherited `PATH`.
    if !Path::new(program).is_absolute() {
        return None;
    }
    let deadline = Instant::now().checked_add(timeout)?;
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let finished = read_stdout(&mut child, deadline)
        .and_then(|stdout| Some((stdout, wait_until(&mut child, deadline)?)));
    let Some((stdout, status)) = finished else {
        // A kill fails only when the tool has exited.
        let _ = child.kill();
        let _ = Instant::now()
            .checked_add(REAP)
            .map(|reap| wait_until(&mut child, reap));
        return None;
    };
    status
        .success()
        .then(|| String::from_utf8_lossy(&stdout).into_owned())
}

/// Everything the child writes to stdout, read on a thread of its own: the
/// child blocks once the pipe is full, and a child that keeps it open past
/// the deadline must not block the caller. `None` past the deadline, on a
/// read error, or when the thread cannot start; a thread left behind ends
/// when the pipe closes.
fn read_stdout(child: &mut Child, deadline: Instant) -> Option<Vec<u8>> {
    let mut stdout = child.stdout.take()?;
    let (sender, receiver) = mpsc::channel();
    std::thread::Builder::new()
        .spawn(move || {
            let mut buffer = Vec::new();
            let read = stdout.read_to_end(&mut buffer).map(|_| buffer);
            // The caller may have given up already.
            let _ = sender.send(read);
        })
        .ok()?;
    receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .ok()?
        .ok()
}

/// The exit status of the child, when it exits before the deadline.
fn wait_until(child: &mut Child, deadline: Instant) -> Option<ExitStatus> {
    loop {
        if let Some(status) = child.try_wait().ok()? {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(POLL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_output_of_a_successful_tool() {
        assert_eq!(
            run_probe("/bin/echo", &["a", "b c"]).as_deref(),
            Some("a b c\n")
        );
    }

    #[test]
    fn a_failing_or_missing_tool_reads_none() {
        assert_eq!(run_probe("/bin/sh", &["-c", "echo out; exit 3"]), None);
        assert_eq!(run_probe("/nonexistent/tool", &[]), None);
    }

    #[test]
    fn a_relative_path_or_a_bare_name_is_refused() {
        // `echo` is on every `PATH`; a relative path depends on the working
        // directory. Neither is run.
        assert_eq!(run_probe("echo", &["x"]), None);
        assert_eq!(run_probe("bin/echo", &["x"]), None);
    }

    #[test]
    fn the_environment_is_cleared_but_the_locale() {
        let output = run_probe("/bin/sh", &["-c", "echo \"[$LC_ALL][$HOME][$USER]\""]);
        assert_eq!(output.as_deref(), Some("[C][][]\n"));
    }

    #[test]
    fn stdin_is_empty() {
        assert_eq!(run_probe("/bin/cat", &[]).as_deref(), Some(""));
    }

    #[test]
    fn a_tool_past_the_deadline_is_killed() {
        let start = Instant::now();
        let output = run_with_timeout("/bin/sleep", &["10"], Duration::from_millis(200));
        assert_eq!(output, None);
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_tool_that_closes_stdout_but_keeps_running_is_killed() {
        let start = Instant::now();
        let output = run_with_timeout(
            "/bin/sh",
            &["-c", "exec >&-; sleep 10"],
            Duration::from_millis(200),
        );
        assert_eq!(output, None);
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}
