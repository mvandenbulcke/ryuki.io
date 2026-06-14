//! Shared command execution helper with subprocess timeout.
//!
//! # Why not `.output()`?
//! `Command::output()` has no timeout — a hung child blocks the calling thread
//! forever. It also has a pipe-buffer deadlock risk: if both stdout and stderr
//! fill their OS-level pipe buffers before the parent reads them, the child
//! blocks writing, the parent blocks waiting, and both hang.
//!
//! # Approach
//! 1. `spawn()` the child (pipes attached).
//! 2. Drain stdout and stderr concurrently in two reader threads so the child
//!    is never blocked by a full pipe.
//! 3. `child.wait_timeout(duration)` — on `Some(status)` the child exited in
//!    time; join the reader threads and assemble `Output`.
//! 4. On `None` (timeout) — kill the child, reap it (prevent zombie), return
//!    `Err(RunnerError::Timeout)`.

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use ryuki_engine::runners::RunnerError;
use wait_timeout::ChildExt;

/// Default timeout used for both terraform init+plan and ansible --check.
pub const RUNNER_TIMEOUT: Duration = Duration::from_secs(120);

/// Run `cmd` to completion, collecting stdout+stderr into an `Output`.
///
/// Returns `Err(RunnerError::Timeout)` if the child does not exit within
/// `timeout`. On timeout the child is killed before returning.
///
/// # Deadlock safety
/// Both stdout and stderr are drained in background threads. The parent never
/// holds the pipe handles open while waiting for the child to exit, so the
/// pipe buffers cannot fill and block the child.
pub fn run_command_with_timeout(
    mut cmd: Command,
    timeout: Duration,
) -> Result<Output, RunnerError> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| RunnerError::Spawn(format!("spawn: {e}")))?;

    // Take the pipe handles out of the Child before handing the child to the
    // wait thread, so the reader threads can drain independently.
    let stdout_pipe = child.stdout.take().expect("stdout was piped");
    let stderr_pipe = child.stderr.take().expect("stderr was piped");

    // Drain stdout and stderr concurrently.
    let stdout_thread = std::thread::spawn(move || -> Vec<u8> { read_all(stdout_pipe) });
    let stderr_thread = std::thread::spawn(move || -> Vec<u8> { read_all(stderr_pipe) });

    match child
        .wait_timeout(timeout)
        .map_err(|e| RunnerError::Spawn(format!("wait_timeout: {e}")))?
    {
        Some(status) => {
            // Child exited in time — join reader threads (they will have
            // finished by now because the pipes are closed on child exit).
            let stdout = stdout_thread.join().unwrap_or_default();
            let stderr = stderr_thread.join().unwrap_or_default();
            Ok(Output {
                status,
                stdout,
                stderr,
            })
        }
        None => {
            // Timeout — kill the child process and reap it to avoid a zombie.
            // We do NOT join the reader threads here: grandchild processes may
            // still hold the pipe write-ends open (e.g. `sleep 5` spawned by a
            // shell script), so `read_to_end` would block until they exit.
            // Joining the reader threads after timeout would defeat the purpose of
            // the timeout. We detach them — they are daemon-like background threads
            // and will terminate when the process ends (or when the grandchildren
            // eventually close the pipes). The captured output is discarded.
            let _ = child.kill();
            let _ = child.wait();
            // Reader thread handles are intentionally dropped here (detached).
            drop(stdout_thread);
            drop(stderr_thread);
            Err(RunnerError::Timeout)
        }
    }
}

fn read_all(mut reader: impl Read) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = reader.read_to_end(&mut buf);
    buf
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::workspace::Workspace;
    use std::os::unix::fs::PermissionsExt;

    fn write_script(ws: &Workspace, name: &str, content: &str) -> std::path::PathBuf {
        let path = ws.path().join(name);
        std::fs::write(&path, content).expect("write script");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod script");
        path
    }

    // ── Task 1 RED→GREEN: timeout kills child and returns Timeout ──

    /// A child that sleeps 5 s must be killed and return Timeout well before
    /// the sleep elapses when the timeout is 1 s.
    #[test]
    fn run_command_with_timeout_kills_slow_child() {
        let ws = Workspace::new().expect("workspace");
        let script = write_script(&ws, "slow.sh", "#!/bin/sh\nsleep 5\n");

        let start = std::time::Instant::now();
        let mut cmd = Command::new(&script);
        let result = run_command_with_timeout(cmd, Duration::from_secs(1));
        let elapsed = start.elapsed();

        assert!(
            matches!(result, Err(RunnerError::Timeout)),
            "expected Timeout, got {result:?}"
        );
        // Must return well under the 5 s sleep — give it up to 3 s for overhead.
        assert!(
            elapsed < Duration::from_secs(3),
            "timeout must return promptly; elapsed: {elapsed:?}"
        );
    }

    /// A child that exits immediately must succeed, not time out.
    #[test]
    fn run_command_with_timeout_fast_child_succeeds() {
        let ws = Workspace::new().expect("workspace");
        let script = write_script(&ws, "fast.sh", "#!/bin/sh\necho hello\nexit 0\n");

        let mut cmd = Command::new(&script);
        let result = run_command_with_timeout(cmd, Duration::from_secs(5));
        assert!(result.is_ok(), "fast child must succeed: {result:?}");
        let output = result.unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("hello"));
    }

    /// A child that writes a large amount to both stdout and stderr must not
    /// deadlock even with a short timeout headroom (drain threads prevent deadlock).
    #[test]
    fn run_command_with_timeout_no_deadlock_on_large_output() {
        // Write ~512 KiB to both stdout and stderr.
        let script = "#!/bin/sh\nyes x | head -c 524288; yes y | head -c 524288 >&2; exit 0\n";
        let ws = Workspace::new().expect("workspace");
        let path = write_script(&ws, "big.sh", script);

        let mut cmd = Command::new(&path);
        let result = run_command_with_timeout(cmd, Duration::from_secs(10));
        assert!(
            result.is_ok(),
            "large output child must not deadlock: {result:?}"
        );
    }

    /// A child that exits non-zero must return Ok with that exit code (timeout
    /// helper does not map exit codes — callers do that).
    #[test]
    fn run_command_with_timeout_non_zero_exit_ok() {
        let ws = Workspace::new().expect("workspace");
        let script = write_script(&ws, "fail.sh", "#!/bin/sh\nexit 42\n");

        let mut cmd = Command::new(&script);
        let output = run_command_with_timeout(cmd, Duration::from_secs(5))
            .expect("non-zero exit must be Ok, not Err");
        assert_eq!(output.status.code(), Some(42));
    }
}
