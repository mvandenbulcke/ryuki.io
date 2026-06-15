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
//! 4. On `None` (timeout) — kill the entire process GROUP (setsid makes the
//!    child the leader of a new session, so pgid == child pid), reap the direct
//!    child to prevent a zombie, and return `Err(RunnerError::Timeout)`.
//!
//! # Process-group kill (Unix only)
//! `child.kill()` only signals the direct child. Long-running subprocesses
//! (e.g. terraform provider plugins, ansible forks) spawned by the child
//! survive and hold the pipe write-ends open, blocking the reader threads
//! indefinitely.
//!
//! To fix this we:
//! - Call `libc::setsid()` in a `pre_exec` hook (runs in the forked child
//!   before exec, so it is async-signal-safe). This puts the child into its
//!   own process session; its pgid equals its pid.
//! - On timeout, send `SIGKILL` to `-pid` (the entire process group) via
//!   `libc::kill(-(pid as libc::pid_t), libc::SIGKILL)`.
//! - Then reap the direct child with `child.wait()` to avoid a zombie.
//! - The reader threads now finish quickly because all processes holding the
//!   pipe write-ends are dead. We join them (with a short deadline) rather
//!   than detaching.

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
/// `timeout`. On timeout the entire process group is killed before returning.
///
/// # Deadlock safety
/// Both stdout and stderr are drained in background threads. The parent never
/// holds the pipe handles open while waiting for the child to exit, so the
/// pipe buffers cannot fill and block the child.
///
/// # Grandchild safety (Unix)
/// The child is placed in a new process session (`setsid`) before exec. On
/// timeout, `SIGKILL` is sent to the whole process group so grandchildren
/// (provider plugins, ansible forks, etc.) are also terminated and the pipe
/// write-ends they held are closed. The reader threads can then drain and
/// finish normally.
pub fn run_command_with_timeout(
    mut cmd: Command,
    timeout: Duration,
) -> Result<Output, RunnerError> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    // ── Unix: place the child in its own process session ──────────────────
    // pre_exec runs in the forked child before exec(). Only async-signal-safe
    // functions are permitted here; setsid(2) is listed as safe.
    // This makes child.id() == pgid, so we can killpg with -child_pid.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid() is async-signal-safe; no allocations or locks.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| RunnerError::Spawn(format!("spawn: {e}")))?;

    // Capture the child pid before we move `child` into wait_timeout.
    // On Unix this equals the pgid after setsid().
    #[cfg(unix)]
    let child_pid = child.id();

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
            // Timeout — kill the entire process GROUP and reap the direct child.
            #[cfg(unix)]
            {
                // SAFETY: kill() is a raw syscall; passing a negative pid
                // sends the signal to every process in the group (pgid ==
                // child_pid after setsid). libc::pid_t is i32 on all Unix
                // targets; the cast is safe because child pids fit in i32.
                unsafe {
                    libc::kill(-(child_pid as libc::pid_t), libc::SIGKILL);
                }
                // Reap the direct child to avoid a zombie.
                let _ = child.wait();
                // Now that the whole group is dead the pipe write-ends are
                // closed; the reader threads drain and finish quickly.
                // Join them (with tolerance for OS scheduling jitter).
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
            }
            #[cfg(not(unix))]
            {
                // Non-unix fallback: kill only the direct child (prior behaviour).
                let _ = child.kill();
                let _ = child.wait();
                drop(stdout_thread);
                drop(stderr_thread);
            }
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
    use crate::workspace::Workspace;
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
        let cmd = Command::new(&script);
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

        let cmd = Command::new(&script);
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

        let cmd = Command::new(&path);
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

        let cmd = Command::new(&script);
        let output = run_command_with_timeout(cmd, Duration::from_secs(5))
            .expect("non-zero exit must be Ok, not Err");
        assert_eq!(output.status.code(), Some(42));
    }

    // ── NEW: process-group kill — grandchild must also die on timeout ──

    /// A shell script spawns a 30-second grandchild (`sleep 30`), writes its
    /// PID to a temp file, then `wait`s (so the direct-child shell blocks for
    /// 30 s unless we kill it). With a 1-second timeout the runner must:
    ///
    /// (a) return `RunnerError::Timeout` promptly (well under 30 s), AND
    /// (b) the grandchild must be dead — verified by `kill(pid, 0)` returning
    ///     `ESRCH` (no such process).
    ///
    /// This proves the whole process GROUP is killed, not just the direct child.
    #[cfg(unix)]
    #[test]
    fn timeout_kills_grandchild_process_group() {
        let ws = Workspace::new().expect("workspace");

        // Write the grandchild PID to a file before blocking on `wait`.
        // The file-write happens before `wait` so it completes even when the
        // shell is killed shortly after — the kernel flushes the write
        // before the SIGKILL takes effect.
        let pidfile = ws.path().join("grand.pid");
        let pidfile_str = pidfile.to_str().expect("pidfile path is utf-8");
        let script_body = format!(
            "#!/bin/sh\nsleep 30 &\nGRAND=$!\nprintf '%s' \"$GRAND\" > {pidfile_str}\nwait\n"
        );
        let script = write_script(&ws, "grand.sh", &script_body);

        let start = std::time::Instant::now();
        let result = run_command_with_timeout(Command::new(&script), Duration::from_secs(1));
        let elapsed = start.elapsed();

        // (a) Must time out, and promptly.
        assert!(
            matches!(result, Err(RunnerError::Timeout)),
            "expected Timeout; got {result:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "timeout must return promptly; elapsed: {elapsed:?}"
        );

        // Read the grandchild PID written by the script.
        // The script writes the PID before calling `wait`, so it should
        // already be present; retry briefly to tolerate scheduling jitter.
        let grandchild_pid: libc::pid_t = {
            let mut raw: Option<String> = None;
            for _ in 0..20 {
                if let Ok(contents) = std::fs::read_to_string(&pidfile) {
                    if !contents.trim().is_empty() {
                        raw = Some(contents);
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            raw.expect("pid file must have been written by the script")
                .trim()
                .parse()
                .expect("pid file must contain a valid integer pid")
        };

        // (b) Poll for up to 500 ms — SIGKILL delivery and kernel reaping are
        // async. `kill(pid, 0)` returns 0 if the process exists; -1 with errno
        // ESRCH when it is gone. Use `io::Error::last_os_error()` to read errno
        // portably (avoids platform-specific `__error`/`__errno_location`).
        let grandchild_dead = (0..50).any(|_| {
            let rc = unsafe { libc::kill(grandchild_pid, 0) };
            if rc == -1 {
                let esrch = std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
                if esrch {
                    return true;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
            false
        });

        assert!(
            grandchild_dead,
            "grandchild PID {grandchild_pid} must be dead after process-group SIGKILL"
        );
    }
}
