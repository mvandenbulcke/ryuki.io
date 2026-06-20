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

    let mut child =
        retry_on_etxtbsy(|| cmd.spawn()).map_err(|e| RunnerError::Spawn(format!("spawn: {e}")))?;

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

/// Retry a spawn-like operation on a transient ETXTBSY ("text file busy", os
/// error 26). When a runner execs a binary that was just written to disk, a
/// concurrent thread's `fork()` can transiently inherit a write fd to that file,
/// so the kernel refuses to exec it with ETXTBSY. The condition clears within
/// milliseconds once the sibling execs (its CLOEXEC fds close), so a short
/// bounded retry turns an intermittent spurious failure into a reliable spawn.
/// Non-ETXTBSY errors propagate immediately. Installed binaries
/// (terraform/ansible) never hit this, so in production the retry never fires.
pub(crate) fn retry_on_etxtbsy<T>(
    mut op: impl FnMut() -> std::io::Result<T>,
) -> std::io::Result<T> {
    const MAX_ATTEMPTS: u32 = 10;
    const BACKOFF: Duration = Duration::from_millis(20);
    let mut attempt = 1u32;
    loop {
        match op() {
            Ok(value) => return Ok(value),
            Err(error) if attempt < MAX_ATTEMPTS && is_etxtbsy(&error) => {
                attempt += 1;
                std::thread::sleep(BACKOFF);
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(unix)]
fn is_etxtbsy(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::ETXTBSY)
}

#[cfg(not(unix))]
fn is_etxtbsy(_error: &std::io::Error) -> bool {
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::Workspace;

    /// Writes `content` as a shell script in `ws` and returns a `Command` that
    /// runs it via `/bin/sh <path>` — deliberately NOT by exec-ing the file
    /// directly. Exec-ing a just-written file races with concurrent tests'
    /// `fork()`s and intermittently fails with ETXTBSY ("text file busy", os
    /// error 26): a forked-but-not-yet-exec'd child transiently inherits a write
    /// fd to the new file, so the kernel refuses to exec it. Running it through
    /// the shell only ever *reads* the file, which cannot trigger ETXTBSY. The
    /// process tree is identical to the shebang form (`/bin/sh` interpreting the
    /// script — the `#!/bin/sh` line is just a comment to `sh`), so the
    /// process-group kill semantics are unchanged. Production exec paths run
    /// stable installed binaries (terraform/ansible), so this is test-only.
    fn sh_script_command(ws: &Workspace, name: &str, content: &str) -> Command {
        let path = ws.path().join(name);
        std::fs::write(&path, content).expect("write script");
        let mut cmd = Command::new("/bin/sh");
        cmd.arg(&path);
        cmd
    }

    // ── Task 1 RED→GREEN: timeout kills child and returns Timeout ──

    /// A child that sleeps 5 s must be killed and return Timeout well before
    /// the sleep elapses when the timeout is 1 s.
    #[test]
    fn run_command_with_timeout_kills_slow_child() {
        let ws = Workspace::new().expect("workspace");
        let cmd = sh_script_command(&ws, "slow.sh", "#!/bin/sh\nsleep 5\n");

        let start = std::time::Instant::now();
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
        let cmd = sh_script_command(&ws, "fast.sh", "#!/bin/sh\necho hello\nexit 0\n");

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
        let cmd = sh_script_command(&ws, "big.sh", script);

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
        let cmd = sh_script_command(&ws, "fail.sh", "#!/bin/sh\nexit 42\n");

        let output = run_command_with_timeout(cmd, Duration::from_secs(5))
            .expect("non-zero exit must be Ok, not Err");
        assert_eq!(output.status.code(), Some(42));
    }

    // ── NEW: process-group kill — grandchild must also die on timeout ──

    /// A shell script spawns a 30-second grandchild (`sleep 30`), writes its
    /// PID to a temp file, then `wait`s (so the direct-child shell blocks for
    /// 30 s unless we kill it). With a 5-second timeout the runner must:
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
        let cmd = sh_script_command(&ws, "grand.sh", &script_body);

        let start = std::time::Instant::now();
        // 5 s timeout (not 1 s): generous headroom so the shell reliably reaches
        // its `printf … > pidfile` line BEFORE the timeout kills the group, even
        // under heavy parallel-test CPU starvation. Still far below the 30 s
        // grandchild sleep, so this verifies the timeout fires and kills the
        // whole group (not the grandchild completing naturally).
        let result = run_command_with_timeout(cmd, Duration::from_secs(5));
        let elapsed = start.elapsed();

        // (a) Must time out before the 30 s grandchild sleep completes. The bound
        // is < 30 s (not a tight value): the meaningful assertion is "the timeout
        // fired, the runner did NOT wait the full 30 s"; the exact wall-clock is
        // load-dependent (reader-thread drain + OS scheduling under parallel
        // tests), so the bound is generous to stay race-free.
        assert!(
            matches!(result, Err(RunnerError::Timeout)),
            "expected Timeout; got {result:?}"
        );
        assert!(
            elapsed < Duration::from_secs(25),
            "timeout must return before the 30s grandchild sleep; elapsed: {elapsed:?}"
        );

        // Read the grandchild PID written by the script.
        // The script writes the PID before calling `wait`, so it should
        // already be present. Retry for up to 5 s to tolerate scheduling
        // jitter under parallel-test / CI CPU contention.
        let grandchild_pid: libc::pid_t = {
            let mut raw: Option<String> = None;
            for _ in 0..200 {
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

        // (b) Poll for up to 5 s — SIGKILL delivery and kernel reaping are
        // async and can lag significantly under CI/parallel-test CPU contention.
        // `kill(pid, 0)` returns 0 if the process exists; -1 with errno ESRCH
        // when it is gone. Use `io::Error::last_os_error()` to read errno
        // portably (avoids platform-specific `__error`/`__errno_location`).
        let grandchild_dead = (0..200).any(|_| {
            let rc = unsafe { libc::kill(grandchild_pid, 0) };
            if rc == -1 {
                let esrch = std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
                if esrch {
                    return true;
                }
            }
            std::thread::sleep(Duration::from_millis(25));
            false
        });

        assert!(
            grandchild_dead,
            "grandchild PID {grandchild_pid} must be dead after process-group SIGKILL"
        );
    }

    // ── retry_on_etxtbsy: transient ETXTBSY is retried, other errors are not ──

    /// A transient ETXTBSY (the first two attempts) must be retried until the
    /// operation succeeds, rather than bubbling up as a spurious failure.
    #[cfg(unix)]
    #[test]
    fn retry_on_etxtbsy_succeeds_after_transient_busy() {
        use std::cell::Cell;
        let calls = Cell::new(0u32);
        let result: std::io::Result<u32> = retry_on_etxtbsy(|| {
            let n = calls.get() + 1;
            calls.set(n);
            if n < 3 {
                Err(std::io::Error::from_raw_os_error(libc::ETXTBSY))
            } else {
                Ok(n)
            }
        });
        assert_eq!(result.expect("should succeed after retries"), 3);
        assert_eq!(calls.get(), 3);
    }

    /// A non-ETXTBSY error must propagate immediately with no retry — we only
    /// paper over the specific transient text-file-busy race.
    #[cfg(unix)]
    #[test]
    fn retry_on_etxtbsy_does_not_retry_other_errors() {
        use std::cell::Cell;
        let calls = Cell::new(0u32);
        let result: std::io::Result<u32> = retry_on_etxtbsy(|| {
            calls.set(calls.get() + 1);
            Err(std::io::Error::from_raw_os_error(libc::ENOENT))
        });
        assert!(result.is_err());
        assert_eq!(calls.get(), 1, "non-ETXTBSY errors must not be retried");
    }

    /// ETXTBSY on every attempt must give up after exactly MAX_ATTEMPTS (10) and
    /// return the final ETXTBSY error — never loop forever. Pins the loop bound
    /// against an off-by-one regression in the `attempt < MAX_ATTEMPTS` guard.
    #[cfg(unix)]
    #[test]
    fn retry_on_etxtbsy_gives_up_after_max_attempts() {
        use std::cell::Cell;
        let calls = Cell::new(0u32);
        let result: std::io::Result<u32> = retry_on_etxtbsy(|| {
            calls.set(calls.get() + 1);
            Err(std::io::Error::from_raw_os_error(libc::ETXTBSY))
        });
        let err = result.expect_err("must fail after exhausting retries");
        assert_eq!(err.raw_os_error(), Some(libc::ETXTBSY));
        assert_eq!(calls.get(), 10, "must give up after exactly MAX_ATTEMPTS");
    }
}
