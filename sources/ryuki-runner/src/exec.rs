//! Shared command execution supervisor with bounded output and cancellation.
//!
//! # Why not `.output()`?
//! `Command::output()` has no timeout — a hung child blocks the calling thread
//! forever. It also has a pipe-buffer deadlock risk: if both stdout and stderr
//! fill their OS-level pipe buffers before the parent reads them, the child
//! blocks writing, the parent blocks waiting, and both hang.
//!
//! # Approach
//! 1. `spawn()` the child (pipes attached).
//! 2. Drain stdout and stderr concurrently in two reader threads. Each reader
//!    enforces a per-stream ceiling and shares an atomic combined ceiling.
//! 3. Poll the child while checking deadline, output-overflow, and an explicit
//!    cancellation handle.
//! 4. Refuse to spawn unless a trusted platform supervisor guarantees that
//!    descendants cannot escape the job boundary. A Unix process group is
//!    retained as defense in depth, but is not accepted as that capability.
//! 5. On timeout, overflow, cancellation, or supervisor drop, kill the entire
//!    process GROUP (setsid makes the child the leader of a new session) and
//!    reap the direct child before returning.
//!
//! # Process-group kill (Unix only)
//! `child.kill()` only signals the direct child. Long-running subprocesses
//! (e.g. terraform provider plugins, ansible forks) spawned by the child
//! survive and hold the pipe write-ends open, blocking the reader threads
//! indefinitely.
//!
//! As a defense-in-depth cleanup layer we:
//! - Call `libc::setsid()` in a `pre_exec` hook (runs in the forked child
//!   before exec, so it is async-signal-safe). This puts the child into its
//!   own process session; its pgid equals its pid.
//! - On timeout, send `SIGKILL` to `-pid` (the entire process group) via
//!   `libc::kill(-(pid as libc::pid_t), libc::SIGKILL)`.
//! - Then reap the direct child with `child.wait()` to avoid a zombie.
//! - Pipe readers use nonblocking descriptors plus a bounded DRAIN/ABORT
//!   lifecycle.
//!
//! A descendant can call `setsid()` again and leave that process group. For
//! that reason process-group isolation alone fails closed before `spawn()`.
//! Production execution remains disabled until the sealed
//! [`ContainmentCapability`] is backed by a per-command cgroup, systemd scope,
//! container sandbox, Windows Job Object, or equivalent supervisor with
//! attach-before-exec, kill-all, and wait-empty semantics.

use std::io::{self, Read};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
#[cfg(test)]
use std::sync::Mutex;
use std::sync::{
    atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    mpsc::{self, Receiver, RecvTimeoutError, Sender},
    Arc, OnceLock,
};
use std::time::{Duration, Instant};

use ryuki_engine::runners::RunnerError;

/// Default timeout used for both terraform init+plan and ansible --check.
pub const RUNNER_TIMEOUT: Duration = Duration::from_secs(120);

/// Stable non-secret identifier bound into execution trust profiles.
///
/// This version requires one fresh OS scope per command, atomic
/// attach-before-exec, kill-all, and wait-empty confirmation. Production
/// spawning fails closed until an implementation can issue the sealed token.
pub const RUNNER_CONTAINMENT_POLICY_VERSION: &str =
    "per-command-attach-before-exec-kill-all-wait-empty-v1";

/// Maximum bytes retained from either stdout or stderr for one subprocess.
///
/// The runner's supported plans are deliberately small, but the capture bound
/// leaves ample diagnostic headroom while preventing provider-controlled
/// output from growing agent memory without limit.
pub const MAX_CAPTURE_BYTES_PER_STREAM: usize = 8 * 1024 * 1024;

/// Maximum bytes retained across stdout and stderr for one subprocess.
pub const MAX_CAPTURE_BYTES_COMBINED: usize = 12 * 1024 * 1024;

/// Maximum number of child processes admitted by this process-wide supervisor.
///
/// Each admitted process uses two bounded capture threads, so this also limits
/// the capture-thread envelope to 32 rather than the previous 512.
pub const MAX_SUPERVISED_PROCESSES: usize = 16;

/// Maximum capture capacity reserved across all admitted subprocesses.
///
/// Capacity is reserved before spawn for both complete per-stream Vec
/// allocations. This bounds concurrent capture memory independently of the
/// process count; at default limits, at most four commands can capture at once.
pub const MAX_GLOBAL_CAPTURE_BYTES: usize = 64 * 1024 * 1024;

const SUPERVISOR_POLL_INTERVAL: Duration = Duration::from_millis(10);
const CAPTURE_SHUTDOWN_GRACE: Duration = Duration::from_millis(500);
const CHILD_REAP_GRACE: Duration = Duration::from_millis(500);
const CAPTURE_THREAD_STACK_BYTES: usize = 256 * 1024;

/// Version checks are subprocesses too: a replaced or broken binary must not
/// be able to hang runner admission or emit unbounded output.
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const VERSION_PROBE_CAPTURE_LIMITS: CaptureLimits = CaptureLimits {
    per_stream: 64 * 1024,
    combined: 96 * 1024,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputScope {
    Stdout,
    Stderr,
    Combined,
}

/// Proof token that every spawned descendant remains inside an OS-enforced
/// job boundary, even if it calls `setsid()` or changes process group.
///
/// The token is deliberately sealed and has no production constructor yet.
/// A real implementation must own a fresh per-command scope with atomic
/// attach-before-exec, kill-all, and wait-empty operations; a marker claiming
/// that the long-lived runner happens to be in a container/cgroup is
/// insufficient. Until that trusted adapter exists, every production entry
/// point fails closed before spawn.
#[derive(Debug)]
pub struct ContainmentCapability {
    _sealed: (),
}

impl ContainmentCapability {
    #[cfg(test)]
    fn for_controlled_test_harness() -> Self {
        Self { _sealed: () }
    }
}

#[cfg(test)]
static CONTROLLED_TEST_CONTAINMENT: ContainmentCapability = ContainmentCapability { _sealed: () };

// The production supervisor deliberately rejects a fifth default capture
// reservation instead of queueing. Rust's parallel unit-test harness would
// otherwise make unrelated command-shim tests contend for that production
// budget nondeterministically. Serialize only actual subprocess tests; direct
// SupervisorBudget tests still exercise exact concurrent admission semantics.
#[cfg(test)]
static CONTROLLED_TEST_SUBPROCESS_SERIAL: Mutex<()> = Mutex::new(());

#[cfg(test)]
fn compatibility_containment() -> Option<&'static ContainmentCapability> {
    Some(&CONTROLLED_TEST_CONTAINMENT)
}

#[cfg(not(test))]
fn compatibility_containment() -> Option<&'static ContainmentCapability> {
    None
}

/// Whether this build can safely start externally supplied subprocesses.
///
/// Production returns `false` until a real per-command containment adapter
/// implements attach-before-exec, kill-all, and wait-empty. The only `true`
/// state is the controlled unit-test harness, which never authorizes deployed
/// runner work. Callers should check this before resolving credentials.
pub const fn external_subprocess_containment_available() -> bool {
    cfg!(test)
}

/// Typed reason why process-local cleanup is not descendant containment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainmentUnavailable {
    /// `setsid()`/`setpgid()` lets a descendant escape a Unix process group.
    EscapableUnixProcessGroup,
    /// No supported process-tree containment primitive is implemented here.
    UnsupportedPlatform,
}

impl std::fmt::Display for ContainmentUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EscapableUnixProcessGroup => formatter.write_str(
                "Unix process groups are escapable with setsid; an external OS supervisor is required",
            ),
            Self::UnsupportedPlatform => formatter.write_str(
                "this platform has no verified descendant-containment implementation",
            ),
        }
    }
}

/// Process-wide supervisor resource whose admission budget was exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorResource {
    Processes,
    CaptureGroups,
    CaptureBytes,
}

/// Typed failures from the shared process supervisor.
///
/// Existing runner APIs still return `RunnerError` for compatibility. The
/// typed supervisor API is public so request/lease owners can distinguish
/// cancellation and output overflow while they adopt cancellation propagation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisedCommandError {
    Spawn(String),
    Wait(String),
    Capture(String),
    CaptureShutdownTimeout {
        scope: OutputScope,
    },
    Timeout,
    Cancelled,
    ContainmentUnavailable(ContainmentUnavailable),
    ResourceBudgetExceeded {
        resource: SupervisorResource,
        limit: usize,
    },
    OutputLimitExceeded {
        scope: OutputScope,
        limit: usize,
    },
}

impl std::fmt::Display for SupervisedCommandError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(detail) => write!(formatter, "spawn: {detail}"),
            Self::Wait(detail) => write!(formatter, "wait: {detail}"),
            Self::Capture(detail) => write!(formatter, "capture: {detail}"),
            Self::CaptureShutdownTimeout { scope } => write!(
                formatter,
                "{scope:?} capture did not stop within {} ms",
                CAPTURE_SHUTDOWN_GRACE.as_millis()
            ),
            Self::Timeout => formatter.write_str("runner timed out"),
            Self::Cancelled => formatter.write_str("runner command cancelled"),
            Self::ContainmentUnavailable(reason) => {
                write!(
                    formatter,
                    "runner descendant containment unavailable: {reason}"
                )
            }
            Self::ResourceBudgetExceeded { resource, limit } => {
                write!(
                    formatter,
                    "runner global {resource:?} budget exhausted (limit {limit})"
                )
            }
            Self::OutputLimitExceeded { scope, limit } => {
                write!(
                    formatter,
                    "runner {scope:?} output exceeded safe capture limit ({limit} bytes)"
                )
            }
        }
    }
}

impl std::error::Error for SupervisedCommandError {}

#[cfg(unix)]
const fn local_containment_unavailable() -> ContainmentUnavailable {
    ContainmentUnavailable::EscapableUnixProcessGroup
}

#[cfg(not(unix))]
const fn local_containment_unavailable() -> ContainmentUnavailable {
    ContainmentUnavailable::UnsupportedPlatform
}

fn require_descendant_containment(
    capability: Option<&ContainmentCapability>,
    unavailable: ContainmentUnavailable,
) -> Result<(), SupervisedCommandError> {
    capability
        .map(|_| ())
        .ok_or(SupervisedCommandError::ContainmentUnavailable(unavailable))
}

/// Cooperative cancellation signal for a supervised subprocess.
///
/// Clones refer to the same signal. Callers that own an HTTP request, agent
/// lease, or shutdown lifecycle can cancel the process promptly instead of
/// waiting for the independent runner deadline.
type CommandCleanupHold = Arc<dyn Send + Sync>;

#[derive(Clone, Default)]
pub struct CommandCancellation {
    cancelled: Arc<AtomicBool>,
    cleanup_hold: Option<CommandCleanupHold>,
}

impl std::fmt::Debug for CommandCancellation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommandCancellation")
            .field("cancelled", &self.is_cancelled())
            .field("has_cleanup_hold", &self.cleanup_hold.is_some())
            .finish()
    }
}

impl CommandCancellation {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adapt an existing authoritative lifecycle flag (for example, an agent
    /// lease-loss fence) without introducing a second source of truth.
    pub fn from_shared_flag(cancelled: Arc<AtomicBool>) -> Self {
        Self {
            cancelled,
            cleanup_hold: None,
        }
    }

    /// Couple an opaque admission/lifetime guard to command cleanup.
    ///
    /// The hold is cloned into each supervised child. If a killed child must
    /// be transferred to the bounded background reaper, that clone prevents
    /// the caller's admission capacity from being recycled until the child is
    /// actually reaped. The value is never inspected by the runner.
    pub fn new_with_cleanup_hold<T>(hold: T) -> Self
    where
        T: Send + Sync + 'static,
    {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            cleanup_hold: Some(Arc::new(hold)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn cleanup_hold(&self) -> Option<CommandCleanupHold> {
        self.cleanup_hold.clone()
    }
}

#[derive(Debug, Clone, Copy)]
struct CaptureLimits {
    per_stream: usize,
    combined: usize,
}

const DEFAULT_CAPTURE_LIMITS: CaptureLimits = CaptureLimits {
    per_stream: MAX_CAPTURE_BYTES_PER_STREAM,
    combined: MAX_CAPTURE_BYTES_COMBINED,
};

const STOP_NONE: u8 = 0;
const STOP_STDOUT: u8 = 1;
const STOP_STDERR: u8 = 2;
const STOP_COMBINED: u8 = 3;
const STOP_CAPTURE: u8 = 4;

const CAPTURE_RUNNING: u8 = 0;
const CAPTURE_DRAIN: u8 = 1;
const CAPTURE_ABORT: u8 = 2;

/// Run `cmd` to completion, collecting stdout+stderr into an `Output`.
///
/// Returns `Err(RunnerError::Timeout)` if the child does not exit within
/// `timeout`. On timeout the entire process group is killed before returning.
/// The command is not spawned until a per-command platform-containment adapter
/// is implemented; the compatibility entry point intentionally has no bypass.
///
/// # Deadlock safety
/// Both stdout and stderr are drained in background threads. The parent never
/// holds the pipe handles open while waiting for the child to exit, so the
/// pipe buffers cannot fill and block the child.
///
/// # Grandchild safety
/// A trusted OS containment capability is mandatory. On Unix, a new process
/// session and process-group kill remain an additional cleanup layer for
/// ordinary descendants; they are not accepted as complete containment.
pub fn run_command_with_timeout(cmd: Command, timeout: Duration) -> Result<Output, RunnerError> {
    run_command_with_optional_cancellation(cmd, timeout, None)
}

/// Reserved per-call entry point for a future trusted containment adapter.
pub fn run_command_with_timeout_in_containment(
    cmd: Command,
    timeout: Duration,
    containment: &ContainmentCapability,
) -> Result<Output, RunnerError> {
    run_command_supervised_with_limits_in_containment(
        cmd,
        timeout,
        None,
        DEFAULT_CAPTURE_LIMITS,
        Some(containment),
        local_containment_unavailable(),
    )
    .map_err(supervisor_error_to_runner)
}

/// Compatibility seam for logical runner operations that optionally carry an
/// authoritative cancellation signal. The ordinary path uses `None` rather
/// than allocating a handle that can never be cancelled.
pub(crate) fn run_command_with_optional_cancellation(
    cmd: Command,
    timeout: Duration,
    cancellation: Option<&CommandCancellation>,
) -> Result<Output, RunnerError> {
    run_command_supervised_with_limits(cmd, timeout, cancellation, DEFAULT_CAPTURE_LIMITS)
        .map_err(supervisor_error_to_runner)
}

/// Run a command under the shared bounded, cancellation-aware supervisor.
pub fn run_command_supervised(
    cmd: Command,
    timeout: Duration,
    cancellation: &CommandCancellation,
) -> Result<Output, SupervisedCommandError> {
    run_command_supervised_with_limits(cmd, timeout, Some(cancellation), DEFAULT_CAPTURE_LIMITS)
}

/// Run with explicit cancellation and per-call trusted descendant containment.
pub fn run_command_supervised_with_containment(
    cmd: Command,
    timeout: Duration,
    cancellation: &CommandCancellation,
    containment: &ContainmentCapability,
) -> Result<Output, SupervisedCommandError> {
    run_command_supervised_with_limits_in_containment(
        cmd,
        timeout,
        Some(cancellation),
        DEFAULT_CAPTURE_LIMITS,
        Some(containment),
        local_containment_unavailable(),
    )
}

/// Run a bounded, short-lived binary version probe through the same process
/// group, deadline, cancellation, capture, and reap boundary as real work.
pub(crate) fn run_version_probe(
    cmd: Command,
    cancellation: Option<&CommandCancellation>,
) -> Result<bool, RunnerError> {
    match run_version_probe_with_limits(
        cmd,
        cancellation,
        VERSION_PROBE_TIMEOUT,
        VERSION_PROBE_CAPTURE_LIMITS,
    ) {
        Ok(available) => Ok(available),
        // Cancellation is authoritative and must remain distinguishable from
        // an unavailable binary to a logical run owner.
        Err(
            error @ (SupervisedCommandError::Cancelled
            | SupervisedCommandError::ContainmentUnavailable(_)
            | SupervisedCommandError::ResourceBudgetExceeded { .. }),
        ) => Err(supervisor_error_to_runner(error)),
        // Preserve the historical availability contract: missing, non-zero,
        // hung, noisy, or otherwise broken binaries are unavailable, not an
        // execution error. The supervisor has already cleaned them up.
        Err(_) => Ok(false),
    }
}

/// Run an executable-identity probe under the same short deadline and tight
/// capture limits as the availability probe, but preserve the bounded output
/// so the approved-executable boundary can verify the tool name and version.
///
/// Unlike [`run_version_probe`], every supervisor failure is returned to the
/// caller. Executable admission is a fail-closed security decision: a noisy,
/// hung, non-zero, or unspawnable candidate must never be treated as an
/// approved CLI.
pub(crate) fn run_executable_identity_probe(
    cmd: Command,
    cancellation: Option<&CommandCancellation>,
) -> Result<Output, RunnerError> {
    run_command_supervised_with_limits(
        cmd,
        VERSION_PROBE_TIMEOUT,
        cancellation,
        VERSION_PROBE_CAPTURE_LIMITS,
    )
    .map_err(supervisor_error_to_runner)
}

fn run_version_probe_with_limits(
    cmd: Command,
    cancellation: Option<&CommandCancellation>,
    timeout: Duration,
    limits: CaptureLimits,
) -> Result<bool, SupervisedCommandError> {
    run_command_supervised_with_limits(cmd, timeout, cancellation, limits)
        .map(|output| output.status.success())
}

fn run_command_supervised_with_limits(
    cmd: Command,
    timeout: Duration,
    cancellation: Option<&CommandCancellation>,
    limits: CaptureLimits,
) -> Result<Output, SupervisedCommandError> {
    #[cfg(test)]
    let _controlled_test_serial = CONTROLLED_TEST_SUBPROCESS_SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // A compatibility command may have waited behind another test shim;
    // cancellation that arrived during that wait remains authoritative.
    if cancellation.is_some_and(CommandCancellation::is_cancelled) {
        return Err(SupervisedCommandError::Cancelled);
    }
    run_command_supervised_with_limits_in_containment(
        cmd,
        timeout,
        cancellation,
        limits,
        compatibility_containment(),
        local_containment_unavailable(),
    )
}

fn run_command_supervised_with_limits_in_containment(
    mut cmd: Command,
    timeout: Duration,
    cancellation: Option<&CommandCancellation>,
    limits: CaptureLimits,
    containment: Option<&ContainmentCapability>,
    unavailable: ContainmentUnavailable,
) -> Result<Output, SupervisedCommandError> {
    if cancellation.is_some_and(CommandCancellation::is_cancelled) {
        return Err(SupervisedCommandError::Cancelled);
    }
    require_descendant_containment(containment, unavailable)?;
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    configure_process_group(&mut cmd);

    // Start the one shared nonblocking reaper before a child exists. If the
    // process cannot create that bounded cleanup service, fail before spawn.
    child_reaper_sender()?;
    let admission = SUPERVISOR_BUDGET.acquire(capture_reservation_bytes(limits))?;

    let child = retry_on_etxtbsy(|| cmd.spawn())
        .map_err(|error| SupervisedCommandError::Spawn(error.to_string()))?;
    let (reap_slot, capture_reservation) = admission.into_slots();

    let cleanup_hold = cancellation.and_then(CommandCancellation::cleanup_hold);
    let mut child = SupervisedChild::new(child, reap_slot, cleanup_hold);

    // The supervisor owns both pipe handles and their bounded collectors.
    let stdout_pipe = child.take_stdout();
    let stderr_pipe = child.take_stderr();

    // Blocking reads are unsafe during cleanup: a descendant can escape the
    // original process group with setsid/setpgid while retaining a pipe writer.
    // Nonblocking readers can observe the lifecycle signal and close their end
    // even when that escaped writer remains alive.
    set_pipe_nonblocking(&stdout_pipe)
        .and_then(|()| set_pipe_nonblocking(&stderr_pipe))
        .map_err(|error| SupervisedCommandError::Capture(error.to_string()))?;

    let total = Arc::new(AtomicUsize::new(0));
    let stop_reason = Arc::new(AtomicU8::new(STOP_NONE));
    let capture_control = Arc::new(AtomicU8::new(CAPTURE_RUNNING));
    let stdout_thread = spawn_capture(
        stdout_pipe,
        OutputScope::Stdout,
        limits,
        Arc::clone(&total),
        Arc::clone(&stop_reason),
        Arc::clone(&capture_control),
    )?;
    let stderr_thread = match spawn_capture(
        stderr_pipe,
        OutputScope::Stderr,
        limits,
        Arc::clone(&total),
        Arc::clone(&stop_reason),
        Arc::clone(&capture_control),
    ) {
        Ok(task) => task,
        Err(error) => {
            capture_control.store(CAPTURE_ABORT, Ordering::Release);
            let stopped = receive_capture(Some(stdout_thread), capture_shutdown_deadline());
            if capture_stop_unconfirmed(&stopped) {
                std::mem::forget(capture_reservation);
            }
            return Err(error);
        }
    };
    let mut captures = CaptureThreads::new(
        stdout_thread,
        stderr_thread,
        capture_control,
        capture_reservation,
    );
    let started_at = Instant::now();
    // An unrepresentable deadline must fail closed rather than silently turn
    // into an unbounded process lifetime.
    let deadline = started_at.checked_add(timeout).unwrap_or(started_at);

    loop {
        if cancellation.is_some_and(CommandCancellation::is_cancelled) {
            captures.abort_discard();
            child.kill_and_reap();
            return Err(SupervisedCommandError::Cancelled);
        }

        if let Some(error) = supervisor_stop_error(stop_reason.load(Ordering::Acquire), limits) {
            captures.abort_discard();
            child.kill_and_reap();
            return Err(error);
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                // Never signal a cached process-group id after reaping its
                // leader: the numeric pid/pgid could already have been reused.
                // A trusted platform boundary owns any remaining descendants.
                let (stdout, stderr) = captures.finish_draining()?;
                return Ok(Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {}
            Err(error) => {
                captures.abort_discard();
                child.kill_and_reap();
                return Err(SupervisedCommandError::Wait(error.to_string()));
            }
        }

        let now = Instant::now();
        if now >= deadline {
            captures.abort_discard();
            child.kill_and_reap();
            return Err(SupervisedCommandError::Timeout);
        }

        let sleep_for = deadline
            .saturating_duration_since(now)
            .min(SUPERVISOR_POLL_INTERVAL);
        std::thread::sleep(sleep_for);
    }
}

#[cfg(unix)]
fn configure_process_group(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;

    // pre_exec runs in the forked child before exec(). Only async-signal-safe
    // functions are permitted here; setsid(2) is async-signal-safe. This makes
    // child.id() the process-group id used by kill_remaining_group.
    // SAFETY: the hook calls only async-signal-safe libc operations and
    // last_os_error. A private umask ensures local backend state and lock
    // artifacts created by Terraform cannot acquire group/other permissions.
    unsafe {
        cmd.pre_exec(|| {
            libc::umask(0o077);
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn configure_process_group(_cmd: &mut Command) {}

pub(crate) fn supervisor_error_to_runner(error: SupervisedCommandError) -> RunnerError {
    match error {
        SupervisedCommandError::Timeout => RunnerError::Timeout,
        SupervisedCommandError::Cancelled => RunnerError::Cancelled,
        SupervisedCommandError::OutputLimitExceeded { scope, limit } => {
            RunnerError::OutputLimitExceeded {
                scope: format!("{scope:?}").to_ascii_lowercase(),
                limit,
            }
        }
        other => RunnerError::Spawn(other.to_string()),
    }
}

struct SupervisedChild {
    child: Option<Child>,
    reap_slot: Option<ReapSlot>,
    cleanup_hold: Option<CommandCleanupHold>,
    reaped: bool,
    group_closed: bool,
    #[cfg(unix)]
    process_group: libc::pid_t,
}

impl SupervisedChild {
    fn new(child: Child, reap_slot: ReapSlot, cleanup_hold: Option<CommandCleanupHold>) -> Self {
        Self {
            #[cfg(unix)]
            process_group: child.id() as libc::pid_t,
            child: Some(child),
            reap_slot: Some(reap_slot),
            cleanup_hold,
            reaped: false,
            group_closed: false,
        }
    }

    fn take_stdout(&mut self) -> std::process::ChildStdout {
        self.child
            .as_mut()
            .expect("supervised child is present")
            .stdout
            .take()
            .expect("stdout was piped")
    }

    fn take_stderr(&mut self) -> std::process::ChildStderr {
        self.child
            .as_mut()
            .expect("supervised child is present")
            .stderr
            .take()
            .expect("stderr was piped")
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self
            .child
            .as_mut()
            .expect("supervised child is present")
            .try_wait()?;
        if status.is_some() {
            self.reaped = true;
        }
        Ok(status)
    }

    fn kill_remaining_group(&mut self) {
        if self.group_closed {
            return;
        }
        #[cfg(unix)]
        unsafe {
            // SAFETY: the child called setsid before exec, so its pid is the
            // process-group id. A negative pid targets that group only.
            libc::kill(-self.process_group, libc::SIGKILL);
        }
        self.group_closed = true;
    }

    fn kill_and_reap(&mut self) {
        if self.reaped {
            return;
        }
        self.kill_remaining_group();
        let Some(child) = self.child.as_mut() else {
            self.reaped = true;
            return;
        };
        let _ = child.kill();

        let deadline = Instant::now()
            .checked_add(CHILD_REAP_GRACE)
            .unwrap_or_else(Instant::now);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    self.reaped = true;
                    return;
                }
                Ok(None) => {}
                Err(_) => break,
            }
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            std::thread::sleep(
                deadline
                    .saturating_duration_since(now)
                    .min(SUPERVISOR_POLL_INTERVAL),
            );
        }

        // Waiting for a killed child is normally immediate, but a process in
        // an uninterruptible kernel state must not turn request cleanup into an
        // unbounded wait. Transfer it to the single bounded reaper, which polls
        // all deferred children with try_wait instead of creating one blocked
        // waiter thread per process.
        if let (Some(child), Some(reap_slot)) = (self.child.take(), self.reap_slot.take()) {
            let deferred = DeferredChild {
                child,
                _reap_slot: reap_slot,
                _cleanup_hold: self.cleanup_hold.take(),
            };
            match child_reaper_sender() {
                Ok(sender) => {
                    if let Err(error) = sender.send(deferred) {
                        // The group was already force-killed, but without the
                        // single reaper there is no proof that the direct child
                        // was collected. Leak this bounded slot/hold instead of
                        // falsely recycling process or caller admission.
                        std::mem::forget(error.0);
                    }
                }
                Err(_) => {
                    // `child_reaper_sender` is started before spawn, so this is
                    // defensive. Preserve the same fail-closed capacity rule.
                    std::mem::forget(deferred);
                }
            }
        }
        self.reaped = true;
    }
}

impl Drop for SupervisedChild {
    fn drop(&mut self) {
        // Covers unwinding and any new early-return branch added in the future.
        self.kill_and_reap();
    }
}

static CHILD_REAPER: OnceLock<Result<Sender<DeferredChild>, String>> = OnceLock::new();

static SUPERVISOR_BUDGET: SupervisorBudget =
    SupervisorBudget::new(MAX_SUPERVISED_PROCESSES, MAX_GLOBAL_CAPTURE_BYTES);

fn capture_reservation_bytes(limits: CaptureLimits) -> usize {
    // Both collectors preallocate their complete per-stream capacity. Reserve
    // exactly that allocation before spawn; the logical combined byte limit is
    // enforced separately while reading.
    limits.per_stream.saturating_mul(2)
}

#[derive(Debug)]
struct SupervisorBudget {
    active_processes: AtomicUsize,
    active_capture_groups: AtomicUsize,
    reserved_capture_bytes: AtomicUsize,
    max_processes: usize,
    max_capture_bytes: usize,
}

impl SupervisorBudget {
    const fn new(max_processes: usize, max_capture_bytes: usize) -> Self {
        Self {
            active_processes: AtomicUsize::new(0),
            active_capture_groups: AtomicUsize::new(0),
            reserved_capture_bytes: AtomicUsize::new(0),
            max_processes,
            max_capture_bytes,
        }
    }

    fn acquire(
        &self,
        capture_bytes: usize,
    ) -> Result<SupervisorAdmission<'_>, SupervisedCommandError> {
        self.active_processes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.max_processes).then_some(active + 1)
            })
            .map_err(|_| SupervisedCommandError::ResourceBudgetExceeded {
                resource: SupervisorResource::Processes,
                limit: self.max_processes,
            })?;

        if self
            .active_capture_groups
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.max_processes).then_some(active + 1)
            })
            .is_err()
        {
            self.active_processes.fetch_sub(1, Ordering::AcqRel);
            return Err(SupervisedCommandError::ResourceBudgetExceeded {
                resource: SupervisorResource::CaptureGroups,
                limit: self.max_processes,
            });
        }

        if self
            .reserved_capture_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |reserved| {
                reserved
                    .checked_add(capture_bytes)
                    .filter(|next| *next <= self.max_capture_bytes)
            })
            .is_err()
        {
            self.active_capture_groups.fetch_sub(1, Ordering::AcqRel);
            self.active_processes.fetch_sub(1, Ordering::AcqRel);
            return Err(SupervisedCommandError::ResourceBudgetExceeded {
                resource: SupervisorResource::CaptureBytes,
                limit: self.max_capture_bytes,
            });
        }

        Ok(SupervisorAdmission {
            process: ProcessPermit { budget: self },
            capture: CaptureReservation {
                budget: self,
                capture_bytes,
            },
        })
    }
}

#[derive(Debug)]
struct SupervisorAdmission<'a> {
    process: ProcessPermit<'a>,
    capture: CaptureReservation<'a>,
}

impl SupervisorAdmission<'static> {
    fn into_slots(self) -> (ReapSlot, CaptureReservation<'static>) {
        (
            ReapSlot {
                _permit: self.process,
            },
            self.capture,
        )
    }
}

#[derive(Debug)]
struct ProcessPermit<'a> {
    budget: &'a SupervisorBudget,
}

impl Drop for ProcessPermit<'_> {
    fn drop(&mut self) {
        self.budget.active_processes.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug)]
struct CaptureReservation<'a> {
    budget: &'a SupervisorBudget,
    capture_bytes: usize,
}

impl Drop for CaptureReservation<'_> {
    fn drop(&mut self) {
        self.budget
            .reserved_capture_bytes
            .fetch_sub(self.capture_bytes, Ordering::AcqRel);
        self.budget
            .active_capture_groups
            .fetch_sub(1, Ordering::AcqRel);
    }
}

struct ReapSlot {
    _permit: ProcessPermit<'static>,
}

struct DeferredChild {
    child: Child,
    _reap_slot: ReapSlot,
    _cleanup_hold: Option<CommandCleanupHold>,
}

fn child_reaper_sender() -> Result<&'static Sender<DeferredChild>, SupervisedCommandError> {
    CHILD_REAPER
        .get_or_init(|| {
            let (sender, receiver) = mpsc::channel();
            std::thread::Builder::new()
                .name("ryuki-runner-reaper".to_string())
                .spawn(move || child_reaper_loop(receiver))
                .map(|_| sender)
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| {
            SupervisedCommandError::Spawn(format!("runner child reaper could not start: {error}"))
        })
}

fn child_reaper_loop(receiver: Receiver<DeferredChild>) {
    let mut pending = Vec::<DeferredChild>::new();
    loop {
        match receiver.recv_timeout(SUPERVISOR_POLL_INTERVAL) {
            Ok(child) => pending.push(child),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) if pending.is_empty() => return,
            Err(RecvTimeoutError::Disconnected) => {
                std::thread::sleep(SUPERVISOR_POLL_INTERVAL);
            }
        }
        while let Ok(child) = receiver.try_recv() {
            pending.push(child);
        }
        pending.retain_mut(|child| match child.child.try_wait() {
            Ok(Some(_)) => false,
            Ok(None) | Err(_) => true,
        });
    }
}

type CaptureResult = Result<Vec<u8>, SupervisedCommandError>;

struct CaptureTask {
    result: Receiver<CaptureResult>,
    scope: OutputScope,
}

fn spawn_capture<R: Read + Send + 'static>(
    reader: R,
    scope: OutputScope,
    limits: CaptureLimits,
    total: Arc<AtomicUsize>,
    stop_reason: Arc<AtomicU8>,
    capture_control: Arc<AtomicU8>,
) -> Result<CaptureTask, SupervisedCommandError> {
    let (sender, result) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name(format!("ryuki-runner-capture-{scope:?}"))
        .stack_size(CAPTURE_THREAD_STACK_BYTES)
        .spawn(move || {
            let captured = read_capped(
                reader,
                scope,
                limits,
                &total,
                &stop_reason,
                &capture_control,
            );
            let _ = sender.send(captured);
        })
        .map_err(|error| {
            SupervisedCommandError::Capture(format!(
                "{scope:?} capture thread could not start: {error}"
            ))
        })?;
    Ok(CaptureTask { result, scope })
}

fn read_capped(
    mut reader: impl Read,
    scope: OutputScope,
    limits: CaptureLimits,
    total: &AtomicUsize,
    stop_reason: &AtomicU8,
    capture_control: &AtomicU8,
) -> CaptureResult {
    // The process-wide budget reserved the worst-case stream capacity before
    // spawn. Start smaller so ordinary short outputs do not retain a full-cap
    // allocation after they leave the active supervisor.
    let mut captured = Vec::with_capacity(limits.per_stream.min(64 * 1024));
    let mut chunk = [0u8; 8192];
    loop {
        if capture_control.load(Ordering::Acquire) == CAPTURE_ABORT {
            return Ok(captured);
        }
        if stop_reason.load(Ordering::Acquire) != STOP_NONE {
            return Ok(captured);
        }
        let read = match reader.read(&mut chunk) {
            Ok(0) => return Ok(captured),
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if capture_control.load(Ordering::Acquire) != CAPTURE_RUNNING {
                    return Ok(captured);
                }
                std::thread::sleep(SUPERVISOR_POLL_INTERVAL);
                continue;
            }
            Err(error) => {
                set_stop_reason(stop_reason, STOP_CAPTURE);
                return Err(SupervisedCommandError::Capture(error.to_string()));
            }
        };

        if captured.len().saturating_add(read) > limits.per_stream {
            set_stop_reason(stop_reason, scope_stop_code(scope));
            return Err(SupervisedCommandError::OutputLimitExceeded {
                scope,
                limit: limits.per_stream,
            });
        }

        let reserved = total.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current
                .checked_add(read)
                .filter(|next| *next <= limits.combined)
        });
        if reserved.is_err() {
            set_stop_reason(stop_reason, STOP_COMBINED);
            return Err(SupervisedCommandError::OutputLimitExceeded {
                scope: OutputScope::Combined,
                limit: limits.combined,
            });
        }
        captured.extend_from_slice(&chunk[..read]);
    }
}

fn set_stop_reason(stop_reason: &AtomicU8, code: u8) {
    let _ = stop_reason.compare_exchange(STOP_NONE, code, Ordering::AcqRel, Ordering::Acquire);
}

fn scope_stop_code(scope: OutputScope) -> u8 {
    match scope {
        OutputScope::Stdout => STOP_STDOUT,
        OutputScope::Stderr => STOP_STDERR,
        OutputScope::Combined => STOP_COMBINED,
    }
}

fn supervisor_stop_error(code: u8, limits: CaptureLimits) -> Option<SupervisedCommandError> {
    if code == STOP_CAPTURE {
        return Some(SupervisedCommandError::Capture(
            "runner output capture failed".to_string(),
        ));
    }
    let (scope, limit) = match code {
        STOP_STDOUT => (OutputScope::Stdout, limits.per_stream),
        STOP_STDERR => (OutputScope::Stderr, limits.per_stream),
        STOP_COMBINED => (OutputScope::Combined, limits.combined),
        _ => return None,
    };
    Some(SupervisedCommandError::OutputLimitExceeded { scope, limit })
}

struct CaptureThreads {
    stdout: Option<CaptureTask>,
    stderr: Option<CaptureTask>,
    control: Arc<AtomicU8>,
    reservation: Option<CaptureReservation<'static>>,
}

impl CaptureThreads {
    fn new(
        stdout: CaptureTask,
        stderr: CaptureTask,
        control: Arc<AtomicU8>,
        reservation: CaptureReservation<'static>,
    ) -> Self {
        Self {
            stdout: Some(stdout),
            stderr: Some(stderr),
            control,
            reservation: Some(reservation),
        }
    }

    fn finish_draining(&mut self) -> Result<(Vec<u8>, Vec<u8>), SupervisedCommandError> {
        self.control.store(CAPTURE_DRAIN, Ordering::Release);
        let deadline = capture_shutdown_deadline();
        let stdout = receive_capture(self.stdout.take(), deadline);
        let stderr = receive_capture(self.stderr.take(), deadline);
        let uncertain = capture_stop_unconfirmed(&stdout) || capture_stop_unconfirmed(&stderr);
        self.finish_reservation(uncertain);
        match (stdout, stderr) {
            (Ok(stdout), Ok(stderr)) => Ok((stdout, stderr)),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }

    fn abort_discard(&mut self) {
        self.control.store(CAPTURE_ABORT, Ordering::Release);
        let deadline = capture_shutdown_deadline();
        let stdout = receive_capture(self.stdout.take(), deadline);
        let stderr = receive_capture(self.stderr.take(), deadline);
        let uncertain = capture_stop_unconfirmed(&stdout) || capture_stop_unconfirmed(&stderr);
        self.finish_reservation(uncertain);
    }

    fn finish_reservation(&mut self, uncertain: bool) {
        let Some(reservation) = self.reservation.take() else {
            return;
        };
        if uncertain {
            // A detached collector may still own its admitted Vec and stack.
            // Leak the bounded reservation instead of recycling unproved
            // capacity and exceeding the global allocation/thread envelope.
            std::mem::forget(reservation);
        }
    }
}

impl Drop for CaptureThreads {
    fn drop(&mut self) {
        // Covers unwinding and future early-return branches. Completion waits
        // are bounded; a non-responsive platform fallback is detached.
        self.abort_discard();
    }
}

fn capture_stop_unconfirmed(result: &CaptureResult) -> bool {
    matches!(
        result,
        Err(SupervisedCommandError::CaptureShutdownTimeout { .. })
    )
}

fn capture_shutdown_deadline() -> Instant {
    Instant::now()
        .checked_add(CAPTURE_SHUTDOWN_GRACE)
        .unwrap_or_else(Instant::now)
}

fn receive_capture(task: Option<CaptureTask>, deadline: Instant) -> CaptureResult {
    let Some(task) = task else {
        return Ok(Vec::new());
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    match task.result.recv_timeout(remaining) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => {
            Err(SupervisedCommandError::CaptureShutdownTimeout { scope: task.scope })
        }
        Err(RecvTimeoutError::Disconnected) => Err(SupervisedCommandError::Capture(format!(
            "{:?} capture thread terminated without a result",
            task.scope
        ))),
    }
}

#[cfg(unix)]
fn set_pipe_nonblocking(pipe: &impl std::os::fd::AsRawFd) -> io::Result<()> {
    let fd = pipe.as_raw_fd();
    // SAFETY: fcntl reads/updates flags on the valid pipe fd borrowed above.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: same valid fd; preserving existing flags and adding O_NONBLOCK.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_pipe_nonblocking<T>(_pipe: &T) -> io::Result<()> {
    Ok(())
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

    const TEST_CAPTURE_LIMITS: CaptureLimits = CaptureLimits {
        per_stream: 2 * 1024 * 1024,
        combined: 3 * 1024 * 1024,
    };

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

    fn run_test_with_limits(
        cmd: Command,
        timeout: Duration,
        cancellation: Option<&CommandCancellation>,
        limits: CaptureLimits,
    ) -> Result<Output, SupervisedCommandError> {
        let containment = ContainmentCapability::for_controlled_test_harness();
        run_command_supervised_with_limits_in_containment(
            cmd,
            timeout,
            cancellation,
            limits,
            Some(&containment),
            local_containment_unavailable(),
        )
    }

    fn run_test_with_timeout(cmd: Command, timeout: Duration) -> Result<Output, RunnerError> {
        run_test_with_limits(cmd, timeout, None, TEST_CAPTURE_LIMITS)
            .map_err(supervisor_error_to_runner)
    }

    fn run_test_supervised(
        cmd: Command,
        timeout: Duration,
        cancellation: &CommandCancellation,
    ) -> Result<Output, SupervisedCommandError> {
        run_test_with_limits(cmd, timeout, Some(cancellation), TEST_CAPTURE_LIMITS)
    }

    fn run_test_version_probe_with_limits(
        cmd: Command,
        cancellation: Option<&CommandCancellation>,
        timeout: Duration,
        limits: CaptureLimits,
    ) -> Result<bool, SupervisedCommandError> {
        run_test_with_limits(cmd, timeout, cancellation, limits)
            .map(|output| output.status.success())
    }

    // ── Task 1 RED→GREEN: timeout kills child and returns Timeout ──

    /// A child that sleeps 5 s must be killed and return Timeout well before
    /// the sleep elapses when the timeout is 1 s.
    #[test]
    fn run_command_with_timeout_kills_slow_child() {
        let ws = Workspace::new().expect("workspace");
        let cmd = sh_script_command(&ws, "slow.sh", "#!/bin/sh\nsleep 5\n");

        let start = std::time::Instant::now();
        let result = run_test_with_timeout(cmd, Duration::from_secs(1));
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

        let result = run_test_with_timeout(cmd, Duration::from_secs(5));
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

        let result = run_test_with_timeout(cmd, Duration::from_secs(10));
        assert!(
            result.is_ok(),
            "large output child must not deadlock: {result:?}"
        );
    }

    #[test]
    fn supervised_capture_accepts_the_exact_stream_limit() {
        let ws = Workspace::new().expect("workspace");
        let cmd = sh_script_command(&ws, "exact-cap.sh", "#!/bin/sh\nyes x | head -c 1024\n");
        let limits = CaptureLimits {
            per_stream: 1024,
            combined: 2048,
        };
        let output = run_test_with_limits(cmd, Duration::from_secs(5), None, limits)
            .expect("exactly-at-cap output must remain valid");
        assert_eq!(output.stdout.len(), 1024);
    }

    #[test]
    fn supervised_capture_rejects_one_byte_over_the_stream_limit() {
        let ws = Workspace::new().expect("workspace");
        let cmd = sh_script_command(&ws, "over-cap.sh", "#!/bin/sh\nyes x | head -c 1025\n");
        let limits = CaptureLimits {
            per_stream: 1024,
            combined: 2048,
        };
        let error = run_test_with_limits(cmd, Duration::from_secs(5), None, limits)
            .expect_err("over-cap output must terminate the command");
        assert_eq!(
            error,
            SupervisedCommandError::OutputLimitExceeded {
                scope: OutputScope::Stdout,
                limit: 1024,
            }
        );
    }

    #[test]
    fn supervised_capture_checks_stderr_at_the_exact_boundary_and_one_over() {
        let ws = Workspace::new().expect("workspace");
        let limits = CaptureLimits {
            per_stream: 1024,
            combined: 2048,
        };
        let exact = sh_script_command(
            &ws,
            "stderr-exact-cap.sh",
            "#!/bin/sh\nyes x | head -c 1024 >&2\n",
        );
        let output = run_test_with_limits(exact, Duration::from_secs(5), None, limits)
            .expect("stderr exactly at the cap must remain valid");
        assert_eq!(output.stderr.len(), 1024);

        let over = sh_script_command(
            &ws,
            "stderr-over-cap.sh",
            "#!/bin/sh\nyes x | head -c 1025 >&2\n",
        );
        let error = run_test_with_limits(over, Duration::from_secs(5), None, limits)
            .expect_err("stderr one byte over must terminate the command");
        assert_eq!(
            error,
            SupervisedCommandError::OutputLimitExceeded {
                scope: OutputScope::Stderr,
                limit: 1024,
            }
        );
    }

    #[test]
    fn supervised_capture_enforces_the_combined_stream_limit() {
        let ws = Workspace::new().expect("workspace");
        let cmd = sh_script_command(
            &ws,
            "combined-cap.sh",
            "#!/bin/sh\nyes x | head -c 700\nyes y | head -c 700 >&2\n",
        );
        let limits = CaptureLimits {
            per_stream: 1024,
            combined: 1200,
        };
        let error = run_test_with_limits(cmd, Duration::from_secs(5), None, limits)
            .expect_err("aggregate output over the combined cap must terminate the command");
        assert_eq!(
            error,
            SupervisedCommandError::OutputLimitExceeded {
                scope: OutputScope::Combined,
                limit: 1200,
            }
        );
    }

    #[test]
    fn supervised_capture_accepts_exact_combined_limit() {
        let ws = Workspace::new().expect("workspace");
        let cmd = sh_script_command(
            &ws,
            "combined-exact-cap.sh",
            "#!/bin/sh\nyes x | head -c 600\nyes y | head -c 600 >&2\n",
        );
        let limits = CaptureLimits {
            per_stream: 1024,
            combined: 1200,
        };
        let output = run_test_with_limits(cmd, Duration::from_secs(5), None, limits)
            .expect("aggregate output exactly at the cap must remain valid");
        assert_eq!(output.stdout.len() + output.stderr.len(), 1200);
    }

    #[test]
    fn global_process_budget_accepts_exact_limit_and_releases_on_drop() {
        let budget = SupervisorBudget::new(2, 100);
        let first = budget.acquire(10).expect("first process permit");
        let second = budget.acquire(10).expect("exact process limit");
        let error = budget
            .acquire(0)
            .expect_err("one process over the global limit must fail");
        assert_eq!(
            error,
            SupervisedCommandError::ResourceBudgetExceeded {
                resource: SupervisorResource::Processes,
                limit: 2,
            }
        );
        drop(first);
        let replacement = budget.acquire(10).expect("dropped permit must release");
        drop(replacement);
        drop(second);
        assert_eq!(budget.active_processes.load(Ordering::Acquire), 0);
        assert_eq!(budget.active_capture_groups.load(Ordering::Acquire), 0);
        assert_eq!(budget.reserved_capture_bytes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn global_capture_budget_accepts_exact_limit_and_rolls_back_process_slot() {
        let budget = SupervisorBudget::new(3, 10);
        let first = budget.acquire(4).expect("first capture reservation");
        let second = budget.acquire(6).expect("exact capture-byte limit");
        let error = budget
            .acquire(1)
            .expect_err("one byte over the global limit must fail");
        assert_eq!(
            error,
            SupervisedCommandError::ResourceBudgetExceeded {
                resource: SupervisorResource::CaptureBytes,
                limit: 10,
            }
        );
        assert_eq!(budget.active_processes.load(Ordering::Acquire), 2);
        assert_eq!(budget.active_capture_groups.load(Ordering::Acquire), 2);
        assert_eq!(budget.reserved_capture_bytes.load(Ordering::Acquire), 10);
        drop(first);
        let replacement = budget.acquire(4).expect("released bytes must be reusable");
        drop(replacement);
        drop(second);
        assert_eq!(budget.active_processes.load(Ordering::Acquire), 0);
        assert_eq!(budget.active_capture_groups.load(Ordering::Acquire), 0);
        assert_eq!(budget.reserved_capture_bytes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn detached_capture_groups_hold_the_thread_budget_after_process_release() {
        let budget = SupervisorBudget::new(2, 100);
        let SupervisorAdmission {
            process: first_process,
            capture: first_capture,
        } = budget.acquire(10).expect("first admission");
        drop(first_process);
        let SupervisorAdmission {
            process: second_process,
            capture: second_capture,
        } = budget.acquire(10).expect("second admission");
        drop(second_process);

        let error = budget
            .acquire(1)
            .expect_err("unconfirmed collectors must retain capture-thread capacity");
        assert_eq!(
            error,
            SupervisedCommandError::ResourceBudgetExceeded {
                resource: SupervisorResource::CaptureGroups,
                limit: 2,
            }
        );
        assert_eq!(budget.active_processes.load(Ordering::Acquire), 0);
        assert_eq!(budget.active_capture_groups.load(Ordering::Acquire), 2);
        drop(first_capture);
        drop(second_capture);
        assert_eq!(budget.active_capture_groups.load(Ordering::Acquire), 0);
    }

    #[test]
    fn production_supervisor_envelope_is_pinned_below_the_legacy_shape() {
        assert_eq!(MAX_SUPERVISED_PROCESSES, 16);
        assert_eq!(MAX_GLOBAL_CAPTURE_BYTES, 64 * 1024 * 1024);
        assert_eq!(
            capture_reservation_bytes(DEFAULT_CAPTURE_LIMITS),
            16 * 1024 * 1024
        );
        assert_eq!(
            MAX_GLOBAL_CAPTURE_BYTES / capture_reservation_bytes(DEFAULT_CAPTURE_LIMITS),
            4
        );
        assert_eq!(CAPTURE_THREAD_STACK_BYTES, 256 * 1024);
    }

    #[test]
    fn compatibility_mapping_preserves_lifecycle_and_overflow_types() {
        assert!(matches!(
            supervisor_error_to_runner(SupervisedCommandError::Cancelled),
            RunnerError::Cancelled
        ));
        assert!(matches!(
            supervisor_error_to_runner(SupervisedCommandError::OutputLimitExceeded {
                scope: OutputScope::Combined,
                limit: 1200,
            }),
            RunnerError::OutputLimitExceeded { ref scope, limit }
                if scope == "combined" && limit == 1200
        ));
    }

    #[test]
    fn capture_read_error_sets_a_supervisor_stop_reason() {
        struct BrokenReader;
        impl Read for BrokenReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("injected capture failure"))
            }
        }

        let total = AtomicUsize::new(0);
        let stop_reason = AtomicU8::new(STOP_NONE);
        let capture_control = AtomicU8::new(CAPTURE_RUNNING);
        let error = read_capped(
            BrokenReader,
            OutputScope::Stdout,
            CaptureLimits {
                per_stream: 1024,
                combined: 2048,
            },
            &total,
            &stop_reason,
            &capture_control,
        )
        .expect_err("reader failure must be terminal");
        assert!(matches!(error, SupervisedCommandError::Capture(_)));
        assert_eq!(stop_reason.load(Ordering::Acquire), STOP_CAPTURE);
    }

    #[test]
    fn pre_cancelled_supervisor_never_spawns_the_child() {
        let ws = Workspace::new().expect("workspace");
        let marker = ws.path().join("spawned");
        let script = format!("#!/bin/sh\ntouch {}\n", marker.display());
        let cmd = sh_script_command(&ws, "must-not-spawn.sh", &script);
        let cancellation = CommandCancellation::new();
        cancellation.cancel();
        let error = run_test_supervised(cmd, Duration::from_secs(5), &cancellation)
            .expect_err("pre-cancelled work must fail before spawn");
        assert_eq!(error, SupervisedCommandError::Cancelled);
        assert!(!marker.exists(), "cancelled child must never execute");
    }

    #[cfg(unix)]
    #[test]
    fn output_overflow_kills_and_reaps_the_process_group() {
        let ws = Workspace::new().expect("workspace");
        let pidfile = ws.path().join("overflow-grandchild.pid");
        let script = format!(
            "#!/bin/sh\n(sleep 0.1; yes z) &\nGRAND=$!\nprintf '%s' \"$GRAND\" > {}\nwait\n",
            pidfile.display()
        );
        let cmd = sh_script_command(&ws, "overflow-group.sh", &script);
        let error = run_test_with_limits(
            cmd,
            Duration::from_secs(5),
            None,
            CaptureLimits {
                per_stream: 1024,
                combined: 2048,
            },
        )
        .expect_err("unbounded grandchild output must be stopped");
        assert!(matches!(
            error,
            SupervisedCommandError::OutputLimitExceeded { .. }
        ));

        let pid: libc::pid_t = std::fs::read_to_string(&pidfile)
            .expect("grandchild pid must be recorded before output starts")
            .trim()
            .parse()
            .expect("pid must parse");
        let dead = (0..200).any(|_| {
            let rc = unsafe { libc::kill(pid, 0) };
            if rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
            false
        });
        assert!(dead, "overflowing grandchild process {pid} must be gone");
    }

    #[cfg(unix)]
    #[test]
    fn explicit_cancellation_kills_and_reaps_the_process_group() {
        let ws = Workspace::new().expect("workspace");
        let pidfile = ws.path().join("cancel-grandchild.pid");
        let script = format!(
            "#!/bin/sh\nsleep 30 &\nGRAND=$!\nprintf '%s' \"$GRAND\" > {}\nwait\n",
            pidfile.display()
        );
        let cmd = sh_script_command(&ws, "cancel-group.sh", &script);
        let cancellation = CommandCancellation::new();
        let worker_cancellation = cancellation.clone();
        let worker = std::thread::spawn(move || {
            run_test_supervised(cmd, Duration::from_secs(30), &worker_cancellation)
        });

        let pid: libc::pid_t = (0..500)
            .find_map(|_| {
                if let Ok(value) = std::fs::read_to_string(&pidfile) {
                    if let Ok(pid) = value.trim().parse() {
                        return Some(pid);
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
                None
            })
            .expect("grandchild pid must be recorded");
        cancellation.cancel();
        let error = worker
            .join()
            .expect("supervisor thread must not panic")
            .expect_err("cancelled command must fail closed");
        assert_eq!(error, SupervisedCommandError::Cancelled);

        let dead = (0..200).any(|_| {
            let rc = unsafe { libc::kill(pid, 0) };
            if rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
            false
        });
        assert!(dead, "cancelled grandchild process {pid} must be gone");
    }

    #[cfg(unix)]
    #[test]
    fn deferred_reaper_retains_cleanup_hold_until_child_is_reaped() {
        struct DropSignal(Arc<AtomicBool>);

        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let hold_dropped = Arc::new(AtomicBool::new(false));
        let cancellation =
            CommandCancellation::new_with_cleanup_hold(DropSignal(Arc::clone(&hold_dropped)));
        let cleanup_hold = cancellation.cleanup_hold();
        drop(cancellation);
        assert!(
            !hold_dropped.load(Ordering::Acquire),
            "a child cleanup clone must retain the opaque admission hold"
        );

        let admission = SUPERVISOR_BUDGET
            .acquire(2048)
            .expect("supervisor admission");
        let (reap_slot, capture_reservation) = admission.into_slots();
        drop(capture_reservation);
        let child = Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .expect("spawn deferred-reaper fixture");
        let deferred = DeferredChild {
            child,
            _reap_slot: reap_slot,
            _cleanup_hold: cleanup_hold,
        };
        let (sender, receiver) = mpsc::channel();
        let reaper = std::thread::spawn(move || child_reaper_loop(receiver));
        assert!(sender.send(deferred).is_ok(), "enqueue deferred child");
        drop(sender);
        reaper.join().expect("local reaper must finish");

        assert!(
            hold_dropped.load(Ordering::Acquire),
            "admission hold must release only after the deferred child is reaped"
        );
    }

    /// A child that exits non-zero must return Ok with that exit code (timeout
    /// helper does not map exit codes — callers do that).
    #[test]
    fn run_command_with_timeout_non_zero_exit_ok() {
        let ws = Workspace::new().expect("workspace");
        let cmd = sh_script_command(&ws, "fail.sh", "#!/bin/sh\nexit 42\n");

        let output = run_test_with_timeout(cmd, Duration::from_secs(5))
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
        let result = run_test_with_timeout(cmd, Duration::from_secs(5));
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

    #[cfg(unix)]
    #[test]
    fn setsid_escape_risk_fails_before_spawn_without_platform_containment() {
        let ws = Workspace::new().expect("workspace");
        let marker = ws.path().join("setsid-spawned");
        let script = format!(
            "#!/bin/sh\nsetsid /bin/sh -c 'touch {}'\n",
            marker.display()
        );
        let cmd = sh_script_command(&ws, "setsid-escape.sh", &script);
        let error = run_command_supervised_with_limits_in_containment(
            cmd,
            Duration::from_secs(5),
            None,
            CaptureLimits {
                per_stream: 1024,
                combined: 2048,
            },
            None,
            ContainmentUnavailable::EscapableUnixProcessGroup,
        )
        .expect_err("an escapable process group must not authorize spawn");
        assert!(
            matches!(
                error,
                SupervisedCommandError::ContainmentUnavailable(
                    ContainmentUnavailable::EscapableUnixProcessGroup
                )
            ),
            "unexpected containment error: {error:?}"
        );
        assert!(!marker.exists(), "setsid fixture must never be spawned");
    }

    #[test]
    fn unsupported_platform_fails_before_spawn() {
        let ws = Workspace::new().expect("workspace");
        let marker = ws.path().join("unsupported-spawned");
        let script = format!("#!/bin/sh\ntouch {}\n", marker.display());
        let cmd = sh_script_command(&ws, "unsupported.sh", &script);
        let error = run_command_supervised_with_limits_in_containment(
            cmd,
            Duration::from_secs(5),
            None,
            CaptureLimits {
                per_stream: 1024,
                combined: 2048,
            },
            None,
            ContainmentUnavailable::UnsupportedPlatform,
        )
        .expect_err("unsupported platforms must not spawn");
        assert!(
            matches!(
                error,
                SupervisedCommandError::ContainmentUnavailable(
                    ContainmentUnavailable::UnsupportedPlatform
                )
            ),
            "unexpected containment error: {error:?}"
        );
        assert!(
            !marker.exists(),
            "unsupported fixture must never be spawned"
        );
    }

    #[cfg(unix)]
    #[test]
    fn supervised_child_drop_kills_and_reaps_within_the_cleanup_bound() {
        let ws = Workspace::new().expect("workspace");
        let mut cmd = sh_script_command(&ws, "drop-child.sh", "#!/bin/sh\nsleep 30\n");
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        configure_process_group(&mut cmd);
        child_reaper_sender().expect("start shared child reaper");
        let admission = SUPERVISOR_BUDGET
            .acquire(2048)
            .expect("supervisor admission");
        let (reap_slot, capture_reservation) = admission.into_slots();
        drop(capture_reservation);
        let child = cmd.spawn().expect("spawn drop fixture");
        let pid = child.id() as libc::pid_t;
        let supervised = SupervisedChild::new(child, reap_slot, None);

        let started = Instant::now();
        drop(supervised);
        let elapsed = started.elapsed();

        let dead = (0..200).any(|_| {
            let rc = unsafe { libc::kill(pid, 0) };
            if rc == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
            false
        });
        assert!(
            dead,
            "dropped supervised child {pid} must be gone and reaped"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "drop cleanup must be bounded; elapsed: {elapsed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn reaped_child_retains_process_permit_until_supervisor_drop() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "exit 0"])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_process_group(&mut cmd);
        child_reaper_sender().expect("start shared child reaper");
        let admission = SUPERVISOR_BUDGET.acquire(0).expect("supervisor admission");
        let (reap_slot, capture_reservation) = admission.into_slots();
        drop(capture_reservation);
        let child = cmd.spawn().expect("spawn reap fixture");
        let mut supervised = SupervisedChild::new(child, reap_slot, None);

        let reaped = (0..200).any(|_| {
            if supervised.try_wait().expect("try wait").is_some() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
            false
        });
        assert!(reaped, "fixture must exit");
        assert!(
            supervised.reap_slot.is_some(),
            "process permit must cover capture teardown after direct-child reap"
        );
        drop(supervised);
    }

    #[test]
    fn version_probe_uses_the_supervisor_deadline() {
        let ws = Workspace::new().expect("workspace");
        let cmd = sh_script_command(&ws, "slow-version.sh", "#!/bin/sh\nsleep 5\n");
        let started = Instant::now();
        let error = run_test_version_probe_with_limits(
            cmd,
            None,
            Duration::from_millis(100),
            CaptureLimits {
                per_stream: 1024,
                combined: 2048,
            },
        )
        .expect_err("hanging version probe must time out");
        assert_eq!(error, SupervisedCommandError::Timeout);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "version deadline must return promptly"
        );
    }

    #[test]
    fn version_probe_uses_the_supervisor_output_cap() {
        let ws = Workspace::new().expect("workspace");
        let cmd = sh_script_command(&ws, "noisy-version.sh", "#!/bin/sh\nyes v | head -c 1025\n");
        let error = run_test_version_probe_with_limits(
            cmd,
            None,
            Duration::from_secs(2),
            CaptureLimits {
                per_stream: 1024,
                combined: 2048,
            },
        )
        .expect_err("noisy version probe must fail closed");
        assert_eq!(
            error,
            SupervisedCommandError::OutputLimitExceeded {
                scope: OutputScope::Stdout,
                limit: 1024,
            }
        );
    }

    #[test]
    fn version_probe_propagates_pre_spawn_cancellation() {
        let ws = Workspace::new().expect("workspace");
        let marker = ws.path().join("probe-spawned");
        let script = format!("#!/bin/sh\ntouch {}\n", marker.display());
        let cmd = sh_script_command(&ws, "cancel-version.sh", &script);
        let cancellation = CommandCancellation::new();
        cancellation.cancel();
        let error = run_test_version_probe_with_limits(
            cmd,
            Some(&cancellation),
            Duration::from_secs(2),
            CaptureLimits {
                per_stream: 1024,
                combined: 2048,
            },
        )
        .expect_err("cancelled probe must not spawn");
        assert_eq!(error, SupervisedCommandError::Cancelled);
        assert!(!marker.exists(), "cancelled probe must not execute");
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
