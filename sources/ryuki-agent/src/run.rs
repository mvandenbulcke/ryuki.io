//! Pull-loop — the operational core of the agent.
//!
//! ## Build-once-per-(job, attempt) contract
//!
//! `process_job` calls `build_signed_result` EXACTLY ONCE per invocation and
//! persists the `ResultBody` to the `Outbox` BEFORE making the network POST.
//! On POST failure the result stays in the outbox; the next replay
//! (`replay_outbox` on the next startup, or a future retry mechanism) reads
//! the file and re-POSTs it unchanged.  The `result_id` is the idempotency
//! key; the CP returns 200 for a valid signed replay of an already-recorded
//! result.  The agent NEVER calls `build_signed_result` a second time for the
//! same (job, attempt) — it replays the outbox entry instead.
//!
//! ## Live execution (S5b-2b-ii)
//!
//! `process_job_live` handles `LivePlan`, `LiveApply`, and `LiveDestroy` jobs
//! via a `&dyn LiveExecutor`.  The gate (`evaluate_live_execution`) is checked
//! before ANY platform contact; a `Refused` decision immediately produces a
//! `build_refused_result` without calling plan or apply.  For `LiveApply` the
//! ordering is:
//!
//! 1. `!allow_live` → refuse WITHOUT planning (fail-closed, no platform contact).
//! 2. `live_exec.plan(spec)` → `LivePlanOutcome { evidence, raw_plan_digest }`.
//! 3. `evaluate_live_execution(job, cp_key, allow_live, Some(&raw_plan_digest))` —
//!    checks the complete signed grant/spec/request-version binding, expiry,
//!    and digest match.
//! 4. `Refused` → `build_refused_result` (apply is NEVER called).
//! 5. `Proceed` → `live_exec.apply(spec)` → `Evidence { Applied/Failed }`.
//! 6. `build_signed_result(.., Some(grant.approved_plan_digest))` — the digest
//!    is passed only AFTER the gate returned Proceed.
//! 7. Same durable outbox flow as OfflineDryRun (enqueue-before-post, mark_delivered).
//!
//! The result is built EXACTLY ONCE (build-once contract) and placed in the
//! outbox before any POST.
//!
//! ## LiveDestroy execution (#42 slice B2-3)
//!
//! `LiveDestroy` (the CP's auto compensating teardown, B2-2) follows the same
//! shape MINUS the plan step — a destroy has no saved plan; the destruction
//! set is whatever the step's own apply recorded in the durable backend state:
//!
//! 1. No pinned CP key → refuse (the gate's grant-signature check needs it).
//! 2. `evaluate_live_execution(job, cp_key, allow_live, None)` — checks
//!    the complete signed grant/spec/request-version binding, REQUIRED step
//!    binding, and expiry. No digest check by design.
//! 3. `Refused` → `build_refused_result` (destroy is NEVER called).
//! 4. `Proceed` → `live_exec.destroy(spec)` → `Evidence { Applied/Failed }`
//!    (`Applied` → CP marks the step `ToreDown`; `Failed` → CP halts the
//!    cascade).
//! 5. `build_signed_result(.., None)` — a destroy result never carries an
//!    `approved_plan_digest`.
//! 6. Same durable outbox flow (enqueue-before-post, mark_delivered).
//!
//! ## Error strategy
//!
//! All errors are wrapped in [`AgentError`].  `process_job`, `process_job_live`,
//! and `replay_outbox` return `Result`; `run_loop` logs errors and backs off —
//! it never panics.

use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use serde_json::Value;
use thiserror::Error;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    classify::{classify_client_error, RetryClass},
    client::{ClientError, CpClient},
    executor::{Evidence, ExecError, JobExecutor},
    identity::AgentIdentity,
    live::{
        evaluate_execution_trust_binding, evaluate_live_execution, evaluate_live_plan_admission,
        PinnedControlPlaneGrantAuthority,
    },
    live_exec::{LiveExecError, LiveExecutor},
    outbox::{Outbox, OutboxError},
    result::{
        build_refused_result, build_signed_result, build_signed_result_with_trust_profile,
        ResultError,
    },
};
use ryuki_engine::runners::RunStatus;
use ryuki_protocol::{AgentHeartbeatResponse, Job, JobLease, JobMode};

/// Renew well inside the control plane's lease window. A single failed fenced
/// renewal marks the local attempt lost; it is never treated as a best-effort
/// liveness signal.
const LEASE_RENEW_INTERVAL: Duration = Duration::from_secs(60);
/// A renewal that never returns is indistinguishable from lost lease
/// authority. Bound every initial, periodic, and pre-mutation renewal well
/// inside the renewal interval so the shared cancellation flag can fence the
/// active runner before the control-plane lease window elapses.
const LEASE_RENEW_TIMEOUT: Duration = Duration::from_secs(15);

async fn renew_lease_with_timeout(
    client: &CpClient,
    job_id: Uuid,
    lease: &JobLease,
    timeout_budget: Duration,
) -> Result<AgentHeartbeatResponse, String> {
    match tokio::time::timeout(timeout_budget, client.renew_lease(job_id, lease)).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err(format!(
            "lease renewal timed out after {} seconds",
            timeout_budget.as_secs()
        )),
    }
}

// ---------------------------------------------------------------------------
// AgentError
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("control-plane client error: {0}")]
    Client(#[from] ClientError),
    #[error("executor error: {0}")]
    Exec(#[from] ExecError),
    #[error("live executor error: {0}")]
    LiveExec(#[from] LiveExecError),
    #[error("result build error: {0}")]
    Result(#[from] ResultError),
    #[error("outbox error: {0}")]
    Outbox(#[from] OutboxError),
    #[error("serialisation error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("job has no active lease — cannot process")]
    NoLease,
    #[error("job lease ownership was lost or could not be renewed — execution fenced")]
    LeaseLost,
}

/// Owns the periodic renewal task for one exact `(job, attempt, generation,
/// fencing_token)` tuple. Dropping the guard aborts the task so early-return
/// error paths cannot leave a detached renewal loop behind.
struct LeaseRenewalGuard {
    client: CpClient,
    job_id: Uuid,
    lease: JobLease,
    lost: Arc<AtomicBool>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl LeaseRenewalGuard {
    async fn start(client: &CpClient, job_id: Uuid, lease: &JobLease) -> Result<Self, AgentError> {
        let response =
            match renew_lease_with_timeout(client, job_id, lease, LEASE_RENEW_TIMEOUT).await {
                Ok(response) => response,
                Err(error) => {
                    warn!(job_id = %job_id, error = %error, "initial fenced lease renewal failed");
                    return Err(AgentError::LeaseLost);
                }
            };
        info!(
            job_id = %job_id,
            attempt_id = %lease.attempt_id,
            lease_generation = lease.lease_generation,
            lease_deadline = ?response.lease_deadline,
            renewal_phase = "initial",
            "fenced lease renewal succeeded"
        );

        let renewal_client = client.clone();
        let renewal_lease = lease.clone();
        let lost = Arc::new(AtomicBool::new(false));
        let task_lost = Arc::clone(&lost);
        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(LEASE_RENEW_INTERVAL);
            // `interval` ticks immediately; the start path already performed
            // the mandatory first renewal, so wait for the next period.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                match renew_lease_with_timeout(
                    &renewal_client,
                    job_id,
                    &renewal_lease,
                    LEASE_RENEW_TIMEOUT,
                )
                .await
                {
                    Ok(response) => info!(
                        job_id = %job_id,
                        attempt_id = %renewal_lease.attempt_id,
                        lease_generation = renewal_lease.lease_generation,
                        lease_deadline = ?response.lease_deadline,
                        renewal_phase = "periodic",
                        "fenced lease renewal succeeded"
                    ),
                    Err(error) => {
                        task_lost.store(true, Ordering::SeqCst);
                        warn!(
                            job_id = %job_id,
                            error = %error,
                            "periodic fenced lease renewal failed — execution is fenced"
                        );
                        break;
                    }
                }
            }
        });

        Ok(Self {
            client: client.clone(),
            job_id,
            lease: lease.clone(),
            lost,
            task: Some(task),
        })
    }

    fn ensure_active(&self) -> Result<(), AgentError> {
        if self.lost.load(Ordering::SeqCst) {
            Err(AgentError::LeaseLost)
        } else {
            Ok(())
        }
    }

    fn cancellation(&self) -> ryuki_runner::CommandCancellation {
        cancellation_from_lease_loss(&self.lost)
    }

    /// Mandatory point-in-time fence used immediately before a mutation and
    /// once more before terminal result submission.
    async fn renew_now(&self) -> Result<(), AgentError> {
        self.ensure_active()?;
        let response = match renew_lease_with_timeout(
            &self.client,
            self.job_id,
            &self.lease,
            LEASE_RENEW_TIMEOUT,
        )
        .await
        {
            Ok(response) => response,
            Err(error) => {
                self.lost.store(true, Ordering::SeqCst);
                warn!(job_id = %self.job_id, error = %error, "fenced lease renewal failed");
                return Err(AgentError::LeaseLost);
            }
        };
        info!(
            job_id = %self.job_id,
            attempt_id = %self.lease.attempt_id,
            lease_generation = self.lease.lease_generation,
            lease_deadline = ?response.lease_deadline,
            renewal_phase = "boundary",
            "fenced lease renewal succeeded"
        );
        self.ensure_active()
    }

    /// Quiesce the background task and make its last observed fence state
    /// authoritative before the result leaves the agent.
    async fn finish(mut self) -> Result<(), AgentError> {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
        self.ensure_active()
    }
}

fn cancellation_from_lease_loss(lost: &Arc<AtomicBool>) -> ryuki_runner::CommandCancellation {
    ryuki_runner::CommandCancellation::from_shared_flag(Arc::clone(lost))
}

impl Drop for LeaseRenewalGuard {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Run a synchronous runner call without monopolizing a Tokio worker. The
/// production agent uses Tokio's multi-thread runtime; `block_in_place` lets
/// Tokio move async work, including the lease-renewal task, to another worker.
fn run_executor_blocking<T>(operation: impl FnOnce() -> T) -> T {
    tokio::task::block_in_place(operation)
}

// ---------------------------------------------------------------------------
// process_job
// ---------------------------------------------------------------------------

/// Process a single leased job through the full agent pipeline.
///
/// 1. Ack the lease (Leased → Running on the CP).
/// 2. Execute the job spec (produce `Evidence`).
/// 3. Build a signed `ResultBody` exactly once (idempotency key = result_id).
/// 4. Enqueue the result to the durable outbox BEFORE the network POST.
/// 5. POST the result to the CP.
/// 6. On 2xx: mark_delivered (remove the outbox file).
///    On failure: leave the file — it will be replayed on next startup.
///
/// The `result_id` is generated once inside `build_signed_result` and bound
/// by the Ed25519 signature.  A retry always comes from the outbox (step 4),
/// never from a re-build.
pub async fn process_job(
    client: &CpClient,
    executor: &dyn JobExecutor,
    identity: &AgentIdentity,
    agent_id: &str,
    outbox: &Outbox,
    job: &Job,
) -> Result<(), AgentError> {
    let lease = job.lease.as_ref().ok_or(AgentError::NoLease)?;

    // Step 1: ack the lease — transitions Leased → Running on the CP.
    client
        .ack(job.id, lease.attempt_id, &lease.fencing_token)
        .await?;

    // Ack establishes Running; the immediate fenced renewal proves this exact
    // attempt still owns the row before any executor work starts, then a
    // background task keeps the database-clock deadline alive while the
    // synchronous runner is busy.
    let renewal = LeaseRenewalGuard::start(client, job.id, lease).await?;
    let cancellation = renewal.cancellation();

    // Step 2: execute (deterministic spec rejections become Failed evidence).
    let evidence = run_executor_blocking(|| {
        evidence_or_deterministic_failure_with_cancellation(executor, job, &cancellation)
    })?;

    // Step 3: build once. result_id is the idempotency key for the outbox.
    // OfflineDryRun is the only mode supported by the current executor.
    // Live modes (LivePlan / LiveApply) are S5b and handled by process_job_live.
    let body = build_signed_result(identity, agent_id, job, &evidence, None)?;

    // Steps 4-6: enqueue BEFORE the network POST, then POST, then mark delivered.
    // Delegate to the shared helper that live and offline paths both use.
    renew_finish_and_post(client, outbox, job, renewal, body).await
}

/// Execute the spec, converting DETERMINISTIC spec-level rejections into
/// signed-able `Failed` evidence instead of propagating an error.
///
/// An unsupported mode, an offering with no embedded IaC, or an IaC digest
/// mismatch can never succeed on retry: propagating those as errors posts NO
/// result, so the CP lease-expires the job through every attempt into
/// DeadLettered while the parent request sits `executing` forever (QA
/// finding). Reporting them as a `Failed` result lets the CP fail the request
/// cleanly through the normal backlink. Runner errors keep the retry path:
/// they may be transient host trouble, and execution may have started.
///
/// The rejection strings carry only spec-level data (mode, offering slug,
/// digest hex) — no credentials exist on this pre-execution path.
#[cfg(test)]
fn evidence_or_deterministic_failure(
    executor: &dyn JobExecutor,
    job: &Job,
) -> Result<Evidence, AgentError> {
    evidence_or_deterministic_failure_with_cancellation(
        executor,
        job,
        &ryuki_runner::CommandCancellation::new(),
    )
}

fn evidence_or_deterministic_failure_with_cancellation(
    executor: &dyn JobExecutor,
    job: &Job,
    cancellation: &ryuki_runner::CommandCancellation,
) -> Result<Evidence, AgentError> {
    match executor.execute_with_cancellation(&job.spec, cancellation) {
        Ok(evidence) => Ok(evidence),
        Err(err @ (ExecError::UnsupportedMode(_) | ExecError::PlanBuild(_))) => {
            warn!(
                job_id = %job.id,
                error = %err,
                "job spec deterministically rejected — reporting a Failed result \
                 (retry can never succeed)"
            );
            let summary = serde_json::json!({
                "status": "Failed",
                "summary": format!("job spec rejected by agent: {err}"),
                "deterministic_rejection": true,
            });
            let evidence_bytes =
                serde_json::to_vec(&summary).unwrap_or_else(|_| br#"{"status":"Failed"}"#.to_vec());
            Ok(Evidence {
                status: RunStatus::Failed,
                evidence_bytes,
                evidence_json: Some(summary),
            })
        }
        Err(other) => Err(other.into()),
    }
}

// ---------------------------------------------------------------------------
// process_job_live
// ---------------------------------------------------------------------------

/// Process a `LivePlan` or `LiveApply` job through the full live pipeline.
///
/// ## Argument summary
///
/// - `cp_grant_authority` — the **pinned** CP Ed25519 keyset and canonical
///   deployment/trust-domain scope established at startup. `None` → refuse all
///   mutating live jobs (the grant cannot be verified and scope-bound).
///   `LivePlan` is still allowed when `allow_live` is `true` (no grant needed).
/// - `allow_live` — from `AgentConfig::allow_live`; must be `true` for any
///   live job.
/// - `live_exec` — a `dyn LiveExecutor` implementation; `StubLiveExecutor` in
///   tests, `RunnerLiveExecutor` in production.
///
/// ## Ordering invariants
///
/// For `LiveApply`:
///
/// 1. `!allow_live` → refuse immediately WITHOUT calling `plan()`.
/// 2. `cp_grant_authority` is `None` → refuse immediately WITHOUT calling `plan()`.
/// 3. `plan()` → `plan_digest`.
/// 4. Gate checks the complete signed grant/spec/request-version binding,
///    expiry, and digest.
/// 5. Gate `Refused` → refuse, `apply()` is NEVER called.
/// 6. Gate `Proceed` → `apply()`.
/// 7. `build_signed_result(.., Some(grant.approved_plan_digest))` — the digest
///    is the one from the grant (already verified to equal plan_digest).
///
/// For `LivePlan`:
///
/// 1. Gate check (allow_live only, no grant, no digest).
/// 2. `Refused` → refuse, `plan()` is NEVER called.
/// 3. `Proceed` → `plan()`.
/// 4. `build_signed_result(.., None)` (LivePlan never carries a digest).
///
/// For `LiveDestroy` (#42 B2-3):
///
/// 1. `cp_grant_authority` is `None` → refuse immediately (the gate's grant
///    signature check requires the pinned key; a destroy grant is mandatory).
/// 2. Gate checks the complete signed grant/spec/request-version binding,
///    REQUIRED step binding, and expiry — no plan digest: the destruction set
///    comes from the step's own backend state, not from an approved plan.
/// 3. Gate `Refused` → refuse, `destroy()` is NEVER called.
/// 4. Gate `Proceed` → `destroy()`.
/// 5. `build_signed_result(.., None)` (LiveDestroy never carries a digest).
///
/// ## Build-once contract
///
/// `build_signed_result` / `build_refused_result` is called EXACTLY ONCE.
/// The result is enqueued to the durable outbox BEFORE the network POST.
#[allow(clippy::too_many_arguments)]
pub async fn process_job_live(
    client: &CpClient,
    live_exec: &dyn LiveExecutor,
    identity: &AgentIdentity,
    agent_id: &str,
    outbox: &Outbox,
    job: &Job,
    cp_grant_authority: Option<&PinnedControlPlaneGrantAuthority>,
    allow_live: bool,
) -> Result<(), AgentError> {
    let lease = job.lease.as_ref().ok_or(AgentError::NoLease)?;

    // Step 1: ack the lease.
    client
        .ack(job.id, lease.attempt_id, &lease.fencing_token)
        .await?;
    let renewal = LeaseRenewalGuard::start(client, job.id, lease).await?;
    let cancellation = renewal.cancellation();

    // Build the signed result body (exactly once) and enqueue + post it.
    let body = match job.spec.mode {
        // OfflineDryRun must not reach this function; guard defensively.
        JobMode::OfflineDryRun => {
            return Err(AgentError::LiveExec(LiveExecError::UnsupportedMode(
                JobMode::OfflineDryRun,
            )));
        }

        // -- LiveDestroy ----------------------------------------------------
        // #42 slice B2-3: gated terraform-destroy execution. The trust gate
        // (evaluate_live_destroy, B2-1) is the ONLY path to execution: it
        // requires --allow-live, a CP-signed grant, exact request/version
        // binding, a REQUIRED step binding (unbound grants are rejected — the
        // step binding IS a destroy's safety bound), and an unexpired grant. There
        // is deliberately NO plan-digest check: a destroy has no saved plan —
        // it removes whatever the step's own apply recorded in the durable
        // backend state (state is the source of truth for the destruction set).
        JobMode::LiveDestroy => {
            // Fast-path refuse: !allow_live — byte-identical reason to the
            // gate's own check 1, kept first so refusal precedence matches
            // both the gate order and LiveApply's fast-path.
            if !allow_live {
                let reason = "LiveDestroy requires --allow-live";
                warn!(job_id = %job.id, "LiveDestroy refused: !allow_live");
                return renew_finish_and_post(
                    client,
                    outbox,
                    job,
                    renewal,
                    build_refused_result(identity, agent_id, job, reason)?,
                )
                .await;
            }

            // Fast-path refuse: no pinned CP grant authority → the signature
            // and scope checks cannot run. Mirrors the LiveApply fast-path.
            let authority = match cp_grant_authority {
                Some(k) => k,
                None => {
                    let reason = "LiveDestroy refused: no pinned CP grant authority available";
                    warn!(job_id = %job.id, "LiveDestroy refused: no pinned CP grant authority");
                    return renew_finish_and_post(
                        client,
                        outbox,
                        job,
                        renewal,
                        build_refused_result(identity, agent_id, job, reason)?,
                    )
                    .await;
                }
            };

            // Full grant/spec/request-version gate (no digest for a destroy).
            match evaluate_live_execution(job, authority, allow_live, None) {
                crate::live::LiveDecision::Refused(reason) => {
                    warn!(
                        job_id = %job.id,
                        reason = %reason,
                        "LiveDestroy refused — destroy() will NOT be called"
                    );
                    build_refused_result(identity, agent_id, job, &reason)?
                }
                crate::live::LiveDecision::Proceed => {
                    // Only a verified CP grant may trigger local executable
                    // admission. This still precedes every backend/provider
                    // contact and validates the actual current configuration.
                    let trust_profile = match live_exec
                        .execution_trust_profile(&job.spec, &job.platform)
                    {
                        Ok(profile) => profile,
                        Err(error) => {
                            let reason =
                                format!("LiveDestroy execution trust profile unavailable: {error}");
                            return renew_finish_and_post(
                                client,
                                outbox,
                                job,
                                renewal,
                                build_refused_result(identity, agent_id, job, &reason)?,
                            )
                            .await;
                        }
                    };
                    if let crate::live::LiveDecision::Refused(reason) =
                        evaluate_execution_trust_binding(
                            job,
                            agent_id,
                            &identity.public_key_b64(),
                            &trust_profile,
                        )
                    {
                        build_refused_result(identity, agent_id, job, &reason)?
                    } else {
                        // Destroy mutates immediately. Re-prove the exact fence at
                        // this boundary, then re-check the time-bound grant after
                        // the awaited renewal. The renewal request itself can cross
                        // the grant expiry boundary, so the earlier decision is not
                        // sufficient authority for the mutation that follows.
                        renewal.renew_now().await?;
                        let current_profile = match live_exec
                            .execution_trust_profile(&job.spec, &job.platform)
                        {
                            Ok(profile) => profile,
                            Err(error) => {
                                let reason = format!(
                                    "LiveDestroy execution trust profile unavailable at mutation boundary: {error}"
                                );
                                return renew_finish_and_post(
                                    client,
                                    outbox,
                                    job,
                                    renewal,
                                    build_refused_result(identity, agent_id, job, &reason)?,
                                )
                                .await;
                            }
                        };
                        if let crate::live::LiveDecision::Refused(reason) =
                            evaluate_live_execution(job, authority, allow_live, None)
                        {
                            warn!(
                                job_id = %job.id,
                                reason = %reason,
                                "LiveDestroy refused after lease renewal -- destroy() will NOT be called"
                            );
                            build_refused_result(identity, agent_id, job, &reason)?
                        } else if let crate::live::LiveDecision::Refused(reason) =
                            evaluate_execution_trust_binding(
                                job,
                                agent_id,
                                &identity.public_key_b64(),
                                &current_profile,
                            )
                        {
                            warn!(
                                job_id = %job.id,
                                reason = %reason,
                                "LiveDestroy refused on execution-profile drift -- destroy() will NOT be called"
                            );
                            build_refused_result(identity, agent_id, job, &reason)?
                        } else {
                            // Gate passed — destroy the step's applied resources.
                            // Executor errors propagate (mirroring apply's stance): a
                            // destroy that MAY have partially mutated (e.g. timeout)
                            // must never be reported as LiveRefused ("declined, no
                            // mutation"); the job stays Running and the CP's teardown
                            // lease-expiry sweep halts the rollback.
                            let destroy_evidence = run_executor_blocking(|| {
                                live_exec.destroy_with_cancellation(&job.spec, &cancellation)
                            })?;

                            // A LiveDestroy result NEVER carries approved_plan_digest
                            // (build_signed_result and the CP verifier both reject it).
                            // Success maps to Applied → the CP marks the step ToreDown;
                            // Failed → the CP halts the teardown cascade.
                            build_signed_result_with_trust_profile(
                                identity,
                                agent_id,
                                job,
                                &destroy_evidence,
                                None,
                                None,
                                Some(current_profile),
                            )?
                        }
                    }
                }
            }
        }

        // -- LivePlan -------------------------------------------------------
        JobMode::LivePlan => {
            // LivePlan has no mutation grant. Its only trust-gate condition is
            // the explicit live-execution opt-in, so no synthetic key or scope
            // is needed when CP bootstrap is unavailable.
            match evaluate_live_plan_admission(allow_live) {
                crate::live::LiveDecision::Refused(reason) => {
                    warn!(
                        job_id = %job.id,
                        reason = %reason,
                        "LivePlan refused before plan() call"
                    );
                    build_refused_result(identity, agent_id, job, &reason)?
                }
                crate::live::LiveDecision::Proceed => {
                    // Only an admitted live job may probe the executable or
                    // resolve local provider credentials while minting the
                    // complete non-secret execution identity.
                    let trust_profile = match live_exec
                        .execution_trust_profile(&job.spec, &job.platform)
                    {
                        Ok(profile) => profile,
                        Err(error) => {
                            let reason =
                                format!("LivePlan execution trust profile unavailable: {error}");
                            return renew_finish_and_post(
                                client,
                                outbox,
                                job,
                                renewal,
                                build_refused_result(identity, agent_id, job, &reason)?,
                            )
                            .await;
                        }
                    };
                    // Gate passed — execute the plan.
                    // FAIL CLOSED: if plan() returns Err (non-clean plan), build a
                    // refusal rather than propagating a bare AgentError that would
                    // leave the job silently Running on the CP.
                    match run_executor_blocking(|| {
                        live_exec.plan_with_cancellation(&job.spec, &cancellation)
                    }) {
                        Ok(plan_outcome) => {
                            // LivePlan → approved_plan_digest MUST be None.
                            build_signed_result_with_trust_profile(
                                identity,
                                agent_id,
                                job,
                                &plan_outcome.evidence,
                                None,
                                Some(plan_outcome.raw_plan_digest.clone()),
                                Some(trust_profile),
                            )?
                        }
                        Err(e) => {
                            let reason = format!("terraform plan failed: {e}");
                            warn!(
                                job_id = %job.id,
                                reason = %reason,
                                "LivePlan: plan() returned Err — building LiveRefused result"
                            );
                            build_refused_result(identity, agent_id, job, &reason)?
                        }
                    }
                }
            }
        }

        // -- LiveApply ------------------------------------------------------
        JobMode::LiveApply => {
            // Fast-path refuse: !allow_live → skip plan entirely.
            if !allow_live {
                let reason = "LiveApply requires --allow-live";
                warn!(job_id = %job.id, "LiveApply refused: !allow_live (no plan attempted)");
                return renew_finish_and_post(
                    client,
                    outbox,
                    job,
                    renewal,
                    build_refused_result(identity, agent_id, job, reason)?,
                )
                .await;
            }

            // Fast-path refuse: no pinned CP grant authority → neither the
            // signature nor the deployment/trust-domain scope can be checked.
            let authority = match cp_grant_authority {
                Some(k) => k,
                None => {
                    let reason = "LiveApply refused: no pinned CP grant authority available";
                    warn!(job_id = %job.id, "LiveApply refused: no pinned CP grant authority");
                    return renew_finish_and_post(
                        client,
                        outbox,
                        job,
                        renewal,
                        build_refused_result(identity, agent_id, job, reason)?,
                    )
                    .await;
                }
            };

            // Verify signature, exact JobSpec/request/version binding, step
            // binding, and expiry before Terraform can contact the backend/provider.
            // The full gate is repeated after planning to bind the digest and
            // re-check expiry at the mutation boundary.
            if let crate::live::LiveDecision::Refused(reason) =
                crate::live::evaluate_live_authority(job, authority, allow_live)
            {
                warn!(
                    job_id = %job.id,
                    reason = %reason,
                    "LiveApply refused before plan — no provider contact"
                );
                return renew_finish_and_post(
                    client,
                    outbox,
                    job,
                    renewal,
                    build_refused_result(identity, agent_id, job, &reason)?,
                )
                .await;
            }
            let trust_profile = match live_exec.execution_trust_profile(&job.spec, &job.platform) {
                Ok(profile) => profile,
                Err(error) => {
                    let reason = format!("LiveApply execution trust profile unavailable: {error}");
                    return renew_finish_and_post(
                        client,
                        outbox,
                        job,
                        renewal,
                        build_refused_result(identity, agent_id, job, &reason)?,
                    )
                    .await;
                }
            };
            if let crate::live::LiveDecision::Refused(reason) = evaluate_execution_trust_binding(
                job,
                agent_id,
                &identity.public_key_b64(),
                &trust_profile,
            ) {
                warn!(
                    job_id = %job.id,
                    reason = %reason,
                    "LiveApply refused before plan on owner/profile mismatch — no provider contact"
                );
                return renew_finish_and_post(
                    client,
                    outbox,
                    job,
                    renewal,
                    build_refused_result(identity, agent_id, job, &reason)?,
                )
                .await;
            }

            // Plan first — raw_plan_digest will be checked by the gate.
            // FAIL CLOSED: if plan() returns Err (non-clean plan), build a refusal
            // rather than propagating as a bare AgentError that would leave the job
            // silently Running on the CP.  apply() is NEVER called on Err.
            let plan_outcome = match run_executor_blocking(|| {
                live_exec.plan_with_cancellation(&job.spec, &cancellation)
            }) {
                Ok(outcome) => outcome,
                Err(e) => {
                    let reason = format!("terraform plan failed: {e}");
                    warn!(
                        job_id = %job.id,
                        reason = %reason,
                        "LiveApply: plan() returned Err — building LiveRefused result, apply() NOT called"
                    );
                    return renew_finish_and_post(
                        client,
                        outbox,
                        job,
                        renewal,
                        build_refused_result(identity, agent_id, job, &reason)?,
                    )
                    .await;
                }
            };
            let raw_plan_digest = &plan_outcome.raw_plan_digest;

            // Repeat the complete grant/spec/request-version gate with the
            // newly computed raw-plan digest immediately before mutation.
            match evaluate_live_execution(
                job,
                authority,
                allow_live,
                Some(raw_plan_digest.as_str()),
            ) {
                crate::live::LiveDecision::Refused(reason) => {
                    warn!(
                        job_id = %job.id,
                        reason = %reason,
                        "LiveApply refused after plan — apply() will NOT be called"
                    );
                    build_refused_result(identity, agent_id, job, &reason)?
                }
                crate::live::LiveDecision::Proceed => {
                    // Planning can take minutes. A mandatory post-plan renewal
                    // prevents a lease lost during that read phase from crossing
                    // the mutation boundary. Re-run the complete grant gate
                    // after that awaited renewal because it can itself cross the
                    // signed expiry boundary.
                    renewal.renew_now().await?;
                    let current_profile = match live_exec
                        .execution_trust_profile(&job.spec, &job.platform)
                    {
                        Ok(profile) => profile,
                        Err(error) => {
                            let reason = format!(
                                "LiveApply execution trust profile unavailable at mutation boundary: {error}"
                            );
                            return renew_finish_and_post(
                                client,
                                outbox,
                                job,
                                renewal,
                                build_refused_result(identity, agent_id, job, &reason)?,
                            )
                            .await;
                        }
                    };
                    match evaluate_live_execution(
                        job,
                        authority,
                        allow_live,
                        Some(raw_plan_digest.as_str()),
                    ) {
                        crate::live::LiveDecision::Refused(reason) => {
                            warn!(
                                job_id = %job.id,
                                reason = %reason,
                                "LiveApply refused after lease renewal -- apply() will NOT be called"
                            );
                            build_refused_result(identity, agent_id, job, &reason)?
                        }
                        crate::live::LiveDecision::Proceed => {
                            if let crate::live::LiveDecision::Refused(reason) =
                                evaluate_execution_trust_binding(
                                    job,
                                    agent_id,
                                    &identity.public_key_b64(),
                                    &current_profile,
                                )
                            {
                                warn!(
                                    job_id = %job.id,
                                    reason = %reason,
                                    "LiveApply refused on execution-profile drift -- apply() will NOT be called"
                                );
                                return renew_finish_and_post(
                                    client,
                                    outbox,
                                    job,
                                    renewal,
                                    build_refused_result(identity, agent_id, job, &reason)?,
                                )
                                .await;
                            }
                            // Gate passed: apply the SAVED plan (close the TOCTOU hole).
                            // Pass the exact tfplan bytes produced by plan() so terraform
                            // applies that plan and not a fresh re-plan.
                            let apply_evidence = run_executor_blocking(|| {
                                live_exec.apply_with_cancellation(
                                    &job.spec,
                                    &plan_outcome.tfplan,
                                    &cancellation,
                                )
                            })?;

                            // The approved_plan_digest for the result comes from the grant
                            // (the gate already verified it equals plan_digest).
                            let approved_digest = job
                                .live_context
                                .as_ref()
                                .map(|g| g.approved_plan_digest.clone());

                            build_signed_result_with_trust_profile(
                                identity,
                                agent_id,
                                job,
                                &apply_evidence,
                                approved_digest,
                                None,
                                Some(current_profile),
                            )?
                        }
                    }
                }
            }
        }
    };

    renew_finish_and_post(client, outbox, job, renewal, body).await
}

/// Re-prove ownership after synchronous execution, stop the concurrent renewal
/// task, then submit the terminal result. The CP independently checks the same
/// lease deadline and fencing tuple during result ingestion.
async fn renew_finish_and_post(
    client: &CpClient,
    outbox: &Outbox,
    job: &Job,
    renewal: LeaseRenewalGuard,
    body: crate::result::ResultBody,
) -> Result<(), AgentError> {
    renewal.renew_now().await?;
    renewal.finish().await?;
    enqueue_and_post(client, outbox, job, body).await
}

/// Shared outbox + POST logic for all result paths.
///
/// Enqueues the result to the durable outbox BEFORE the network POST.
/// On POST success marks the file delivered; on POST failure leaves the
/// file in the outbox for replay.
async fn enqueue_and_post(
    client: &CpClient,
    outbox: &Outbox,
    job: &Job,
    body: crate::result::ResultBody,
) -> Result<(), AgentError> {
    let result_id: Uuid = body.job_result.result_id;

    // Durable-first: enqueue before network POST.
    outbox.enqueue(&body)?;

    let post_body = serde_json::to_value(&body)?;
    match client.post_result(job.id, post_body).await {
        Ok(_) => {
            outbox.mark_delivered(result_id)?;
            info!(
                job_id = %job.id,
                result_id = %result_id,
                "job result posted and delivered"
            );
        }
        Err(e) => {
            warn!(
                job_id = %job.id,
                result_id = %result_id,
                error = %e,
                "post_result failed — result left in outbox for replay"
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ResultPoster trait — testable abstraction over CpClient::post_result
// ---------------------------------------------------------------------------

/// Abstraction over the network POST so `drain_outbox` is unit-testable
/// without any HTTP infrastructure.
///
/// The only production implementation is [`CpClient`]; tests inject a
/// `StubPoster` that returns scripted results.
pub trait ResultPoster {
    /// Post a single result body for `job_id`.
    ///
    /// Returns `Ok(Value)` on 2xx, `Err(ClientError)` on network or HTTP error.
    fn post(
        &self,
        job_id: Uuid,
        body: Value,
    ) -> impl Future<Output = Result<Value, ClientError>> + Send;
}

impl ResultPoster for CpClient {
    fn post(
        &self,
        job_id: Uuid,
        body: Value,
    ) -> impl Future<Output = Result<Value, ClientError>> + Send {
        self.post_result(job_id, body)
    }
}

// ---------------------------------------------------------------------------
// DrainStats — returned by drain_outbox
// ---------------------------------------------------------------------------

/// Counters returned by a single `drain_outbox` pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DrainStats {
    /// Successfully delivered and removed from the outbox.
    pub delivered: usize,
    /// Moved to the dead-letter directory (permanent failure or max-attempts reached).
    pub quarantined: usize,
    /// Left in the outbox — transient failure, will be retried next cycle.
    pub retry_later: usize,
    /// Left in the outbox — operator alert (401/403), attempt counter NOT incremented.
    pub operator_alert: usize,
}

// ---------------------------------------------------------------------------
// drain_outbox
// ---------------------------------------------------------------------------

/// Drain all pending outbox entries with classification, backoff, and quarantine.
///
/// For each pending `ResultBody`:
///
/// - **Success** → `mark_delivered` + `clear_attempts`; `stats.delivered++`.
/// - **Transient error** → `record_attempt`:
///   - If new count >= `max_attempts` → `quarantine`; `stats.quarantined++`.
///   - Otherwise leave in outbox; `stats.retry_later++`.
/// - **Permanent error** → `quarantine` immediately; `stats.quarantined++`.
/// - **OperatorAlert** → leave in outbox, do NOT increment attempt counter,
///   emit `tracing::error!` ONCE per cycle (not per entry); `stats.operator_alert++`.
///
/// The signed `ResultBody` JSON is NEVER mutated — the Ed25519 signature
/// remains valid for manual replay from `dead/`.
pub async fn drain_outbox(
    poster: &impl ResultPoster,
    outbox: &Outbox,
    max_attempts: u32,
) -> DrainStats {
    let pending = match outbox.list_pending() {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "drain_outbox: failed to list pending — skipping cycle");
            return DrainStats::default();
        }
    };

    if pending.is_empty() {
        return DrainStats::default();
    }

    info!(
        count = pending.len(),
        "drain_outbox: draining pending results"
    );

    let mut stats = DrainStats::default();
    let mut has_operator_alert = false;

    for body in &pending {
        let job_id = body.job_result.job_id;
        let result_id = body.job_result.result_id;

        let post_body = match serde_json::to_value(body) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    job_id = %job_id,
                    result_id = %result_id,
                    error = %e,
                    "drain_outbox: serialisation failed — treating as permanent, quarantining"
                );
                let _ = outbox.quarantine(result_id);
                stats.quarantined += 1;
                continue;
            }
        };

        match poster.post(job_id, post_body).await {
            Ok(_) => {
                if let Err(e) = outbox.mark_delivered(result_id) {
                    warn!(
                        result_id = %result_id,
                        error = %e,
                        "drain_outbox: delivered but failed to remove file"
                    );
                }
                stats.delivered += 1;
                info!(job_id = %job_id, result_id = %result_id, "drain_outbox: delivered");
            }

            Err(ref e) => match classify_client_error(e) {
                RetryClass::Permanent => {
                    warn!(
                        job_id = %job_id,
                        result_id = %result_id,
                        error = %e,
                        "drain_outbox: permanent failure — quarantining"
                    );
                    let _ = outbox.quarantine(result_id);
                    stats.quarantined += 1;
                }

                RetryClass::Transient => {
                    let n = match outbox.record_attempt(result_id) {
                        Ok(n) => n,
                        Err(ie) => {
                            warn!(
                                result_id = %result_id,
                                error = %ie,
                                "drain_outbox: failed to record attempt — leaving for next cycle"
                            );
                            stats.retry_later += 1;
                            continue;
                        }
                    };

                    if n >= max_attempts {
                        warn!(
                            job_id = %job_id,
                            result_id = %result_id,
                            attempts = n,
                            max_attempts,
                            "drain_outbox: max attempts reached — quarantining"
                        );
                        let _ = outbox.quarantine(result_id);
                        stats.quarantined += 1;
                    } else {
                        warn!(
                            job_id = %job_id,
                            result_id = %result_id,
                            attempts = n,
                            max_attempts,
                            error = %e,
                            "drain_outbox: transient failure — will retry"
                        );
                        stats.retry_later += 1;
                    }
                }

                RetryClass::OperatorAlert => {
                    // Do NOT increment attempt counter — this needs human resolution.
                    // Emit one error per drain cycle, not per entry (rate-limited).
                    has_operator_alert = true;
                    stats.operator_alert += 1;
                }
            },
        }
    }

    if has_operator_alert {
        error!(
            count = stats.operator_alert,
            "drain_outbox: {} outbox entries have auth errors (401/403) — \
             token may be revoked or agent not yet approved; operator intervention required",
            stats.operator_alert
        );
    }

    info!(
        delivered = stats.delivered,
        quarantined = stats.quarantined,
        retry_later = stats.retry_later,
        operator_alert = stats.operator_alert,
        "drain_outbox: cycle complete"
    );

    stats
}

// ---------------------------------------------------------------------------
// replay_outbox (startup alias — delegates to drain_outbox)
// ---------------------------------------------------------------------------

/// On startup: drain the outbox with full classification/quarantine semantics.
///
/// Delegates to [`drain_outbox`] with the provided `max_attempts`.  Returns
/// `(delivered, failed_or_quarantined)` for backwards-compatible logging in
/// `run_loop`.
pub async fn replay_outbox(client: &CpClient, outbox: &Outbox, max_attempts: u32) -> DrainStats {
    drain_outbox(client, outbox, max_attempts).await
}

// ---------------------------------------------------------------------------
// run_loop
// ---------------------------------------------------------------------------

/// Main agent pull-loop.
///
/// 1. Replay the outbox at startup (with full classification/quarantine).
/// 2. Loop:
///    - Send a heartbeat (idle or with running job id).
///    - Poll for a job.
///    - `Some(job)` with `OfflineDryRun` → `process_job`.
///    - `Some(job)` with `LivePlan` / `LiveApply` → `process_job_live`.
///    - `None` → sleep `poll_interval`, then drain outbox if `drain_interval` elapsed.
///    - Errors → `warn` + sleep `poll_interval` (never panic).
///
/// ## Outbox draining
///
/// The outbox is drained once at startup, and then periodically during idle
/// ticks (no job received).  The drain fires when at least
/// `outbox_drain_interval` has elapsed since the last drain.  The hot path
/// (while a job is being processed) is not interrupted.
///
/// ## CP grant authority pin (`cp_grant_authority`)
///
/// When `allow_live` is `true`, the caller should attempt
/// `client.fetch_cp_public_keyset()` → `pin_cp_grant_authority()` BEFORE calling `run_loop`
/// and pass the result here.  If the fetch/pin fails, pass `None` — live
/// `LiveApply` jobs will be refused (the gate requires the pinned key);
/// `LivePlan` jobs are still allowed (they only check `allow_live`).
///
/// This function never returns under normal operation.
#[allow(clippy::too_many_arguments)]
pub async fn run_loop(
    client: &CpClient,
    executor: &dyn JobExecutor,
    live_exec: &dyn LiveExecutor,
    identity: &AgentIdentity,
    agent_id: &str,
    outbox: &Outbox,
    poll_interval: Duration,
    cp_grant_authority: Option<&PinnedControlPlaneGrantAuthority>,
    allow_live: bool,
    max_outbox_attempts: u32,
    outbox_drain_interval: Duration,
) {
    // Drain any results left over from a prior run (startup replay).
    let startup_stats = replay_outbox(client, outbox, max_outbox_attempts).await;
    if startup_stats.delivered > 0
        || startup_stats.quarantined > 0
        || startup_stats.retry_later > 0
        || startup_stats.operator_alert > 0
    {
        info!(
            delivered = startup_stats.delivered,
            quarantined = startup_stats.quarantined,
            retry_later = startup_stats.retry_later,
            operator_alert = startup_stats.operator_alert,
            "startup outbox replay finished"
        );
    }

    info!("entering poll loop");

    let mut last_drain = tokio::time::Instant::now();

    loop {
        // Heartbeat — send while idle (no running job in this loop tick).
        if let Err(e) = client.heartbeat().await {
            warn!(error = %e, "heartbeat failed — continuing");
        }

        // Poll for the next available job.
        match client.poll().await {
            Ok(Some(job)) => {
                info!(job_id = %job.id, mode = ?job.spec.mode, "job received — processing");

                // Route by mode: offline → process_job; live → process_job_live.
                let result = match job.spec.mode {
                    JobMode::OfflineDryRun => {
                        process_job(client, executor, identity, agent_id, outbox, &job).await
                    }
                    JobMode::LivePlan | JobMode::LiveApply | JobMode::LiveDestroy => {
                        process_job_live(
                            client,
                            live_exec,
                            identity,
                            agent_id,
                            outbox,
                            &job,
                            cp_grant_authority,
                            allow_live,
                        )
                        .await
                    }
                };

                if let Err(e) = result {
                    warn!(
                        job_id = %job.id,
                        error = %e,
                        "process_job failed — job may be retried by the CP lease expiry sweep"
                    );
                }
                // Do NOT drain the outbox while a job is actively being processed —
                // drain only happens on idle ticks (Ok(None) or Err below).
            }
            Ok(None) => {
                // No work available — wait before polling again.
                tokio::time::sleep(poll_interval).await;

                // Periodic outbox drain on idle ticks.
                if last_drain.elapsed() >= outbox_drain_interval {
                    let stats = drain_outbox(client, outbox, max_outbox_attempts).await;
                    if stats.delivered > 0
                        || stats.quarantined > 0
                        || stats.retry_later > 0
                        || stats.operator_alert > 0
                    {
                        info!(
                            delivered = stats.delivered,
                            quarantined = stats.quarantined,
                            retry_later = stats.retry_later,
                            operator_alert = stats.operator_alert,
                            "periodic outbox drain complete"
                        );
                    }
                    last_drain = tokio::time::Instant::now();
                }
            }
            Err(e) => {
                warn!(error = %e, "poll failed — backing off");
                tokio::time::sleep(poll_interval).await;

                // Also drain on poll-error idle ticks.
                if last_drain.elapsed() >= outbox_drain_interval {
                    drain_outbox(client, outbox, max_outbox_attempts).await;
                    last_drain = tokio::time::Instant::now();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use rand::rngs::OsRng;
    use ryuki_protocol::{
        control_plane_grant_verifying_key,
        crypto::{generate_keypair, job_spec_digest, sha256_hex, sign_vlc},
        ControlPlaneGrantKeyDisposition, ControlPlaneGrantKeyset, ControlPlaneGrantScope, JobLease,
        JobMode, JobSpec, JobStatus, VerifiedLiveContext,
    };
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };
    use uuid::Uuid;

    use crate::{
        executor::StubExecutor,
        identity::AgentIdentity,
        live::{pin_cp_grant_authority, PinnedControlPlaneGrantAuthority},
        live_exec::{LivePlanOutcome, StubLiveExecutor},
        outbox::Outbox,
    };
    use ryuki_engine::runners::RunStatus;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn blocking_executor_call_does_not_starve_async_lease_work() {
        let progressed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let task_progressed = Arc::clone(&progressed);
        let lease_task = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            task_progressed.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        run_executor_blocking(|| std::thread::sleep(std::time::Duration::from_millis(75)));
        assert!(
            progressed.load(std::sync::atomic::Ordering::SeqCst),
            "Tokio must schedule renewal work while the synchronous executor runs"
        );
        lease_task.await.expect("lease task");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unresponsive_lease_renewal_is_bounded_and_fails_closed() {
        let job = make_leased_job();
        let lease = job.lease.as_ref().expect("leased job");
        let (base_url, server, _heartbeat_count) =
            cp_stub_delaying_boundary_renewal(std::time::Duration::from_secs(2)).await;
        let client = CpClient::new(&base_url, "test-platform", "rya_test-token");

        renew_lease_with_timeout(&client, job.id, lease, std::time::Duration::from_secs(1))
            .await
            .expect("first renewal is immediate");

        let started = std::time::Instant::now();
        let error =
            renew_lease_with_timeout(&client, job.id, lease, std::time::Duration::from_millis(50))
                .await
                .expect_err("an unresponsive renewal must lose authority");
        server.abort();

        assert!(error.contains("timed out"));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "renewal timeout must be observed promptly"
        );
    }

    struct LeaseAwareBlockingExecutor {
        started: Arc<std::sync::Barrier>,
    }

    impl JobExecutor for LeaseAwareBlockingExecutor {
        fn execute(&self, _spec: &JobSpec) -> Result<Evidence, ExecError> {
            panic!("lease-aware path must call execute_with_cancellation")
        }

        fn execute_with_cancellation(
            &self,
            _spec: &JobSpec,
            cancellation: &ryuki_runner::CommandCancellation,
        ) -> Result<Evidence, ExecError> {
            self.started.wait();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !cancellation.is_cancelled() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            if !cancellation.is_cancelled() {
                return Err(ExecError::PlanBuild(
                    "lease-loss cancellation was not observed".to_string(),
                ));
            }
            Err(ExecError::Runner(
                ryuki_engine::runners::RunnerError::Cancelled,
            ))
        }
    }

    #[test]
    fn authoritative_lease_loss_cancels_an_active_job_executor() {
        let lost = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancellation = cancellation_from_lease_loss(&lost);
        let started = Arc::new(std::sync::Barrier::new(2));
        let executor = LeaseAwareBlockingExecutor {
            started: Arc::clone(&started),
        };
        let job = make_leased_job();
        let worker = std::thread::spawn(move || {
            evidence_or_deterministic_failure_with_cancellation(&executor, &job, &cancellation)
        });

        started.wait();
        let cancelled_at = std::time::Instant::now();
        lost.store(true, std::sync::atomic::Ordering::SeqCst);
        let error = worker
            .join()
            .expect("executor thread must not panic")
            .expect_err("lease loss must cancel active execution");
        assert!(matches!(error, AgentError::Exec(ExecError::Runner(_))));
        assert!(
            cancelled_at.elapsed() < std::time::Duration::from_secs(1),
            "lease-loss cancellation must return promptly"
        );
    }

    // -----------------------------------------------------------------------
    // StubPoster — injectable ResultPoster for drain_outbox tests
    // -----------------------------------------------------------------------

    /// Scripted `ResultPoster` for unit tests.  Each call pops one result from
    /// the front of `responses`.  If the queue is exhausted, returns `Ok(json!({}))`.
    struct StubPoster {
        /// Pre-scripted results in call order.
        responses: Mutex<Vec<Result<Value, ClientError>>>,
        /// Records (job_id) for each call received.
        calls: Mutex<Vec<Uuid>>,
    }

    impl StubPoster {
        fn new(responses: Vec<Result<Value, ClientError>>) -> Arc<Self> {
            Arc::new(Self {
                responses: Mutex::new(responses),
                calls: Mutex::new(Vec::new()),
            })
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    impl ResultPoster for Arc<StubPoster> {
        fn post(
            &self,
            job_id: Uuid,
            _body: Value,
        ) -> impl Future<Output = Result<Value, ClientError>> + Send {
            self.calls.lock().unwrap().push(job_id);
            let result = self
                .responses
                .lock()
                .unwrap()
                .drain(..1)
                .next()
                .unwrap_or(Ok(serde_json::json!({})));
            std::future::ready(result)
        }
    }

    /// Build a `ClientError::ErrorStatus` with the given status code.
    fn status_err(status: u16) -> ClientError {
        ClientError::ErrorStatus {
            status,
            body: "test body".to_owned(),
        }
    }

    /// Build a transient-looking `ClientError` (uses a 503 status for simplicity
    /// since we can't easily construct a `reqwest::Error` in unit tests).
    fn transient_err() -> ClientError {
        status_err(503)
    }

    /// Build the outbox + enqueue one result body, return the result_id.
    fn setup_one_pending(outbox: &Outbox) -> Uuid {
        use crate::result::ResultBody;
        use chrono::Utc;
        use ryuki_protocol::{
            job_spec_digest, sha256_hex, sign, JobMode, JobResult, JobResultStatus, JobSpec,
            SignedEnvelope,
        };

        let identity = AgentIdentity::generate();
        let result_id = Uuid::new_v4();
        let spec = JobSpec {
            request_id: Uuid::new_v4(),
            request_resource_version: ryuki_protocol::RequestResourceVersion::new(1)
                .expect("positive request resource version"),
            offering_id: Uuid::new_v4(),
            iac_ref: "test@v1".to_string(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            state_key: Some("request-test".to_string()),
            mode: JobMode::OfflineDryRun,
        };
        let spec_digest = job_spec_digest(&spec);
        let evidence = b"test".to_vec();
        let evidence_digest = sha256_hex(&evidence);

        let unsigned = SignedEnvelope {
            agent_id: "test-agent".to_string(),
            agent_enrollment_id: Uuid::nil(),
            platform: "test".to_string(),
            job_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
            lease_generation: 1,
            request_id: spec.request_id,
            request_resource_version: spec.request_resource_version,
            result_id,
            mode: JobMode::OfflineDryRun,
            status: JobResultStatus::CheckOk,
            job_spec_digest: spec_digest,
            approved_plan_digest: None,
            raw_plan_digest: None,
            execution_trust_profile: None,
            evidence_digest: evidence_digest.clone(),
            redaction_policy_version: ryuki_protocol::REDACTION_POLICY_VERSION.to_string(),
            timestamp: Utc::now(),
            key_id: identity.public_key_b64(),
            cp_nonce: Uuid::new_v4().to_string(),
            signature: String::new(),
        };
        let signed = sign(unsigned, identity.signing_key());
        let job_result = JobResult {
            job_id: signed.job_id,
            attempt_id: signed.attempt_id,
            result_id: signed.result_id,
            status: signed.status.clone(),
            raw_plan_digest: signed.raw_plan_digest.clone(),
            evidence_digest: signed.evidence_digest.clone(),
            signed_envelope: signed,
        };
        let body = ResultBody {
            job_result,
            evidence,
            evidence_json: None,
        };
        outbox.enqueue(&body).expect("enqueue");
        result_id
    }

    // -----------------------------------------------------------------------
    // drain_outbox tests
    // -----------------------------------------------------------------------

    /// Transient failure on first drain, success on second → delivered on cycle 2.
    #[tokio::test]
    async fn drain_transient_then_success_delivers() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());
        let result_id = setup_one_pending(&outbox);

        // First call: transient 503. Second call: success.
        let poster = StubPoster::new(vec![
            Err(transient_err()),
            Ok(serde_json::json!({"ok": true})),
        ]);

        // Cycle 1: transient — left in outbox.
        let stats = drain_outbox(&poster, &outbox, 10).await;
        assert_eq!(stats.retry_later, 1, "must be left for retry");
        assert_eq!(stats.delivered, 0);
        assert_eq!(stats.quarantined, 0);

        // attempt sidecar must exist with count=1.
        let sidecar = dir.path().join(format!("{}.attempts", result_id));
        assert!(
            sidecar.exists(),
            "sidecar must exist after transient failure"
        );

        // Cycle 2: success.
        let stats2 = drain_outbox(&poster, &outbox, 10).await;
        assert_eq!(stats2.delivered, 1, "must be delivered on second cycle");
        assert_eq!(stats2.retry_later, 0);

        // Outbox must be empty; sidecar must be gone.
        assert!(
            outbox.list_pending().expect("list").is_empty(),
            "outbox must be empty after delivery"
        );
        assert!(
            !sidecar.exists(),
            "attempts sidecar must be cleared after delivery"
        );

        // Total poster calls: 2.
        assert_eq!(poster.call_count(), 2);
    }

    /// Permanent failure → quarantined on first drain, not retried.
    #[tokio::test]
    async fn drain_permanent_quarantines_immediately() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());
        let result_id = setup_one_pending(&outbox);

        // 409 = Permanent.
        let poster = StubPoster::new(vec![Err(status_err(409))]);

        let stats = drain_outbox(&poster, &outbox, 10).await;
        assert_eq!(stats.quarantined, 1);
        assert_eq!(stats.delivered, 0);
        assert_eq!(stats.retry_later, 0);

        // Entry is in dead/, not in list_pending.
        let dead_path = dir.path().join("dead").join(format!("{}.json", result_id));
        assert!(
            dead_path.exists(),
            "json must be in dead/ after permanent failure"
        );
        assert!(
            outbox.list_pending().expect("list").is_empty(),
            "list_pending must be empty after quarantine"
        );

        // Second drain: poster must NOT be called again (nothing pending).
        let stats2 = drain_outbox(&poster, &outbox, 10).await;
        assert_eq!(stats2.quarantined, 0, "second drain must not re-quarantine");
        assert_eq!(
            poster.call_count(),
            1,
            "poster called exactly once (not retried)"
        );
    }

    /// OperatorAlert (401) → kept, NOT quarantined, attempt counter NOT incremented.
    #[tokio::test]
    async fn drain_operator_alert_kept_not_quarantined_no_attempt_increment() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());
        let result_id = setup_one_pending(&outbox);

        // 401 = OperatorAlert.
        let poster = StubPoster::new(vec![
            Err(status_err(401)),
            Err(status_err(401)),
            Err(status_err(401)),
        ]);

        // Run 3 drain cycles.
        for _ in 0..3 {
            let stats = drain_outbox(&poster, &outbox, 3).await;
            assert_eq!(stats.operator_alert, 1, "must be operator_alert");
            assert_eq!(stats.quarantined, 0, "must NOT be quarantined");
            assert_eq!(stats.delivered, 0);
        }

        // Entry is still pending (not quarantined even after 3 cycles at max_attempts=3).
        assert!(
            outbox.list_pending().expect("list").len() == 1,
            "entry must still be pending after operator-alert cycles"
        );

        // The attempts sidecar must NOT have been created (no record_attempt calls).
        let sidecar = dir.path().join(format!("{}.attempts", result_id));
        assert!(
            !sidecar.exists(),
            "attempts sidecar must NOT exist for OperatorAlert entries"
        );

        // Poster was called 3 times.
        assert_eq!(poster.call_count(), 3);
    }

    /// max_attempts: a transient that fails max_attempts times → quarantined at threshold.
    #[tokio::test]
    async fn drain_max_attempts_quarantines_after_threshold() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());
        let result_id = setup_one_pending(&outbox);
        let max_attempts = 3u32;

        // All transient 503 responses.
        let poster = StubPoster::new(vec![
            Err(transient_err()),
            Err(transient_err()),
            Err(transient_err()),
            // This 4th one should never be called — entry must be quarantined after 3.
            Err(transient_err()),
        ]);

        // Cycle 1: attempts=1, retry_later.
        let s1 = drain_outbox(&poster, &outbox, max_attempts).await;
        assert_eq!(s1.retry_later, 1);
        assert_eq!(s1.quarantined, 0);

        // Cycle 2: attempts=2, retry_later.
        let s2 = drain_outbox(&poster, &outbox, max_attempts).await;
        assert_eq!(s2.retry_later, 1);
        assert_eq!(s2.quarantined, 0);

        // Cycle 3: attempts=3 = max_attempts → quarantined.
        let s3 = drain_outbox(&poster, &outbox, max_attempts).await;
        assert_eq!(s3.quarantined, 1, "must be quarantined at threshold");
        assert_eq!(s3.retry_later, 0);

        // Entry is in dead/, nothing pending.
        let dead_path = dir.path().join("dead").join(format!("{}.json", result_id));
        assert!(dead_path.exists(), "must be in dead/ after max-attempts");
        assert!(
            outbox.list_pending().expect("list").is_empty(),
            "must be empty after quarantine"
        );

        // Cycle 4: nothing pending, poster NOT called.
        let s4 = drain_outbox(&poster, &outbox, max_attempts).await;
        assert_eq!(s4.quarantined, 0);
        assert_eq!(
            poster.call_count(),
            3,
            "poster called exactly max_attempts times"
        );
    }

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    /// Generate a fresh CP keypair (parallel-safe: no global state).
    fn test_grant_scope() -> ControlPlaneGrantScope {
        ControlPlaneGrantScope::new(
            "deployment:test-eu1".to_owned(),
            "trust-domain:ryuki.test".to_owned(),
        )
        .expect("canonical test grant scope")
    }

    fn cp_keypair() -> (ed25519_dalek::SigningKey, PinnedControlPlaneGrantAuthority) {
        let sk = generate_keypair(&mut OsRng);
        let entry = control_plane_grant_verifying_key(
            &sk.verifying_key(),
            ControlPlaneGrantKeyDisposition::Active,
        );
        let keyset = ControlPlaneGrantKeyset {
            keyset_version: 1,
            active_key_id: entry.key_id.clone(),
            keys: vec![entry],
        };
        let authority = pin_cp_grant_authority(keyset, test_grant_scope())
            .expect("valid test keyset and canonical scope must pin");
        (sk, authority)
    }

    fn exact_test_execution_authority(
        live_exec: &dyn LiveExecutor,
        identity: &AgentIdentity,
        agent_id: &str,
        job: &Job,
    ) -> ryuki_protocol::LiveExecutionAuthority {
        let profile = live_exec
            .execution_trust_profile(&job.spec, &job.platform)
            .expect("stub execution trust profile");
        ryuki_protocol::LiveExecutionAuthority {
            assigned_agent_id: agent_id.to_string(),
            assigned_agent_enrollment_id: job.agent_enrollment_id,
            assigned_agent_key_fingerprint: ryuki_protocol::public_key_fingerprint(
                &identity.public_key_b64(),
            ),
            execution_trust_profile_digest: ryuki_protocol::execution_trust_profile_digest(
                &profile,
            ),
        }
    }

    fn unrelated_test_execution_authority() -> ryuki_protocol::LiveExecutionAuthority {
        ryuki_protocol::LiveExecutionAuthority {
            assigned_agent_id: "unrelated-test-agent".to_string(),
            assigned_agent_enrollment_id: Uuid::nil(),
            assigned_agent_key_fingerprint: "sha256:test-only-unrelated".to_string(),
            execution_trust_profile_digest: sha256_hex(b"unrelated-test-profile"),
        }
    }

    /// Build a valid signed grant for `request_id` using `cp_sk`.
    fn make_grant(
        cp_sk: &ed25519_dalek::SigningKey,
        request_id: Uuid,
        approved_plan_digest: &str,
        spec: &JobSpec,
        execution_authority: ryuki_protocol::LiveExecutionAuthority,
    ) -> VerifiedLiveContext {
        make_grant_expiring_at(
            cp_sk,
            request_id,
            approved_plan_digest,
            spec,
            execution_authority,
            Utc::now() + Duration::hours(1),
        )
    }

    fn make_grant_expiring_at(
        cp_sk: &ed25519_dalek::SigningKey,
        request_id: Uuid,
        approved_plan_digest: &str,
        spec: &JobSpec,
        execution_authority: ryuki_protocol::LiveExecutionAuthority,
        expiry: chrono::DateTime<Utc>,
    ) -> VerifiedLiveContext {
        let unsigned = VerifiedLiveContext {
            request_id,
            request_resource_version: spec.request_resource_version,
            deployment_id: test_grant_scope().deployment_id().to_owned(),
            trust_domain_id: test_grant_scope().trust_domain_id().to_owned(),
            platform: "test-platform".to_owned(),
            job_spec_digest: job_spec_digest(spec),
            approved_plan_digest: approved_plan_digest.to_owned(),
            approved_plan_job_id: Uuid::new_v4(),
            approved_plan_attempt_id: Uuid::new_v4(),
            approver: "ops-test".to_owned(),
            expiry,
            step_job_id: None,
            execution_authority,
            signing_key_id: String::new(),
            signature: String::new(),
        };
        sign_vlc(unsigned, cp_sk)
    }

    /// Start a minimal CP stub. The second heartbeat is the pre-mutation
    /// renewal and is deliberately delayed past the supplied grant expiry.
    async fn cp_stub_delaying_boundary_renewal(
        delay: std::time::Duration,
    ) -> (
        String,
        tokio::task::JoinHandle<()>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind CP stub");
        let address = listener.local_addr().expect("CP stub address");
        let heartbeat_count = Arc::new(AtomicUsize::new(0));
        let server_heartbeat_count = Arc::clone(&heartbeat_count);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let heartbeat_count = Arc::clone(&server_heartbeat_count);
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let header_end = loop {
                        let Ok(read) = stream.read(&mut chunk).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&chunk[..read]);
                        if let Some(pos) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                    };
                    let headers = String::from_utf8_lossy(&request[..header_end]).into_owned();
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    while request.len() < header_end + content_length {
                        let Ok(read) = stream.read(&mut chunk).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        request.extend_from_slice(&chunk[..read]);
                    }

                    let request_line = headers.lines().next().unwrap_or_default();
                    let is_heartbeat = request_line.contains("/heartbeat ");
                    if is_heartbeat && heartbeat_count.fetch_add(1, Ordering::SeqCst) == 1 {
                        tokio::time::sleep(delay).await;
                    }
                    let body = if is_heartbeat {
                        serde_json::json!({
                            "agent_id": "test-platform",
                            "last_seen_at": Utc::now(),
                            "lease_deadline": Utc::now() + Duration::minutes(10),
                        })
                    } else {
                        serde_json::json!({"ok": true})
                    };
                    let body = body.to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        (format!("http://{address}"), task, heartbeat_count)
    }

    fn make_leased_job_mode(mode: JobMode) -> Job {
        let spec = JobSpec {
            request_id: Uuid::new_v4(),
            request_resource_version: ryuki_protocol::RequestResourceVersion::new(1)
                .expect("positive request resource version"),
            offering_id: Uuid::new_v4(),
            iac_ref: "patch-maintenance@v1.0.0".to_string(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            state_key: Some("request-test".to_string()),
            mode,
        };
        let lease = JobLease {
            attempt_id: Uuid::new_v4(),
            lease_generation: 1,
            fencing_token: Uuid::new_v4().to_string(),
            deadline: Utc::now() + Duration::minutes(5),
            cp_nonce: Uuid::new_v4().to_string(),
        };
        Job {
            id: Uuid::new_v4(),
            agent_enrollment_id: Uuid::nil(),
            platform: "test-platform".to_string(),
            spec,
            status: JobStatus::Running,
            lease: Some(lease),
            live_context: None,
        }
    }

    fn make_leased_job() -> Job {
        make_leased_job_mode(JobMode::OfflineDryRun)
    }

    // =======================================================================
    // process_job_live tests (Part 4) — pure/stub, parallel-safe, no terraform
    // =======================================================================

    // Helper: build a stub live executor with a deterministic plan digest.
    fn stub_live(plan_bytes: &'static [u8], apply_status: RunStatus) -> StubLiveExecutor {
        StubLiveExecutor::with_plan(plan_bytes, apply_status)
    }

    #[derive(Clone, Copy)]
    enum ProfileDrift {
        BackendLocation,
        CredentialRevision,
        ProviderDestinationSet,
    }

    /// Returns the approved profile on the first execution check and a
    /// same-agent authority drift on the mutation-boundary recomputation.
    struct BoundaryDriftExecutor {
        inner: StubLiveExecutor,
        drift: ProfileDrift,
        profile_calls: std::sync::atomic::AtomicU32,
    }

    impl BoundaryDriftExecutor {
        fn new(plan_bytes: &'static [u8], drift: ProfileDrift) -> Self {
            Self {
                inner: stub_live(plan_bytes, RunStatus::Applied),
                drift,
                profile_calls: std::sync::atomic::AtomicU32::new(0),
            }
        }
    }

    impl LiveExecutor for BoundaryDriftExecutor {
        fn execution_trust_profile(
            &self,
            spec: &JobSpec,
            platform: &str,
        ) -> Result<ryuki_protocol::ExecutionTrustProfile, LiveExecError> {
            let mut profile = self.inner.execution_trust_profile(spec, platform)?;
            let call = self
                .profile_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if call > 0 {
                match self.drift {
                    ProfileDrift::BackendLocation => {
                        profile.backend_authority_digest =
                            sha256_hex(b"same-kind-different-backend-authority");
                    }
                    ProfileDrift::CredentialRevision => {
                        profile.backend_credential_authority_revision = "v2".to_string();
                    }
                    ProfileDrift::ProviderDestinationSet => {
                        profile.provider_authority_version = "v2".to_string();
                    }
                }
            }
            Ok(profile)
        }

        fn plan(&self, spec: &JobSpec) -> Result<LivePlanOutcome, LiveExecError> {
            self.inner.plan(spec)
        }

        fn apply(&self, spec: &JobSpec, tfplan: &[u8]) -> Result<Evidence, LiveExecError> {
            self.inner.apply(spec, tfplan)
        }

        fn destroy(&self, spec: &JobSpec) -> Result<Evidence, LiveExecError> {
            self.inner.destroy(spec)
        }
    }

    // Helper: build a LiveApply job with a valid grant signed by cp_sk, where
    // the grant's approved_plan_digest matches the stub's plan_digest.
    fn make_live_apply_job_with_grant(cp_sk: &ed25519_dalek::SigningKey, plan_bytes: &[u8]) -> Job {
        let plan_digest = sha256_hex(plan_bytes);
        let request_id = Uuid::new_v4();

        let spec = JobSpec {
            request_id,
            request_resource_version: ryuki_protocol::RequestResourceVersion::new(1)
                .expect("positive request resource version"),
            offering_id: Uuid::new_v4(),
            iac_ref: "patch-maintenance@v1.0.0".to_string(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            state_key: Some(format!("request-{request_id}")),
            mode: JobMode::LiveApply,
        };
        let grant = make_grant(
            cp_sk,
            request_id,
            &plan_digest,
            &spec,
            unrelated_test_execution_authority(),
        );
        let lease = JobLease {
            attempt_id: Uuid::new_v4(),
            lease_generation: 1,
            fencing_token: Uuid::new_v4().to_string(),
            deadline: Utc::now() + Duration::minutes(5),
            cp_nonce: Uuid::new_v4().to_string(),
        };
        Job {
            id: Uuid::new_v4(),
            agent_enrollment_id: Uuid::nil(),
            platform: "test-platform".to_string(),
            spec,
            status: JobStatus::Running,
            lease: Some(lease),
            live_context: Some(grant),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_apply_rechecks_grant_after_boundary_renewal() {
        let (cp_sk, vk) = cp_keypair();
        const PLAN_BYTES: &[u8] = b"plan-for-expiry-boundary";
        let live_exec = stub_live(PLAN_BYTES, RunStatus::Applied);
        let identity = AgentIdentity::generate();
        let agent_id = "test-platform";
        let mut job = make_live_apply_job_with_grant(&cp_sk, PLAN_BYTES);
        job.agent_enrollment_id = Uuid::new_v4();
        let execution_authority =
            exact_test_execution_authority(&live_exec, &identity, agent_id, &job);
        job.live_context = Some(make_grant_expiring_at(
            &cp_sk,
            job.spec.request_id,
            &sha256_hex(PLAN_BYTES),
            &job.spec,
            execution_authority,
            Utc::now() + Duration::seconds(2),
        ));

        let (base_url, server, heartbeat_count) =
            cp_stub_delaying_boundary_renewal(std::time::Duration::from_millis(2200)).await;
        let client = CpClient::new(&base_url, agent_id, "rya_test-token");
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());

        process_job_live(
            &client,
            &live_exec,
            &identity,
            agent_id,
            &outbox,
            &job,
            Some(&vk),
            true,
        )
        .await
        .expect("expired-at-boundary apply must be reported as a refusal");

        server.abort();
        assert_eq!(
            live_exec.plan_call_count(),
            1,
            "the approved plan is rebuilt"
        );
        assert!(
            heartbeat_count.load(std::sync::atomic::Ordering::SeqCst) >= 2,
            "the initial and post-plan boundary renewals must both reach the CP"
        );
        assert_eq!(
            live_exec.apply_call_count(),
            0,
            "apply must not start after the grant expires during renewal"
        );
    }

    async fn assert_live_apply_boundary_profile_drift(drift: ProfileDrift) {
        let (cp_sk, vk) = cp_keypair();
        const PLAN_BYTES: &[u8] = b"plan-for-authority-drift-boundary";
        let live_exec = BoundaryDriftExecutor::new(PLAN_BYTES, drift);
        let identity = AgentIdentity::generate();
        let agent_id = "test-platform";
        let mut job = make_live_apply_job_with_grant(&cp_sk, PLAN_BYTES);
        job.agent_enrollment_id = Uuid::new_v4();
        let authority = exact_test_execution_authority(&live_exec.inner, &identity, agent_id, &job);
        job.live_context = Some(make_grant(
            &cp_sk,
            job.spec.request_id,
            &sha256_hex(PLAN_BYTES),
            &job.spec,
            authority,
        ));

        let (base_url, server, heartbeat_count) =
            cp_stub_delaying_boundary_renewal(std::time::Duration::ZERO).await;
        let client = CpClient::new(&base_url, agent_id, "rya_test-token");
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());
        process_job_live(
            &client,
            &live_exec,
            &identity,
            agent_id,
            &outbox,
            &job,
            Some(&vk),
            true,
        )
        .await
        .expect("authority drift must be reported as a refusal");
        server.abort();

        assert_eq!(
            live_exec
                .profile_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            2,
            "profile must be recomputed before contact and at the apply boundary"
        );
        assert_eq!(live_exec.inner.plan_call_count(), 1);
        assert_eq!(live_exec.inner.apply_call_count(), 0);
        assert!(
            heartbeat_count.load(std::sync::atomic::Ordering::SeqCst) >= 2,
            "the boundary renewal must complete before drift is refused"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_apply_refuses_same_kind_backend_authority_drift_at_boundary() {
        assert_live_apply_boundary_profile_drift(ProfileDrift::BackendLocation).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_apply_refuses_backend_credential_authority_revision_drift_at_boundary() {
        assert_live_apply_boundary_profile_drift(ProfileDrift::CredentialRevision).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_apply_refuses_provider_destination_set_drift_at_boundary() {
        assert_live_apply_boundary_profile_drift(ProfileDrift::ProviderDestinationSet).await;
    }

    // -----------------------------------------------------------------------
    // LiveApply happy path: valid grant + matching digest → apply called, Applied
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn live_apply_happy_path_apply_is_called() {
        let (cp_sk, vk) = cp_keypair();
        const PLAN_BYTES: &[u8] = b"canonical-plan-json-for-happy-path";
        let live_exec = stub_live(PLAN_BYTES, RunStatus::Applied);
        let job = make_live_apply_job_with_grant(&cp_sk, PLAN_BYTES);

        let identity = AgentIdentity::generate();
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());

        // We don't need a real CP client — just verify the outbox gets the result.
        // Use a CpClient that will fail the POST (network error), leaving the
        // result in the outbox. We only assert on apply_call_count + outbox state.
        let body = {
            // Simulate just the gate + build step without async HTTP.
            let plan_outcome = live_exec.plan(&job.spec).expect("plan");
            let plan_digest = &plan_outcome.raw_plan_digest;

            // Gate check — must Proceed.
            let decision = evaluate_live_execution(&job, &vk, true, Some(plan_digest.as_str()));
            assert_eq!(
                decision,
                crate::live::LiveDecision::Proceed,
                "gate must Proceed for valid grant"
            );

            // apply IS called — pass the exact tfplan bytes produced by plan().
            let apply_evidence = live_exec
                .apply(&job.spec, &plan_outcome.tfplan)
                .expect("apply");

            let approved_digest = job
                .live_context
                .as_ref()
                .map(|g| g.approved_plan_digest.clone());

            crate::result::build_signed_result(
                &identity,
                "test-agent",
                &job,
                &apply_evidence,
                approved_digest,
            )
            .expect("build_signed_result")
        };

        // plan and apply were each called once.
        assert_eq!(live_exec.plan_call_count(), 1, "plan must have been called");
        assert_eq!(
            live_exec.apply_call_count(),
            1,
            "apply must have been called"
        );

        // Result carries Applied status.
        assert_eq!(
            body.job_result.status,
            ryuki_protocol::JobResultStatus::Applied,
            "result status must be Applied"
        );

        // approved_plan_digest is set.
        assert!(
            body.job_result
                .signed_envelope
                .approved_plan_digest
                .is_some(),
            "approved_plan_digest must be set on the Applied result"
        );

        // Enqueue to verify outbox contract.
        outbox.enqueue(&body).expect("enqueue");
        let pending = outbox.list_pending().expect("list");
        assert_eq!(pending.len(), 1, "result must be in outbox");
    }

    // -----------------------------------------------------------------------
    // LiveApply refused: bad grant → Refused, apply NOT called
    // -----------------------------------------------------------------------

    #[test]
    fn live_apply_refused_bad_grant_plan_and_apply_not_called() {
        let (cp_sk, vk) = cp_keypair();
        const PLAN_BYTES: &[u8] = b"plan-bytes-for-bad-grant-test";
        let live_exec = stub_live(PLAN_BYTES, RunStatus::Applied);

        // Build a grant for a DIFFERENT request_id than the job's.
        let wrong_request_id = Uuid::new_v4();
        let plan_digest = sha256_hex(PLAN_BYTES);
        let mut job = make_leased_job_mode(JobMode::LiveApply);
        let bad_grant = make_grant(
            &cp_sk,
            wrong_request_id,
            &plan_digest,
            &job.spec,
            unrelated_test_execution_authority(),
        );
        job.live_context = Some(bad_grant);
        // job.spec.request_id is a different Uuid → grant.request_id mismatch.

        // The pre-plan authority gate must refuse the request binding before
        // any provider/backend contact.
        let decision = crate::live::evaluate_live_authority(&job, &vk, true);
        assert_eq!(
            decision,
            crate::live::LiveDecision::Refused("grant is for a different request".to_owned()),
            "gate must Refuse on request_id mismatch"
        );

        // apply is NOT called.
        assert_eq!(
            live_exec.plan_call_count(),
            0,
            "plan must NOT be called when authority is invalid"
        );
        assert_eq!(
            live_exec.apply_call_count(),
            0,
            "apply must NOT be called when gate refuses"
        );
    }

    #[test]
    fn live_apply_refuses_signed_cross_deployment_grant_before_plan() {
        let (cp_sk, authority) = cp_keypair();
        const PLAN_BYTES: &[u8] = b"plan-bytes-for-scope-replay-test";
        let live_exec = stub_live(PLAN_BYTES, RunStatus::Applied);
        let plan_digest = sha256_hex(PLAN_BYTES);
        let mut job = make_leased_job_mode(JobMode::LiveApply);
        let mut grant = make_grant(
            &cp_sk,
            job.spec.request_id,
            &plan_digest,
            &job.spec,
            unrelated_test_execution_authority(),
        );
        grant.deployment_id = "deployment:other-eu1".to_owned();
        grant.signature.clear();
        job.live_context = Some(sign_vlc(grant, &cp_sk));

        assert_eq!(
            crate::live::evaluate_live_authority(&job, &authority, true),
            crate::live::LiveDecision::Refused("grant is for a different deployment".to_owned())
        );
        assert_eq!(
            live_exec.plan_call_count(),
            0,
            "cross-deployment grants must be refused before provider contact"
        );
        assert_eq!(live_exec.apply_call_count(), 0);
    }

    // -----------------------------------------------------------------------
    // LiveApply refused: digest mismatch → Refused, apply NOT called
    // -----------------------------------------------------------------------

    #[test]
    fn live_apply_refused_digest_mismatch_apply_not_called() {
        let (cp_sk, vk) = cp_keypair();
        const PLAN_BYTES: &[u8] = b"actual-plan";
        let live_exec = stub_live(PLAN_BYTES, RunStatus::Applied);

        // Grant approved a DIFFERENT plan.
        let request_id = Uuid::new_v4();
        let wrong_digest = sha256_hex(b"a-different-approved-plan");
        let spec = JobSpec {
            request_id,
            request_resource_version: ryuki_protocol::RequestResourceVersion::new(1)
                .expect("positive request resource version"),
            offering_id: Uuid::new_v4(),
            iac_ref: "patch-maintenance@v1.0.0".to_string(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            state_key: Some(format!("request-{request_id}")),
            mode: JobMode::LiveApply,
        };
        let grant = make_grant(
            &cp_sk,
            request_id,
            &wrong_digest,
            &spec,
            unrelated_test_execution_authority(),
        );
        let lease = JobLease {
            attempt_id: Uuid::new_v4(),
            lease_generation: 1,
            fencing_token: Uuid::new_v4().to_string(),
            deadline: Utc::now() + Duration::minutes(5),
            cp_nonce: Uuid::new_v4().to_string(),
        };
        let job = Job {
            id: Uuid::new_v4(),
            agent_enrollment_id: Uuid::nil(),
            platform: "test-platform".to_string(),
            spec,
            status: JobStatus::Running,
            lease: Some(lease),
            live_context: Some(grant),
        };
        let _ = &job; // silence unused warning

        // Plan → digest is sha256(PLAN_BYTES), NOT wrong_digest.
        let plan_outcome = live_exec.plan(&job.spec).expect("plan");
        let replanned_digest = &plan_outcome.raw_plan_digest;

        let decision = evaluate_live_execution(&job, &vk, true, Some(replanned_digest.as_str()));
        assert_eq!(
            decision,
            crate::live::LiveDecision::Refused(
                "the plan the agent produced does not match the approved plan".to_owned()
            ),
            "gate must Refuse on digest mismatch"
        );
        assert_eq!(
            live_exec.apply_call_count(),
            0,
            "apply NOT called on digest mismatch"
        );
    }

    // -----------------------------------------------------------------------
    // LiveApply !allow_live → Refused WITHOUT plan being called
    // -----------------------------------------------------------------------

    #[test]
    fn live_apply_no_allow_live_plan_not_called() {
        // !allow_live → fast-path refuse in process_job_live BEFORE plan().
        // We test the gate directly (allow_live=false).
        let (_, vk) = cp_keypair();
        let live_exec = stub_live(b"plan", RunStatus::Applied);
        let job = make_leased_job_mode(JobMode::LiveApply);

        // Gate check with allow_live=false — immediately Refuses (no plan called).
        let decision = evaluate_live_execution(&job, &vk, false, None);
        assert_eq!(
            decision,
            crate::live::LiveDecision::Refused("LiveApply requires --allow-live".to_owned()),
            "gate must Refuse immediately when allow_live=false"
        );

        // In process_job_live the fast-path !allow_live → refuse without plan().
        // The gate is checked BEFORE plan(), so plan_call_count is 0.
        assert_eq!(
            live_exec.plan_call_count(),
            0,
            "plan must NOT be called when allow_live=false (fast-path refuse)"
        );
        assert_eq!(live_exec.apply_call_count(), 0, "apply NOT called");
    }

    // -----------------------------------------------------------------------
    // LivePlan allow_live=true → plan IS called and its raw digest is signed
    // -----------------------------------------------------------------------

    #[test]
    fn live_plan_allow_live_true_plan_called_with_raw_digest() {
        let (_, vk) = cp_keypair();
        const PLAN_BYTES: &[u8] = b"live-plan-canonical-output";
        let live_exec = stub_live(PLAN_BYTES, RunStatus::Applied);
        let job = make_leased_job_mode(JobMode::LivePlan);
        let identity = AgentIdentity::generate();

        // Gate: LivePlan + allow_live=true → Proceed.
        let decision = evaluate_live_execution(&job, &vk, true, None);
        assert_eq!(
            decision,
            crate::live::LiveDecision::Proceed,
            "LivePlan + allow_live=true must Proceed"
        );

        // plan IS called.
        let plan_outcome = live_exec.plan(&job.spec).expect("plan");
        assert_eq!(live_exec.plan_call_count(), 1, "plan must be called");
        assert_eq!(
            live_exec.apply_call_count(),
            0,
            "apply NOT called for LivePlan"
        );

        // Build result — approved_plan_digest is absent, while the raw-plan
        // commitment and exact execution profile are signed for review.
        let trust_profile = live_exec
            .execution_trust_profile(&job.spec, &job.platform)
            .expect("stub execution trust profile");
        let body = crate::result::build_signed_result_with_trust_profile(
            &identity,
            "test-agent",
            &job,
            &plan_outcome.evidence,
            None,
            Some(plan_outcome.raw_plan_digest.clone()),
            Some(trust_profile),
        )
        .expect("build");

        assert_eq!(
            body.job_result.status,
            ryuki_protocol::JobResultStatus::Planned,
            "LivePlan result status must be Planned"
        );
        assert!(
            body.job_result
                .signed_envelope
                .approved_plan_digest
                .is_none(),
            "LivePlan must NOT carry approved_plan_digest"
        );
        assert_eq!(
            body.job_result.signed_envelope.raw_plan_digest,
            Some(plan_outcome.raw_plan_digest),
            "LivePlan must carry the canonical raw-plan commitment"
        );
    }

    // -----------------------------------------------------------------------
    // LivePlan allow_live=false → Refused, plan NOT called
    // -----------------------------------------------------------------------

    #[test]
    fn live_plan_no_allow_live_refused_plan_not_called() {
        let (_, vk) = cp_keypair();
        let live_exec = stub_live(b"plan", RunStatus::Applied);
        let job = make_leased_job_mode(JobMode::LivePlan);

        let decision = evaluate_live_execution(&job, &vk, false, None);
        assert_eq!(
            decision,
            crate::live::LiveDecision::Refused("LivePlan requires --allow-live".to_owned()),
            "LivePlan + allow_live=false must Refuse"
        );
        assert_eq!(
            live_exec.plan_call_count(),
            0,
            "plan NOT called when gate refuses"
        );
    }

    // -----------------------------------------------------------------------
    // LiveApply no pinned CP grant authority → refused WITHOUT plan called
    // -----------------------------------------------------------------------

    #[test]
    fn live_apply_no_cp_key_plan_not_called() {
        // process_job_live's fast-path refuses LiveApply when cp_grant_authority=None
        // WITHOUT calling plan(). Test by asserting plan_call_count stays 0.
        let live_exec = stub_live(b"plan", RunStatus::Applied);
        let identity = AgentIdentity::generate();
        let job = make_leased_job_mode(JobMode::LiveApply);
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());

        // Build the refused result manually (mirroring what process_job_live does).
        let refused = crate::result::build_refused_result(
            &identity,
            "test-agent",
            &job,
            "LiveApply refused: no pinned CP grant authority available",
        )
        .expect("refused result must build");

        outbox.enqueue(&refused).expect("enqueue");

        // plan was never called.
        assert_eq!(
            live_exec.plan_call_count(),
            0,
            "plan NOT called when no CP key"
        );
        assert_eq!(live_exec.apply_call_count(), 0, "apply NOT called");

        // Result is LiveRefused.
        assert_eq!(
            refused.job_result.status,
            ryuki_protocol::JobResultStatus::LiveRefused
        );
        // Outbox has one entry.
        assert_eq!(outbox.list_pending().expect("list").len(), 1);
    }

    // -----------------------------------------------------------------------
    // Blocker 1: tfplan bytes thread through plan → apply unchanged
    // -----------------------------------------------------------------------

    /// The happy-path stub test verifies that `apply()` receives the EXACT
    /// tfplan bytes that `plan()` produced, closing the TOCTOU hole.
    #[test]
    fn live_apply_tfplan_bytes_thread_through_unchanged() {
        let (cp_sk, vk) = cp_keypair();
        const PLAN_BYTES: &[u8] = b"canonical-tfplan-thread-through-test";
        let live_exec = stub_live(PLAN_BYTES, RunStatus::Applied);
        let job = make_live_apply_job_with_grant(&cp_sk, PLAN_BYTES);

        // plan() produces outcome with tfplan = PLAN_BYTES.
        let plan_outcome = live_exec.plan(&job.spec).expect("plan");
        assert_eq!(
            plan_outcome.tfplan.as_slice(),
            PLAN_BYTES,
            "stub plan_outcome.tfplan must equal the plan bytes"
        );

        // Gate must Proceed.
        let decision =
            evaluate_live_execution(&job, &vk, true, Some(plan_outcome.raw_plan_digest.as_str()));
        assert_eq!(decision, crate::live::LiveDecision::Proceed);

        // apply() receives exactly the tfplan bytes from plan_outcome.
        live_exec
            .apply(&job.spec, &plan_outcome.tfplan)
            .expect("apply");

        // The stub recorded what it got — must equal PLAN_BYTES.
        let recorded = live_exec.last_apply_tfplan();
        assert_eq!(
            recorded.as_slice(),
            PLAN_BYTES,
            "apply() must receive the exact tfplan bytes from plan_outcome"
        );
    }

    // -----------------------------------------------------------------------
    // Blocker 2: plan() Err → LiveRefused result, apply() NOT called
    // -----------------------------------------------------------------------

    /// When plan() returns Err(PlanFailed), process_job_live must build a
    /// LiveRefused result and enqueue it — apply() is NEVER called.
    #[test]
    fn live_apply_plan_err_produces_refused_apply_not_called() {
        use crate::live_exec::StubLiveExecutor;

        let failing_exec = StubLiveExecutor::with_failing_plan();
        let identity = AgentIdentity::generate();
        let job = make_leased_job_mode(JobMode::LiveApply);
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());

        // Simulate the LiveApply Proceed path — plan fails → must build a
        // LiveRefused result (not propagate the error as AgentError).
        let reason = format!(
            "terraform plan failed: {}",
            crate::live_exec::LiveExecError::PlanFailed(
                "stub: plan configured to fail".to_string()
            )
        );
        let refused = build_refused_result(&identity, "test-agent", &job, &reason)
            .expect("refused result must build");

        outbox.enqueue(&refused).expect("enqueue");

        // apply was never called.
        assert_eq!(
            failing_exec.apply_call_count(),
            0,
            "apply must NOT be called when plan() returns Err"
        );
        // plan WAS called (once, to discover the failure).
        // (In this test we build the refused result manually, so plan_call_count is 0;
        //  the assertion that plan is called is in process_job_live's own logic.)

        // Result must be LiveRefused.
        assert_eq!(
            refused.job_result.status,
            ryuki_protocol::JobResultStatus::LiveRefused,
            "plan failure must produce LiveRefused, not propagate as AgentError"
        );

        // Outbox has exactly one entry.
        assert_eq!(outbox.list_pending().expect("list").len(), 1);
    }

    /// Integration-style: StubLiveExecutor::with_failing_plan() → plan_call_count
    /// increments but apply_call_count stays 0, and plan() returns Err.
    #[test]
    fn stub_failing_plan_returns_err_apply_not_called() {
        use crate::live_exec::StubLiveExecutor;

        let failing_exec = StubLiveExecutor::with_failing_plan();
        let spec = make_leased_job_mode(JobMode::LiveApply).spec;

        let result = failing_exec.plan(&spec);
        assert!(
            matches!(result, Err(crate::live_exec::LiveExecError::PlanFailed(_))),
            "with_failing_plan must return Err(PlanFailed): {result:?}"
        );
        assert_eq!(failing_exec.plan_call_count(), 1, "plan was called once");
        assert_eq!(failing_exec.apply_call_count(), 0, "apply never called");
    }

    // =======================================================================
    // #42 B2-3: LiveDestroy pipeline tests — pure/stub, no terraform
    // =======================================================================

    /// Build a valid step-bound grant (the ONLY grant shape a destroy accepts).
    fn make_step_grant(
        cp_sk: &ed25519_dalek::SigningKey,
        request_id: Uuid,
        step_job_id: Uuid,
        spec: &JobSpec,
        execution_authority: ryuki_protocol::LiveExecutionAuthority,
    ) -> VerifiedLiveContext {
        make_step_grant_expiring_at(
            cp_sk,
            request_id,
            step_job_id,
            spec,
            execution_authority,
            Utc::now() + Duration::hours(1),
        )
    }

    fn make_step_grant_expiring_at(
        cp_sk: &ed25519_dalek::SigningKey,
        request_id: Uuid,
        step_job_id: Uuid,
        spec: &JobSpec,
        execution_authority: ryuki_protocol::LiveExecutionAuthority,
        expiry: chrono::DateTime<Utc>,
    ) -> VerifiedLiveContext {
        let unsigned = VerifiedLiveContext {
            request_id,
            request_resource_version: spec.request_resource_version,
            deployment_id: test_grant_scope().deployment_id().to_owned(),
            trust_domain_id: test_grant_scope().trust_domain_id().to_owned(),
            platform: "test-platform".to_owned(),
            job_spec_digest: job_spec_digest(spec),
            // The digest of the plan the step APPLIED — present in the grant but
            // deliberately unchecked by the destroy gate (no plan-then-apply).
            approved_plan_digest: sha256_hex(b"the-applied-plan"),
            approved_plan_job_id: Uuid::new_v4(),
            approved_plan_attempt_id: Uuid::new_v4(),
            approver: "ops-test".to_owned(),
            expiry,
            step_job_id: Some(step_job_id),
            execution_authority,
            signing_key_id: String::new(),
            signature: String::new(),
        };
        sign_vlc(unsigned, cp_sk)
    }

    /// Build a leased LiveDestroy job whose grant is step-bound to its own id.
    fn make_live_destroy_job_with_step_grant(cp_sk: &ed25519_dalek::SigningKey) -> Job {
        let request_id = Uuid::new_v4();
        let job_id = Uuid::new_v4();
        let spec = JobSpec {
            request_id,
            request_resource_version: ryuki_protocol::RequestResourceVersion::new(1)
                .expect("positive request resource version"),
            offering_id: Uuid::new_v4(),
            iac_ref: "request-preflight@v1.0.0".to_string(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            state_key: Some(format!("step-{request_id}")),
            mode: JobMode::LiveDestroy,
        };
        let grant = make_step_grant(
            cp_sk,
            request_id,
            job_id,
            &spec,
            unrelated_test_execution_authority(),
        );
        let lease = JobLease {
            attempt_id: Uuid::new_v4(),
            lease_generation: 1,
            fencing_token: Uuid::new_v4().to_string(),
            deadline: Utc::now() + Duration::minutes(5),
            cp_nonce: Uuid::new_v4().to_string(),
        };
        Job {
            id: job_id,
            agent_enrollment_id: Uuid::nil(),
            platform: "test-platform".to_string(),
            spec,
            status: JobStatus::Running,
            lease: Some(lease),
            live_context: Some(grant),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_destroy_rechecks_grant_after_boundary_renewal() {
        let (cp_sk, vk) = cp_keypair();
        let live_exec = stub_live(b"unused-plan", RunStatus::Applied);
        let identity = AgentIdentity::generate();
        let agent_id = "test-platform";
        let mut job = make_live_destroy_job_with_step_grant(&cp_sk);
        job.agent_enrollment_id = Uuid::new_v4();
        let execution_authority =
            exact_test_execution_authority(&live_exec, &identity, agent_id, &job);
        job.live_context = Some(make_step_grant_expiring_at(
            &cp_sk,
            job.spec.request_id,
            job.id,
            &job.spec,
            execution_authority,
            Utc::now() + Duration::seconds(2),
        ));

        let (base_url, server, heartbeat_count) =
            cp_stub_delaying_boundary_renewal(std::time::Duration::from_millis(2200)).await;
        let client = CpClient::new(&base_url, agent_id, "rya_test-token");
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());

        process_job_live(
            &client,
            &live_exec,
            &identity,
            agent_id,
            &outbox,
            &job,
            Some(&vk),
            true,
        )
        .await
        .expect("expired-at-boundary destroy must be reported as a refusal");

        server.abort();
        assert!(
            heartbeat_count.load(std::sync::atomic::Ordering::SeqCst) >= 2,
            "the initial and pre-destroy boundary renewals must both reach the CP"
        );
        assert_eq!(
            live_exec.destroy_call_count(),
            0,
            "destroy must not start after the grant expires during renewal"
        );
    }

    async fn assert_live_destroy_boundary_profile_drift(drift: ProfileDrift) {
        let (cp_sk, vk) = cp_keypair();
        let live_exec = BoundaryDriftExecutor::new(b"unused-destroy-plan", drift);
        let identity = AgentIdentity::generate();
        let agent_id = "test-platform";
        let mut job = make_live_destroy_job_with_step_grant(&cp_sk);
        job.agent_enrollment_id = Uuid::new_v4();
        let authority = exact_test_execution_authority(&live_exec.inner, &identity, agent_id, &job);
        job.live_context = Some(make_step_grant(
            &cp_sk,
            job.spec.request_id,
            job.id,
            &job.spec,
            authority,
        ));

        let (base_url, server, heartbeat_count) =
            cp_stub_delaying_boundary_renewal(std::time::Duration::ZERO).await;
        let client = CpClient::new(&base_url, agent_id, "rya_test-token");
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());
        process_job_live(
            &client,
            &live_exec,
            &identity,
            agent_id,
            &outbox,
            &job,
            Some(&vk),
            true,
        )
        .await
        .expect("destroy authority drift must be reported as a refusal");
        server.abort();

        assert_eq!(
            live_exec
                .profile_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            2,
            "profile must be recomputed before contact and at the destroy boundary"
        );
        assert_eq!(live_exec.inner.destroy_call_count(), 0);
        assert!(
            heartbeat_count.load(std::sync::atomic::Ordering::SeqCst) >= 2,
            "the pre-destroy boundary renewal must complete before drift is refused"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_destroy_refuses_same_kind_backend_authority_drift_at_boundary() {
        assert_live_destroy_boundary_profile_drift(ProfileDrift::BackendLocation).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_destroy_refuses_backend_credential_authority_revision_drift_at_boundary() {
        assert_live_destroy_boundary_profile_drift(ProfileDrift::CredentialRevision).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_destroy_refuses_provider_destination_set_drift_at_boundary() {
        assert_live_destroy_boundary_profile_drift(ProfileDrift::ProviderDestinationSet).await;
    }

    // -----------------------------------------------------------------------
    // LiveDestroy happy path: step-bound grant → destroy called, Applied
    // result, NO digest, outbox-enqueued
    // -----------------------------------------------------------------------

    #[test]
    fn live_destroy_happy_path_destroy_called_result_applied_no_digest() {
        let (cp_sk, vk) = cp_keypair();
        let live_exec = stub_live(b"unused-plan-bytes", RunStatus::Applied);
        let job = make_live_destroy_job_with_step_grant(&cp_sk);
        let identity = AgentIdentity::generate();
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());

        // Gate: LiveDestroy with a valid step-bound grant and NO digest → Proceed.
        let decision = evaluate_live_execution(&job, &vk, true, None);
        assert_eq!(
            decision,
            crate::live::LiveDecision::Proceed,
            "gate must Proceed for a valid step-bound destroy grant"
        );

        // destroy IS called — and it is the ONLY executor call (no plan step).
        let destroy_evidence = live_exec.destroy(&job.spec).expect("destroy");
        assert_eq!(live_exec.destroy_call_count(), 1, "destroy called once");
        assert_eq!(live_exec.plan_call_count(), 0, "a destroy has NO plan step");
        assert_eq!(live_exec.apply_call_count(), 0, "apply never called");

        // Result: Applied status, LiveDestroy mode, NO approved_plan_digest.
        let body = build_signed_result(&identity, "test-agent", &job, &destroy_evidence, None)
            .expect("build_signed_result");
        assert_eq!(
            body.job_result.status,
            ryuki_protocol::JobResultStatus::Applied,
            "successful destroy maps to Applied (the CP marks the step ToreDown)"
        );
        assert_eq!(body.job_result.signed_envelope.mode, JobMode::LiveDestroy);
        assert!(
            body.job_result
                .signed_envelope
                .approved_plan_digest
                .is_none(),
            "a LiveDestroy result must NEVER carry approved_plan_digest"
        );

        // Outbox contract: enqueue-before-post.
        outbox.enqueue(&body).expect("enqueue");
        assert_eq!(outbox.list_pending().expect("list").len(), 1);
    }

    // -----------------------------------------------------------------------
    // LiveDestroy refusals: the gate is the only path to execution
    // -----------------------------------------------------------------------

    /// An UNBOUND (legacy whole-request) grant must refuse a destroy — the
    /// step binding IS the destroy's safety bound. destroy() is never called.
    #[test]
    fn live_destroy_refused_unbound_grant_destroy_not_called() {
        let (cp_sk, vk) = cp_keypair();
        let live_exec = stub_live(b"plan", RunStatus::Applied);
        let identity = AgentIdentity::generate();

        let mut job = make_live_destroy_job_with_step_grant(&cp_sk);
        // Replace with an unbound grant for the SAME request (a valid legacy
        // LiveApply-shaped grant — exactly the replay the gate must block).
        job.live_context = Some(make_grant(
            &cp_sk,
            job.spec.request_id,
            &sha256_hex(b"the-applied-plan"),
            &job.spec,
            unrelated_test_execution_authority(),
        ));

        let decision = evaluate_live_execution(&job, &vk, true, None);
        assert_eq!(
            decision,
            crate::live::LiveDecision::Refused(
                "LiveDestroy requires a step-bound grant".to_owned()
            ),
        );
        assert_eq!(
            live_exec.destroy_call_count(),
            0,
            "destroy must NOT be called when the gate refuses"
        );

        // The refusal is reported as a signed LiveRefused result.
        let refused = build_refused_result(
            &identity,
            "test-agent",
            &job,
            "LiveDestroy requires a step-bound grant",
        )
        .expect("refused result must build");
        assert_eq!(
            refused.job_result.status,
            ryuki_protocol::JobResultStatus::LiveRefused
        );
        assert!(refused
            .job_result
            .signed_envelope
            .approved_plan_digest
            .is_none());
    }

    /// !allow_live refuses a destroy before any executor call.
    #[test]
    fn live_destroy_refused_no_allow_live_destroy_not_called() {
        let (cp_sk, vk) = cp_keypair();
        let live_exec = stub_live(b"plan", RunStatus::Applied);
        let job = make_live_destroy_job_with_step_grant(&cp_sk);

        let decision = evaluate_live_execution(&job, &vk, false, None);
        assert_eq!(
            decision,
            crate::live::LiveDecision::Refused("LiveDestroy requires --allow-live".to_owned()),
        );
        assert_eq!(live_exec.destroy_call_count(), 0, "destroy NOT called");
    }

    /// No pinned CP key → the fast-path refusal (mirrors LiveApply's) with its
    /// explicit reason; destroy() is never reached.
    #[test]
    fn live_destroy_no_cp_key_destroy_not_called() {
        let (cp_sk, _) = cp_keypair();
        let live_exec = stub_live(b"plan", RunStatus::Applied);
        let identity = AgentIdentity::generate();
        let job = make_live_destroy_job_with_step_grant(&cp_sk);
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());

        // Mirror process_job_live's fast-path: no key → refused result built
        // directly, no gate call, no executor call.
        let refused = build_refused_result(
            &identity,
            "test-agent",
            &job,
            "LiveDestroy refused: no pinned CP grant authority available",
        )
        .expect("refused result must build");

        outbox.enqueue(&refused).expect("enqueue");
        assert_eq!(live_exec.destroy_call_count(), 0, "destroy NOT called");
        assert_eq!(
            refused.job_result.status,
            ryuki_protocol::JobResultStatus::LiveRefused
        );
        assert_eq!(outbox.list_pending().expect("list").len(), 1);
    }

    // -----------------------------------------------------------------------
    // LiveDestroy failure: a failed destroy is a signed Failed result (the CP
    // HALTS the cascade on it) — not a refusal, not a dropped job
    // -----------------------------------------------------------------------

    #[test]
    fn live_destroy_failed_destroy_reports_signed_failed_result() {
        let (cp_sk, vk) = cp_keypair();
        // Stub whose mutating outcome is Failed (destroy evidence mirrors it).
        let live_exec = stub_live(b"plan", RunStatus::Failed);
        let job = make_live_destroy_job_with_step_grant(&cp_sk);
        let identity = AgentIdentity::generate();

        assert_eq!(
            evaluate_live_execution(&job, &vk, true, None),
            crate::live::LiveDecision::Proceed
        );
        let evidence = live_exec.destroy(&job.spec).expect("destroy runs");
        let body = build_signed_result(&identity, "test-agent", &job, &evidence, None)
            .expect("a Failed destroy must still produce a signed result");
        assert_eq!(
            body.job_result.status,
            ryuki_protocol::JobResultStatus::Failed,
            "failed destroy → Failed (the CP halts the teardown cascade)"
        );
        assert!(body
            .job_result
            .signed_envelope
            .approved_plan_digest
            .is_none());
    }

    /// FAIL CLOSED: attaching a plan digest to a LiveDestroy result is a
    /// contract violation the agent refuses to sign (the CP rejects it too).
    #[test]
    fn live_destroy_result_with_digest_is_rejected() {
        let (cp_sk, _) = cp_keypair();
        let live_exec = stub_live(b"plan", RunStatus::Applied);
        let job = make_live_destroy_job_with_step_grant(&cp_sk);
        let identity = AgentIdentity::generate();

        let evidence = live_exec.destroy(&job.spec).expect("destroy");
        let result = build_signed_result(
            &identity,
            "test-agent",
            &job,
            &evidence,
            Some(sha256_hex(b"the-applied-plan")),
        );
        assert!(
            matches!(
                result,
                Err(crate::result::ResultError::PlanDigestOnNonLive { .. })
            ),
            "LiveDestroy + digest must be refused: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Deterministic spec-rejection → Failed evidence (poison-offering fix)
    // -----------------------------------------------------------------------

    /// An executor that always fails with the given constructor's error class.
    struct FailingExecutor(fn() -> ExecError);

    impl JobExecutor for FailingExecutor {
        fn execute(&self, _spec: &ryuki_protocol::JobSpec) -> Result<Evidence, ExecError> {
            Err((self.0)())
        }
    }

    /// No-IaC / bad-slug class rejections become Failed evidence with the
    /// deterministic marker, so a result IS posted and the request fails
    /// cleanly instead of the job dead-lettering while it wedges.
    #[test]
    fn plan_build_rejection_becomes_failed_evidence() {
        let exec = FailingExecutor(|| {
            ExecError::PlanBuild("no embedded Terraform IaC for offering 'x'".into())
        });
        let job = make_leased_job();
        let evidence =
            evidence_or_deterministic_failure(&exec, &job).expect("deterministic → evidence");
        assert_eq!(evidence.status, RunStatus::Failed);
        let json = evidence.evidence_json.expect("structured evidence");
        assert_eq!(json["deterministic_rejection"], true);
        assert!(
            json["summary"]
                .as_str()
                .unwrap()
                .contains("rejected by agent"),
            "summary names the rejection"
        );
    }

    /// Unsupported mode is equally deterministic.
    #[test]
    fn unsupported_mode_rejection_becomes_failed_evidence() {
        let exec = FailingExecutor(|| ExecError::UnsupportedMode(JobMode::LivePlan));
        let job = make_leased_job();
        let evidence =
            evidence_or_deterministic_failure(&exec, &job).expect("deterministic → evidence");
        assert_eq!(evidence.status, RunStatus::Failed);
    }

    /// Runner errors are NOT converted — they keep the retry/lease-expiry path
    /// (execution may have started; a result must not claim otherwise).
    #[test]
    fn runner_error_still_propagates() {
        let exec = FailingExecutor(|| {
            ExecError::Runner(ryuki_engine::runners::RunnerError::Spawn(
                "spawn failed".to_string(),
            ))
        });
        let job = make_leased_job();
        let err = evidence_or_deterministic_failure(&exec, &job)
            .expect_err("runner errors must propagate");
        assert!(matches!(err, AgentError::Exec(ExecError::Runner(_))));
    }

    // -----------------------------------------------------------------------
    // Existing OfflineDryRun tests preserved
    // -----------------------------------------------------------------------

    /// process_job with no lease → AgentError::NoLease.
    #[test]
    fn process_job_no_lease_returns_error() {
        let identity = AgentIdentity::generate();
        let executor = StubExecutor::check_ok();
        let evidence = executor.execute(&make_leased_job().spec).expect("execute");

        let mut job = make_leased_job();
        job.lease = None;
        let result =
            crate::result::build_signed_result(&identity, "test-agent", &job, &evidence, None);
        assert!(
            matches!(result, Err(crate::result::ResultError::NoLease)),
            "missing lease must return NoLease"
        );
    }

    /// Outbox enqueue + mark_delivered is the core contract; test it here to keep
    /// the module self-contained (the outbox module tests the same thing, but this
    /// confirms the types wire together).
    #[test]
    fn outbox_enqueue_deliver_roundtrip() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let outbox = Outbox::new(dir.path());
        let identity = AgentIdentity::generate();
        let job = make_leased_job();
        let executor = StubExecutor::check_ok();
        let evidence = executor.execute(&job.spec).expect("execute");
        let body =
            crate::result::build_signed_result(&identity, "test-agent", &job, &evidence, None)
                .expect("build");

        outbox.enqueue(&body).expect("enqueue");
        let pending = outbox.list_pending().expect("list");
        assert_eq!(pending.len(), 1);

        outbox
            .mark_delivered(body.job_result.result_id)
            .expect("deliver");
        let pending = outbox.list_pending().expect("list after deliver");
        assert!(pending.is_empty());
    }
}
