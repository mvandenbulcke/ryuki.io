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
//! ## Error strategy
//!
//! All errors are wrapped in [`AgentError`].  `process_job` and `replay_outbox`
//! return `Result`; `run_loop` logs errors and backs off — it never panics.

use std::time::Duration;

use thiserror::Error;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    client::{ClientError, CpClient},
    executor::{ExecError, JobExecutor},
    identity::AgentIdentity,
    outbox::{Outbox, OutboxError},
    result::{build_signed_result, ResultError},
};
use ryuki_protocol::Job;

// ---------------------------------------------------------------------------
// AgentError
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("control-plane client error: {0}")]
    Client(#[from] ClientError),
    #[error("executor error: {0}")]
    Exec(#[from] ExecError),
    #[error("result build error: {0}")]
    Result(#[from] ResultError),
    #[error("outbox error: {0}")]
    Outbox(#[from] OutboxError),
    #[error("serialisation error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("job has no active lease — cannot process")]
    NoLease,
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

    // Step 2: execute.
    let evidence = executor.execute(&job.spec)?;

    // Step 3: build once. result_id is the idempotency key for the outbox.
    // OfflineDryRun is the only mode supported by the current executor.
    // Live modes (LivePlan / LiveApply) are S5b — pass None for the
    // approved_plan_digest; the live executor (S5b-2b-ii) will supply
    // the real digest when it builds LiveApply+Applied results.
    let body = build_signed_result(identity, agent_id, job, &evidence, None)?;
    let result_id: Uuid = body.job_result.result_id;

    // Step 4: enqueue BEFORE the network POST (durable-first).
    outbox.enqueue(&body)?;

    // Step 5: POST to the CP.
    let post_body = serde_json::to_value(&body)?;
    match client.post_result(job.id, post_body).await {
        Ok(_) => {
            // Step 6: success — remove the outbox file.
            outbox.mark_delivered(result_id)?;
            info!(
                job_id = %job.id,
                result_id = %result_id,
                "job result posted and delivered"
            );
        }
        Err(e) => {
            // POST failed — leave the file in the outbox for replay.
            // Do NOT rebuild; the next replay reuses the same result_id.
            warn!(
                job_id = %job.id,
                result_id = %result_id,
                error = %e,
                "post_result failed — result left in outbox for replay"
            );
            // Do not propagate as an error; the job was processed correctly
            // (executed + signed + durably enqueued). The delivery failure is
            // transient and will be retried by replay_outbox.
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// replay_outbox
// ---------------------------------------------------------------------------

/// On startup: iterate every pending outbox entry and attempt to re-POST it.
///
/// Each successful POST is followed by `mark_delivered`. Failed POSTs are
/// left in the outbox for the next startup cycle. Returns the counts for
/// logging / testing.
pub async fn replay_outbox(
    client: &CpClient,
    outbox: &Outbox,
) -> Result<(usize, usize), AgentError> {
    let pending = outbox.list_pending()?;
    let total = pending.len();

    if total > 0 {
        info!(count = total, "outbox replay: re-posting pending results");
    }

    let mut delivered = 0usize;
    let mut failed = 0usize;

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
                    "outbox replay: serialisation failed — skipping"
                );
                failed += 1;
                continue;
            }
        };

        match client.post_result(job_id, post_body).await {
            Ok(_) => {
                if let Err(e) = outbox.mark_delivered(result_id) {
                    warn!(
                        result_id = %result_id,
                        error = %e,
                        "outbox replay: delivered but failed to remove file"
                    );
                }
                delivered += 1;
                info!(job_id = %job_id, result_id = %result_id, "outbox replay: delivered");
            }
            Err(e) => {
                warn!(
                    job_id = %job_id,
                    result_id = %result_id,
                    error = %e,
                    "outbox replay: POST failed — will retry on next startup"
                );
                failed += 1;
            }
        }
    }

    if total > 0 {
        info!(delivered, failed, "outbox replay complete");
    }

    Ok((delivered, failed))
}

// ---------------------------------------------------------------------------
// run_loop
// ---------------------------------------------------------------------------

/// Main agent pull-loop.
///
/// 1. Replay the outbox (at-least-once delivery of prior results).
/// 2. Loop:
///    - Send a heartbeat (idle or with running job id).
///    - Poll for a job.
///    - `Some(job)` → `process_job`.
///    - `None` → sleep `poll_interval`.
///    - Errors → `warn` + sleep `poll_interval` (never panic).
///
/// This function never returns under normal operation.
pub async fn run_loop(
    client: &CpClient,
    executor: &dyn JobExecutor,
    identity: &AgentIdentity,
    agent_id: &str,
    outbox: &Outbox,
    poll_interval: Duration,
) {
    // Replay any results left over from a prior run.
    match replay_outbox(client, outbox).await {
        Ok((delivered, failed)) => {
            if delivered > 0 || failed > 0 {
                info!(delivered, failed, "startup outbox replay finished");
            }
        }
        Err(e) => {
            warn!(error = %e, "startup outbox replay failed — continuing");
        }
    }

    info!("entering poll loop");

    loop {
        // Heartbeat — send while idle (no running job in this loop tick).
        if let Err(e) = client.heartbeat(None).await {
            warn!(error = %e, "heartbeat failed — continuing");
        }

        // Poll for the next available job.
        match client.poll().await {
            Ok(Some(job)) => {
                info!(job_id = %job.id, "job received — processing");
                // Send a running-heartbeat so the CP knows we're active.
                if let Err(e) = client.heartbeat(Some(job.id)).await {
                    warn!(error = %e, "heartbeat (running) failed — continuing");
                }
                if let Err(e) =
                    process_job(client, executor, identity, agent_id, outbox, &job).await
                {
                    warn!(
                        job_id = %job.id,
                        error = %e,
                        "process_job failed — job may be retried by the CP lease expiry sweep"
                    );
                }
            }
            Ok(None) => {
                // No work available — wait before polling again.
                tokio::time::sleep(poll_interval).await;
            }
            Err(e) => {
                warn!(error = %e, "poll failed — backing off");
                tokio::time::sleep(poll_interval).await;
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
    use chrono::Utc;
    use ryuki_protocol::{JobLease, JobMode, JobSpec, JobStatus};
    use std::collections::BTreeMap;
    use uuid::Uuid;

    use crate::{executor::StubExecutor, identity::AgentIdentity, outbox::Outbox};

    fn make_leased_job() -> Job {
        let spec = JobSpec {
            request_id: Uuid::new_v4(),
            offering_id: Uuid::new_v4(),
            iac_ref: "patch-maintenance@v1.0.0".to_string(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            mode: JobMode::OfflineDryRun,
        };
        let lease = JobLease {
            attempt_id: Uuid::new_v4(),
            lease_generation: 1,
            fencing_token: Uuid::new_v4().to_string(),
            deadline: Utc::now() + chrono::Duration::minutes(5),
            cp_nonce: Uuid::new_v4().to_string(),
        };
        Job {
            id: Uuid::new_v4(),
            platform: "test-platform".to_string(),
            spec,
            status: JobStatus::Running,
            lease: Some(lease),
            live_context: None,
        }
    }

    /// process_job with no lease → AgentError::NoLease.
    #[test]
    fn process_job_no_lease_returns_error() {
        // We can't easily unit-test the async function without a live CP, but
        // we CAN test that a job with no lease fails at the validation step
        // within build_signed_result.  The test for the full async path is the
        // e2e in ryuki-api.
        let identity = AgentIdentity::generate();
        let executor = StubExecutor::check_ok();
        let evidence = executor.execute(&make_leased_job().spec).expect("execute");

        // Jobwith no lease: build_signed_result must return ResultError::NoLease.
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
