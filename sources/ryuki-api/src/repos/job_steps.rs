//! Repository for a request's multi-step orchestration plan (#42 slice 2a).
//!
//! Persists what `ryuki_engine::job_orchestration` needs to decide readiness
//! (step key, dependencies, status) plus what dispatch needs (the IaC ref to
//! build a `JobSpec` from, and the dispatched `agent_jobs` back-link). The
//! readiness DECISION itself (`validate_plan` / `ready_steps`) stays in the
//! pure engine core — this module only reads/writes the durable state it
//! operates over.

use sqlx::PgExecutor;
use uuid::Uuid;

use ryuki_engine::job_orchestration::{Step, StepStatus};

/// One persisted step of a request's orchestration plan.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct JobStepRow {
    pub id: Uuid,
    // Read directly only by tests today (materialize_execution keys off
    // `step_key`, not `request_id`, since it already loads the plan scoped to
    // one request). Slice 2b's next-step dispatch (scanning across requests)
    // is expected to read this back.
    #[cfg_attr(not(test), allow(dead_code))]
    pub request_id: Uuid,
    pub step_key: String,
    pub depends_on: Vec<String>,
    pub iac_ref: String,
    pub status: String,
    // Read directly only by tests today; slice 2b's step-success backlink
    // will look up the step by its dispatched agent_job_id.
    #[cfg_attr(not(test), allow(dead_code))]
    pub agent_job_id: Option<Uuid>,
    // #42 slice B1a: the signed `agent_jobs.raw_plan_digest` of this step's
    // exact genuinely-successful LivePlan job/attempt, recorded when the step
    // moves to `AwaitingApproval`. It commits to the complete canonical plan
    // and is never interchangeable with the safe-projection evidence digest.
    // NULL until then (and always NULL for OfflineDryRun-only plans).
    #[cfg_attr(not(test), allow(dead_code))]
    pub live_plan_digest: Option<String>,
}

impl JobStepRow {
    /// Map this row onto the pure engine's `Step` shape for `validate_plan` /
    /// `ready_steps`. The pure engine only knows Pending/Running/Succeeded/
    /// Failed; the live-path statuses map onto that four-state model by their
    /// READINESS meaning:
    ///
    ///   * `Applied` (a step's live apply succeeded) → `Succeeded`. This is the
    ///     load-bearing #42 slice B1b mapping: a live-applied step is DONE, so
    ///     `ready_steps` must let its dependents proceed. (A dependent's own
    ///     LivePlan can only be computed once its dependency is really applied.)
    ///   * `Planning` / `AwaitingApproval` / `Applying` → `Running`. These are
    ///     in-flight (dispatched-but-not-done) live states: NOT ready to
    ///     dispatch a dependent (dep isn't `Succeeded`), and NOT a terminal
    ///     failure. `AwaitingApproval` in particular is a step correctly PARKED
    ///     on an operator — treating it as `Failed` (the old B1a fail-safe)
    ///     would make `ready_steps` see a healthy mid-flight plan as failed.
    ///   * anything else, incl. `Failed` and any unrecognized/schema-skew value
    ///     → `Failed` (fail-safe: a status the orchestration doesn't understand
    ///     must block its dependents rather than be treated as ready).
    pub fn to_orchestration_step(&self) -> Step {
        let status = match self.status.as_str() {
            "Pending" => StepStatus::Pending,
            // In-flight (dispatched, not terminal): forward live/dry-run states
            // plus `TearingDown` (a LiveDestroy in flight, #42 B2).
            "Running" | "Planning" | "AwaitingApproval" | "Applying" | "TearingDown" => {
                StepStatus::Running
            }
            "Succeeded" | "Applied" => StepStatus::Succeeded,
            // `ToreDown` (a rolled-back step) is terminal-but-NOT-succeeded — it
            // must never satisfy a forward dependency, so it maps to `Failed`
            // alongside the real failure/unknown cases. (Forward readiness is
            // never computed during teardown anyway; this keeps the mapping
            // total and safe.)
            _ => StepStatus::Failed,
        };
        Step {
            key: self.step_key.clone(),
            depends_on: self.depends_on.clone(),
            status,
        }
    }
}

/// Author a request's step plan: one row per `(step_key, depends_on, iac_ref)`,
/// all starting `Pending`. This is the AUTHORING seam: `requests_create`
/// (#42 slice 3) calls it inside the same transaction as the request INSERT,
/// for any offering whose `offering_step_template` is non-empty. Takes a
/// concrete `&mut PgConnection` (rather than a generic `impl PgExecutor`) so
/// it can be re-borrowed across the per-step INSERTs in the loop — callers
/// pass `&mut *tx` to author the plan inside the same transaction as the
/// request's creation/validation.
pub async fn insert_plan(
    executor: &mut sqlx::PgConnection,
    request_id: Uuid,
    steps: &[(&str, Vec<String>, &str)],
) -> Result<(), sqlx::Error> {
    for (step_key, depends_on, iac_ref) in steps {
        sqlx::query(
            "INSERT INTO job_steps (request_id, step_key, depends_on, iac_ref) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(request_id)
        .bind(step_key)
        .bind(depends_on)
        .bind(iac_ref)
        .execute(&mut *executor)
        .await?;
    }
    Ok(())
}

/// Load a request's full step plan, ordered by `step_key` for determinism.
pub async fn load_plan<'e, E>(executor: E, request_id: Uuid) -> Result<Vec<JobStepRow>, sqlx::Error>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as::<_, JobStepRow>(
        "SELECT id, request_id, step_key, depends_on, iac_ref, status, agent_job_id, live_plan_digest \
         FROM job_steps WHERE request_id = $1 ORDER BY step_key",
    )
    .bind(request_id)
    .fetch_all(executor)
    .await
}

/// Mark a step `Running` and record the `agent_jobs` row dispatched for it.
pub async fn mark_running<'e, E>(
    executor: E,
    step_id: Uuid,
    agent_job_id: Uuid,
) -> Result<(), sqlx::Error>
where
    E: PgExecutor<'e>,
{
    sqlx::query(
        "UPDATE job_steps SET status = 'Running', agent_job_id = $2, updated_at = NOW() \
         WHERE id = $1",
    )
    .bind(step_id)
    .bind(agent_job_id)
    .execute(executor)
    .await?;
    Ok(())
}

/// Mark a step `Planning` and record the dispatched LivePlan `agent_jobs` row.
/// Mirrors `mark_running` exactly but for the live-plan step-dispatch path
/// (#42 slice B1a) — the CP has dispatched a LivePlan job for this step and
/// is awaiting the agent's plan result.
pub async fn mark_planning<'e, E>(
    executor: E,
    step_id: Uuid,
    agent_job_id: Uuid,
) -> Result<(), sqlx::Error>
where
    E: PgExecutor<'e>,
{
    sqlx::query(
        "UPDATE job_steps SET status = 'Planning', agent_job_id = $2, updated_at = NOW() \
         WHERE id = $1",
    )
    .bind(step_id)
    .bind(agent_job_id)
    .execute(executor)
    .await?;
    Ok(())
}

/// Approve a step's live apply: move it `AwaitingApproval -> Applying` and
/// record the dispatched LiveApply `agent_jobs` row, guarded so it only fires
/// for a step genuinely still `AwaitingApproval` (#42 slice B1b). Returns the
/// number of rows affected — the approval endpoint asserts it is 1, so a
/// concurrent second approval (whose row is no longer `AwaitingApproval`)
/// updates zero rows and is rejected rather than minting a second grant.
#[allow(dead_code)]
pub async fn mark_applying<'e, E>(
    executor: E,
    step_id: Uuid,
    agent_job_id: Uuid,
) -> Result<u64, sqlx::Error>
where
    E: PgExecutor<'e>,
{
    let result = sqlx::query(
        "UPDATE job_steps SET status = 'Applying', agent_job_id = $2, updated_at = NOW() \
         WHERE id = $1 AND status = 'AwaitingApproval'",
    )
    .bind(step_id)
    .bind(agent_job_id)
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}

/// Record a step's successful LivePlan result: move it to `AwaitingApproval`
/// and stamp the signed raw canonical plan digest in one statement (#42 slice
/// B1a).
/// This is the step-scoped analogue of what `requests_approve_live_apply`
/// already does for the single-job live path (re-deriving the latest
/// genuinely-successful LivePlan's `raw_plan_digest` from `agent_jobs`) — the
/// CALLER (`backlink_request_execution`) is responsible for only invoking
/// this off a terminal, successful LivePlan result (`Planned`/`CheckOk`);
/// this function does not re-validate that itself.
pub async fn record_live_plan_digest<'e, E>(
    executor: E,
    step_id: Uuid,
    digest: &str,
) -> Result<(), sqlx::Error>
where
    E: PgExecutor<'e>,
{
    // Defense-in-depth against a stale-status TOCTOU: only park a step that is
    // genuinely still `Planning`. The caller (backlink) re-reads the request
    // status under the plan lock before calling this, which is the primary
    // guard; the `status = 'Planning'` predicate here means that even if a
    // concurrent failure already swept this step to `Failed`, this update
    // affects zero rows rather than resurrecting it to `AwaitingApproval`.
    sqlx::query(
        "UPDATE job_steps SET status = 'AwaitingApproval', live_plan_digest = $2, \
         updated_at = NOW() WHERE id = $1 AND status = 'Planning'",
    )
    .bind(step_id)
    .bind(digest)
    .execute(executor)
    .await?;
    Ok(())
}

/// Load a request's full step plan WITH a row lock (`FOR UPDATE`), ordered by
/// `step_key` for a deterministic lock-acquisition order (avoids deadlock
/// when two step completions for the SAME request are processed by
/// concurrent transactions — both always acquire the plan's row locks in the
/// same order).
///
/// This is the #42 slice 2b concurrency primitive: the step-success backlink
/// takes this lock BEFORE reading step statuses to decide readiness/
/// completion, so two step-jobs completing concurrently for one request
/// serialize on the plan rather than racing (no double-dispatch of a
/// newly-ready step, no missed final-step transition).
pub async fn load_plan_for_update(
    executor: &mut sqlx::PgConnection,
    request_id: Uuid,
) -> Result<Vec<JobStepRow>, sqlx::Error> {
    sqlx::query_as::<_, JobStepRow>(
        "SELECT id, request_id, step_key, depends_on, iac_ref, status, agent_job_id, live_plan_digest \
         FROM job_steps WHERE request_id = $1 ORDER BY step_key FOR UPDATE",
    )
    .bind(request_id)
    .fetch_all(executor)
    .await
}

/// Load ONE step of a request by its `step_key`, WITH a row lock (`FOR
/// UPDATE`). The per-step approval endpoint (#42 slice B1b) uses this to
/// serialize concurrent approvals of the SAME step: it locks the row, checks
/// the step is still `AwaitingApproval`, mints the grant, and flips it to
/// `Applying` — all under this lock, so a racing second approval blocks and
/// then sees `Applying` (no double-mint).
#[allow(dead_code)]
pub async fn load_step_for_update(
    executor: &mut sqlx::PgConnection,
    request_id: Uuid,
    step_key: &str,
) -> Result<Option<JobStepRow>, sqlx::Error> {
    sqlx::query_as::<_, JobStepRow>(
        "SELECT id, request_id, step_key, depends_on, iac_ref, status, agent_job_id, live_plan_digest \
         FROM job_steps WHERE request_id = $1 AND step_key = $2 FOR UPDATE",
    )
    .bind(request_id)
    .bind(step_key)
    .fetch_all(executor)
    .await
    .map(|mut v| v.pop())
}

/// Look up the step (if any) that a dispatched `agent_jobs.id` is linked to.
/// The step-success backlink resolves this via its already-locked plan
/// (`plan.iter().find(...)`) rather than a second query, so this is not
/// currently called; kept as the direct by-job-id lookup primitive for
/// callers that have not already loaded the plan.
#[allow(dead_code)]
pub async fn step_for_job<'e, E>(
    executor: E,
    job_id: Uuid,
) -> Result<Option<JobStepRow>, sqlx::Error>
where
    E: PgExecutor<'e>,
{
    sqlx::query_as::<_, JobStepRow>(
        "SELECT id, request_id, step_key, depends_on, iac_ref, status, agent_job_id, live_plan_digest \
         FROM job_steps WHERE agent_job_id = $1",
    )
    .bind(job_id)
    .fetch_optional(executor)
    .await
}

/// Set a step's status directly (e.g. `Succeeded`/`Failed` on step
/// completion). Does NOT touch `agent_job_id` — that link is established once,
/// at dispatch time, by [`mark_running`].
pub async fn mark_status<'e, E>(executor: E, step_id: Uuid, status: &str) -> Result<(), sqlx::Error>
where
    E: PgExecutor<'e>,
{
    sqlx::query("UPDATE job_steps SET status = $2, updated_at = NOW() WHERE id = $1")
        .bind(step_id)
        .bind(status)
        .execute(executor)
        .await?;
    Ok(())
}

/// Move an `Applied` step to `TearingDown` and record the dispatched
/// LiveDestroy `agent_jobs` row (#42 slice B2-2). Guarded on the step still
/// being `Applied` so a step is torn down at most once; returns the rows
/// affected (the teardown dispatcher asserts 1).
pub async fn mark_tearing_down<'e, E>(
    executor: E,
    step_id: Uuid,
    agent_job_id: Uuid,
) -> Result<u64, sqlx::Error>
where
    E: PgExecutor<'e>,
{
    let result = sqlx::query(
        "UPDATE job_steps SET status = 'TearingDown', agent_job_id = $2, updated_at = NOW() \
         WHERE id = $1 AND status = 'Applied'",
    )
    .bind(step_id)
    .bind(agent_job_id)
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}

/// Reconcile a failing request's plan: mark every still-in-flight step
/// `Failed`. An in-flight step is one with a dispatched agent_job that has not
/// yet returned a terminal result — `Running` (an OfflineDryRun step, #42 2b),
/// `Planning` (a LivePlan step whose plan job is in flight, #42 B1a), OR
/// `Applying` (a LiveApply step whose apply job is in flight, #42 B1b). Leaves
/// `Pending` steps (never dispatched — honestly "never started"), `Succeeded`,
/// `Applied`, `AwaitingApproval` (parked on an operator, no live op running),
/// and already-`Failed` steps untouched. Returns the number of rows swept.
///
/// This closes a concurrency gap: when independent parallel steps complete in
/// separate transactions, one sibling's success can dispatch a downstream step
/// (flipping it `Running`/`Planning`) just before another sibling's failure
/// fails the request. Without this sweep, that freshly-dispatched step's row
/// would be stranded in-flight forever — its eventual result hits the
/// backlink's `status != 'executing'` early-guard and is silently swallowed.
/// Sweeping in-flight steps to `Failed` in the SAME transaction as the
/// request-fail keeps the plan's terminal state consistent with the request's.
/// (`Pending` is NOT swept: a never-dispatched step under a failed request is
/// inert and its `Pending` status truthfully records that it never ran.)
pub async fn fail_inflight_steps<'e, E>(executor: E, request_id: Uuid) -> Result<u64, sqlx::Error>
where
    E: PgExecutor<'e>,
{
    // Sweep the in-flight steps to `Failed` AND, in the SAME statement, cancel any still
    // `Pending` agent_job linked to a swept step. The cancel closes the #42 B2-2 approval-
    // vs-failure race: a step-approval that commits microseconds before this sweep leaves a
    // freshly dispatched `Pending` LiveApply job whose step is now `Failed`. Without cancelling
    // it, that job stays leaseable (`poll_job` filters only by platform + `status = 'Pending'`,
    // not request/step state) and could later apply live infra OUTSIDE the rollback's coverage.
    // `Leased`/`Running` jobs are deliberately left to the lease-expiry reconcile path — they
    // may have already touched infra, so they need operator reconciliation, not a silent cancel.
    // The returned count is the number of swept STEPS (identical to the old rows_affected).
    let swept: i64 = sqlx::query_scalar(
        "WITH swept AS ( \
             UPDATE job_steps SET status = 'Failed', updated_at = NOW() \
             WHERE request_id = $1 AND status IN ('Running', 'Planning', 'Applying') \
             RETURNING agent_job_id \
         ), cancelled AS ( \
             UPDATE agent_jobs SET status = 'Cancelled', updated_at = NOW() \
             WHERE id IN (SELECT agent_job_id FROM swept WHERE agent_job_id IS NOT NULL) \
               AND status = 'Pending' \
             RETURNING id \
         ) \
         SELECT count(*) FROM swept",
    )
    .bind(request_id)
    .fetch_one(executor)
    .await?;
    Ok(u64::try_from(swept).unwrap_or(0))
}

/// Sweep any steps parked `AwaitingApproval` to `Failed` (#42 slice B2-2).
///
/// Unlike [`fail_inflight_steps`], which deliberately leaves `AwaitingApproval`
/// alone during a normal request-fail (the request then leaves `executing`, so
/// the approval endpoint's `status == executing` guard already blocks approval),
/// a request that begins AUTO COMPENSATING TEARDOWN intentionally STAYS
/// `executing` while its `LiveDestroy` jobs run. That leaves the approval
/// endpoint reachable, so a still-parked `AwaitingApproval` step could be
/// approved into a fresh `LiveApply` AFTER rollback started — minting live infra
/// the teardown will not clean up, possibly after its dependency was destroyed.
/// Failing those parked steps up front (in the same transaction that starts the
/// teardown) removes anything left to approve. Returns the rows swept.
pub async fn fail_awaiting_approval_steps<'e, E>(
    executor: E,
    request_id: Uuid,
) -> Result<u64, sqlx::Error>
where
    E: PgExecutor<'e>,
{
    let result = sqlx::query(
        "UPDATE job_steps SET status = 'Failed', updated_at = NOW() \
         WHERE request_id = $1 AND status = 'AwaitingApproval'",
    )
    .bind(request_id)
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}
