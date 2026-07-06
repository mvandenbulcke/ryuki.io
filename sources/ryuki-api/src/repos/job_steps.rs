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
    // #42 slice B1a: the `agent_jobs.evidence_digest` of this step's most
    // recent genuinely-successful LivePlan result, recorded when the step
    // moves to `AwaitingApproval`. NULL until then (and always NULL for
    // OfflineDryRun-only plans). Surfaced to approvers in slice B1b; read
    // directly only by tests today.
    #[cfg_attr(not(test), allow(dead_code))]
    pub live_plan_digest: Option<String>,
}

impl JobStepRow {
    /// Map this row onto the pure engine's `Step` shape for `validate_plan` /
    /// `ready_steps`. An unrecognized `status` value (schema skew) maps
    /// fail-safe to `Failed` — a step orchestration doesn't understand must
    /// block its dependents rather than silently be treated as ready.
    ///
    /// #42 slice B1a: the new live-path statuses (`Planning`,
    /// `AwaitingApproval`, `Applying`, `Applied`) are intentionally NOT part
    /// of the pure engine's `StepStatus` enum and fall into this same
    /// fail-safe-to-`Failed` arm. This is safe for THIS slice specifically
    /// because nothing in B1a's code paths calls `ready_steps`/`validate_plan`
    /// on a plan containing a step in one of these statuses in a way that
    /// would incorrectly fail a healthy in-flight plan: `dispatch_ready_steps`
    /// and `materialize_execution` only run readiness over an all-`Pending`
    /// plan (initial dispatch) or an `OfflineDryRun` mid-flight plan
    /// (slice 2b's backlink dispatch), and a `LivePlan` step reaching
    /// `AwaitingApproval` never triggers a `dispatch_ready_steps` call in
    /// B1a (downstream dispatch on LivePlan success is explicitly withheld —
    /// see `backlink_request_execution`). NOTE FOR B1b: once the approval
    /// endpoint needs to compute readiness over a plan that legitimately has
    /// an `AwaitingApproval` step sitting mid-plan, mapping it to `Failed`
    /// here would be WRONG (it would look like a terminal failure to
    /// `ready_steps`, not a step correctly parked awaiting an operator). This
    /// mapping will need to distinguish "in-flight-but-not-done" from
    /// "actually failed" before B1b starts calling readiness over live plans.
    pub fn to_orchestration_step(&self) -> Step {
        let status = match self.status.as_str() {
            "Pending" => StepStatus::Pending,
            "Running" => StepStatus::Running,
            "Succeeded" => StepStatus::Succeeded,
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

/// Record a step's successful LivePlan result: move it to `AwaitingApproval`
/// and stamp the plan's `evidence_digest` in one statement (#42 slice B1a).
/// This is the step-scoped analogue of what `requests_approve_live_apply`
/// already does for the single-job live path (re-deriving the latest
/// genuinely-successful LivePlan's `evidence_digest` from `agent_jobs`) — the
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

/// Reconcile a failing request's plan: mark every still-in-flight step
/// `Failed`. An in-flight step is one with a dispatched agent_job that has not
/// yet returned a terminal result — `Running` (an OfflineDryRun step, #42 2b)
/// OR `Planning` (a LivePlan step whose plan job is in flight, #42 B1a). Leaves
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
    let result = sqlx::query(
        "UPDATE job_steps SET status = 'Failed', updated_at = NOW() \
         WHERE request_id = $1 AND status IN ('Running', 'Planning')",
    )
    .bind(request_id)
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}
