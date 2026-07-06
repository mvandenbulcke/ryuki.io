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
}

impl JobStepRow {
    /// Map this row onto the pure engine's `Step` shape for `validate_plan` /
    /// `ready_steps`. An unrecognized `status` value (schema skew) maps
    /// fail-safe to `Failed` — a step orchestration doesn't understand must
    /// block its dependents rather than silently be treated as ready.
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
        "SELECT id, request_id, step_key, depends_on, iac_ref, status, agent_job_id \
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
        "SELECT id, request_id, step_key, depends_on, iac_ref, status, agent_job_id \
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
        "SELECT id, request_id, step_key, depends_on, iac_ref, status, agent_job_id \
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

/// Reconcile a failing request's plan: mark every still-in-flight (`Running`,
/// i.e. dispatched-but-not-yet-terminal) step `Failed`. Leaves `Pending` steps
/// (never dispatched — honestly "never started"), `Succeeded`, and
/// already-`Failed` steps untouched. Returns the number of rows swept.
///
/// This closes a concurrency gap in #42 slice 2b: when independent parallel
/// steps complete in separate transactions, one sibling's success can dispatch
/// a downstream step (flipping it `Running`) just before another sibling's
/// failure fails the request. Without this sweep, that freshly-dispatched
/// step's row would be stranded `Running` forever — its eventual result hits
/// the backlink's `status != 'executing'` early-guard and is silently
/// swallowed. Sweeping in-flight steps to `Failed` in the SAME transaction as
/// the request-fail keeps the plan's terminal state consistent with the
/// request's. (Only `Running` is swept, not `Pending`: a never-dispatched step
/// under a failed request is inert and its `Pending` status truthfully records
/// that it never ran.)
pub async fn fail_inflight_steps<'e, E>(executor: E, request_id: Uuid) -> Result<u64, sqlx::Error>
where
    E: PgExecutor<'e>,
{
    let result = sqlx::query(
        "UPDATE job_steps SET status = 'Failed', updated_at = NOW() \
         WHERE request_id = $1 AND status = 'Running'",
    )
    .bind(request_id)
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}
