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
/// all starting `Pending`. This is the slice-2a AUTHORING seam — called
/// directly by tests today; a future POST endpoint will call the same
/// function. Takes a concrete `&mut PgConnection` (rather than a generic
/// `impl PgExecutor`) so it can be re-borrowed across the per-step INSERTs in
/// the loop — callers pass `&mut *tx` to author the plan inside the same
/// transaction as the request's creation/validation.
#[cfg_attr(not(test), allow(dead_code))]
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
