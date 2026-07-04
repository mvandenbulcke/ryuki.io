//! Repository for the #31 drift-recheck scan (slice 1) and drift-recheck job
//! dispatch (slice 2b-2).

use sqlx::PgExecutor;

/// One operational deployment and when it was last verified against live infra —
/// a CANDIDATE for a drift re-check. The overdue DECISION (is it older than the
/// interval?) and the priority are made by the pure engine gate
/// `ryuki_engine::drift_scan::{is_drift_recheck_due, drift_recheck_priority}`, NOT
/// here, so the unit-tested predicate is the one that actually gates production.
#[derive(Debug, sqlx::FromRow)]
pub struct DriftRecheckCandidate {
    pub request_id: uuid::Uuid,
    pub site: String,
    pub environment: String,
    /// When this deployment was last verified against live infra: the GREATEST of
    /// its most recent successful live-APPLY (`agent_jobs.completed_at` where
    /// `result_status` is 'applied'/'verified') and its last completed drift
    /// re-check (`requests.last_drift_check_at`, #31 slice 2b). Taking the later of
    /// the two means a completed re-check RESETS the overdue clock — otherwise a
    /// LivePlan re-check (which never advances the LiveApply timestamp) would leave
    /// the deployment perpetually overdue and re-checked every scan.
    pub last_verified: chrono::DateTime<chrono::Utc>,
    /// `agent_jobs.platform` of the most recent LiveApply job — the target for the
    /// dispatched LivePlan drift-recheck (slice 2b-2). Carried alongside the
    /// candidate (rather than re-queried at dispatch time) so the dispatch scan
    /// reuses the EXACT same "latest LiveApply" row the overdue decision was made
    /// from.
    pub platform: String,
    /// The most recent LiveApply job's `spec` JSONB — the basis for the dispatched
    /// LivePlan drift-recheck (slice 2b-2). Dispatch clones this and swaps
    /// `mode` to `LivePlan` (mirrors `approve_live_apply`'s LivePlan→LiveApply
    /// mirror, just in the opposite direction).
    pub spec: serde_json::Value,
}

/// Every `operational` deployment that has at least one successful live-APPLY
/// verification, with its MOST RECENT such verification's time, platform, and
/// spec. `DISTINCT ON (r.id)` + `ORDER BY r.id, j.completed_at DESC` picks the
/// single newest qualifying LiveApply job per request — that job's
/// `completed_at` is by construction the MAX for that request, so
/// `GREATEST(j.completed_at, r.last_drift_check_at)` below is exactly the same
/// "last verified" value the prior `GROUP BY`/`MAX` formulation produced; the
/// only change is that we now also carry that winning row's `platform` and
/// `spec` forward for slice 2b-2 dispatch. INNER JOIN so only deployments that
/// actually ran against live infra are considered. The interval gate and the
/// priority are applied in Rust via the pure engine classifier — this repo does
/// only the (bounded) selection, so the unit-tested decision core is the one
/// that gates production. Executor-generic so the scheduler tick runs it on
/// `&mut *tx`.
///
/// The candidate is the last `mode = 'LiveApply'` job whose `result_status` is
/// 'applied' or 'verified' (a converged apply, #43). Both `mode = 'LiveApply'` AND
/// the success `result_status` are required: those statuses only ever arise from a
/// live apply today, but pinning `mode` makes the "last live-apply verification"
/// invariant EXPLICIT so a later LivePlan drift-recheck job (slice 2) can never be
/// mistaken for the applied baseline.
pub async fn operational_deployments_for_drift_recheck<'e>(
    executor: impl PgExecutor<'e>,
) -> Result<Vec<DriftRecheckCandidate>, sqlx::Error> {
    sqlx::query_as::<_, DriftRecheckCandidate>(
        "SELECT DISTINCT ON (r.id) r.id AS request_id, r.site, r.environment, \
                GREATEST(j.completed_at, r.last_drift_check_at) AS last_verified, \
                j.platform, j.spec \
         FROM requests r \
         JOIN agent_jobs j ON j.request_id = r.id \
         WHERE r.status = 'operational' \
           AND j.mode = 'LiveApply' \
           AND j.result_status IN ('applied', 'verified') \
           AND j.completed_at IS NOT NULL \
         ORDER BY r.id, j.completed_at DESC, j.id DESC",
    )
    .fetch_all(executor)
    .await
}

/// Is there already an in-flight (Pending/Leased/Running) scheduler-dispatched
/// drift-recheck job for this request? A dispatch scan must never stack a second
/// recheck on top of one that hasn't finished yet — `agent_jobs` has no partial-
/// unique constraint like `shift_queue`'s dedup index, so the dispatch scan must
/// check explicitly before inserting.
pub async fn open_drift_recheck_job_exists<'e>(
    executor: impl PgExecutor<'e>,
    request_id: uuid::Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM agent_jobs \
         WHERE request_id = $1 AND origin = $2 AND status IN ('Pending', 'Leased', 'Running'))",
    )
    .bind(request_id)
    .bind(ryuki_engine::drift_scan::DRIFT_RECHECK_JOB_ORIGIN)
    .fetch_one(executor)
    .await
}

/// Insert a scheduler-dispatched LivePlan drift-recheck job (#31 slice 2b-2). The
/// `mode` COLUMN is the PascalCase label `'LivePlan'` (matching every other
/// `agent_jobs.mode` write in this codebase); `spec_json` is expected to already
/// carry the mirrored snake_case `"mode":"live_plan"` inside its JSONB — both
/// encodings are independent and the caller is responsible for keeping them in
/// sync. `origin` is set to [`ryuki_engine::drift_scan::DRIFT_RECHECK_JOB_ORIGIN`]
/// so the CP ingest path classifies this job's result as a drift re-check (not a
/// normal operator plan) and resets `requests.last_drift_check_at`. `status`
/// defaults to `'Pending'` — the agent picks it up like any other dispatched job.
pub async fn insert_drift_recheck_job<'e>(
    executor: impl PgExecutor<'e>,
    request_id: uuid::Uuid,
    platform: &str,
    spec_json: &serde_json::Value,
) -> Result<uuid::Uuid, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO agent_jobs (request_id, platform, spec, mode, origin) \
         VALUES ($1, $2, $3, 'LivePlan', $4) RETURNING id",
    )
    .bind(request_id)
    .bind(platform)
    .bind(spec_json)
    .bind(ryuki_engine::drift_scan::DRIFT_RECHECK_JOB_ORIGIN)
    .fetch_one(executor)
    .await
}
