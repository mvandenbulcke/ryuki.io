//! Repository for the #31 drift-recheck scan (slice 1).

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
    /// The MOST RECENT successful live-apply verification: `agent_jobs.completed_at`
    /// where `result_status` is 'applied' or 'verified'.
    pub last_verified: chrono::DateTime<chrono::Utc>,
}

/// Every `operational` deployment that has at least one successful live-APPLY
/// verification, with its MOST RECENT such verification time. INNER JOIN so only
/// deployments that actually ran against live infra are considered. The interval
/// gate and the priority are applied in Rust via the pure engine classifier — this
/// repo does only the (bounded) selection, so the unit-tested decision core is the
/// one that gates production. Executor-generic so the scheduler tick runs it on
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
        "SELECT r.id AS request_id, r.site, r.environment, \
                MAX(j.completed_at) AS last_verified \
         FROM requests r \
         JOIN agent_jobs j ON j.request_id = r.id \
         WHERE r.status = 'operational' \
           AND j.mode = 'LiveApply' \
           AND j.result_status IN ('applied', 'verified') \
           AND j.completed_at IS NOT NULL \
         GROUP BY r.id, r.site, r.environment",
    )
    .fetch_all(executor)
    .await
}
