//! Repository functions for `dr_plans`.
//!
//! Full `DrPlan` round-tripped through `plan_json` JSONB column.
//! Scalar `status` and `site` columns kept in sync for queryability.
//! xmin CAS in `transition` guards all mutations (including same-status ones like rpo/rto updates).

use ryuki_engine::dr_testing::{DrPlan, DrPlanStatus};
use sqlx::PgPool;

pub const COLUMNS: &str = "id, status, plan_json::text AS plan_json, xmin::text AS row_version";

#[derive(sqlx::FromRow)]
pub struct DrPlanRow {
    pub id: String,
    pub status: String,
    pub plan_json: Option<String>,
    pub row_version: String,
}

impl DrPlanRow {
    pub fn into_model(self) -> Result<DrPlan, sqlx::Error> {
        let raw = self
            .plan_json
            .ok_or_else(|| sqlx::Error::Decode("dr_plans.plan_json: NULL".into()))?;
        let mut entity: DrPlan = serde_json::from_str(&raw).map_err(|e| {
            sqlx::Error::Decode(format!("dr_plans.plan_json: corrupt persisted value: {e}").into())
        })?;
        // DB status column is authoritative on read
        entity.status = decode_status(&self.status)
            .map_err(|e| sqlx::Error::Decode(format!("dr_plans.status: {e}").into()))?;
        entity.id = self.id;
        Ok(entity)
    }
}

/// Canonical serde variant name for a `DrPlanStatus` as stored in the DB.
/// Matches the `#[serde(rename_all = "kebab-case")]` derivation.
pub fn status_str(s: &DrPlanStatus) -> &'static str {
    match s {
        DrPlanStatus::Draft => "draft",
        DrPlanStatus::Approved => "approved",
        DrPlanStatus::Active => "active",
        DrPlanStatus::Expired => "expired",
    }
}

fn decode_status(s: &str) -> Result<DrPlanStatus, String> {
    serde_json::from_str(&format!("\"{s}\""))
        .map_err(|e| format!("unknown dr_plans status '{s}': {e}"))
}

/// Fetch the RAW rows for all DR plans with status 'active' or 'approved' for the
/// overdue-scan job. The scan classifies each plan by comparing `next_test_due`
/// against NOW() — only plans that COULD be executed (active/approved) are considered;
/// draft/expired are excluded. Returns `DrPlanRow` (not the deserialized model) so the
/// caller can `into_model()` PER ROW and skip a single corrupt `plan_json` without
/// failing the whole scan (one malformed persisted row must not poison the fan-out for
/// every healthy plan — mirrors restore_overdue_scan's per-row resilience).
pub async fn active_plans_for_overdue_scan(
    executor: impl sqlx::PgExecutor<'_>,
) -> Result<Vec<DrPlanRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM dr_plans WHERE status IN ('active', 'approved') ORDER BY id"
    ))
    .fetch_all(executor)
    .await
}

pub async fn insert(executor: impl sqlx::PgExecutor<'_>, plan: &DrPlan) -> Result<(), sqlx::Error> {
    let plan_json = serde_json::to_value(plan)
        .map_err(|e| sqlx::Error::Decode(format!("dr_plans: serialize failed: {e}").into()))?;
    sqlx::query(
        "INSERT INTO dr_plans (id, name, site, status, plan_json) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&plan.id)
    .bind(&plan.name)
    .bind(&plan.site)
    .bind(status_str(&plan.status))
    .bind(plan_json)
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn get(pool: &PgPool, id: &str) -> Result<Option<(DrPlan, String)>, sqlx::Error> {
    let row: Option<DrPlanRow> =
        sqlx::query_as(&format!("SELECT {COLUMNS} FROM dr_plans WHERE id = $1"))
            .bind(id)
            .fetch_optional(pool)
            .await?;
    match row {
        Some(r) => {
            let version = r.row_version.clone();
            Ok(Some((r.into_model()?, version)))
        }
        None => Ok(None),
    }
}

pub async fn list(pool: &PgPool) -> Result<Vec<DrPlan>, sqlx::Error> {
    let rows: Vec<DrPlanRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM dr_plans ORDER BY created_at DESC, id DESC"
    ))
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(|r| r.into_model()).collect()
}

/// List DR plans (optionally site-filtered), bounded to one `LIMIT`/`OFFSET`
/// page (#14). SEPARATE from [`list`] because that feeds startup hydration
/// (`replace_plans`, FATAL-on-error) which must see EVERY row — only the list
/// endpoint pages. Handles both all-sites (empty `site`) and a site filter, so
/// it supersedes the old `list_by_site`. `ORDER BY created_at DESC, id DESC`
/// ends in the unique PK `id`, so the page is a stable cut.
pub async fn list_page(
    pool: &PgPool,
    site: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<DrPlan>, sqlx::Error> {
    let rows: Vec<DrPlanRow> = if site.is_empty() {
        sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM dr_plans ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM dr_plans \
             WHERE site = $1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3"
        ))
        .bind(site)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    };
    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Count DR plans (optionally site-filtered) — the pagination total for
/// [`list_page`], using the SAME `WHERE` so the count matches the paged set.
pub async fn count(pool: &PgPool, site: &str) -> Result<i64, sqlx::Error> {
    if site.is_empty() {
        sqlx::query_scalar("SELECT COUNT(*) FROM dr_plans")
            .fetch_one(pool)
            .await
    } else {
        sqlx::query_scalar("SELECT COUNT(*) FROM dr_plans WHERE site = $1")
            .bind(site)
            .fetch_one(pool)
            .await
    }
}

/// Atomically update a DR plan IFF the row has NOT been written since it was
/// read (xmin CAS). Returns `Ok(false)` on CAS mismatch (row absent or
/// concurrently modified) — handler maps this to 409.
///
/// xmin guards ALL mutations including same-status ones (e.g. rpo/rto update).
pub async fn transition(
    executor: &mut sqlx::PgConnection,
    id: &str,
    expected_version: &str,
    updated: &DrPlan,
) -> Result<bool, sqlx::Error> {
    let plan_json = serde_json::to_value(updated)
        .map_err(|e| sqlx::Error::Decode(format!("dr_plans: serialize failed: {e}").into()))?;
    // The scalar `name` column is denormalized for queryability and kept in sync
    // here so a general PUT (which may edit the name) does not leave it stale.
    // `site` stays OUT of the UPDATE: it is the immutable RBAC scope key.
    let res = sqlx::query(
        "UPDATE dr_plans SET \
         name = $2, \
         status = $3, \
         plan_json = $4, \
         updated_at = NOW() \
         WHERE id = $1 AND xmin = $5::xid",
    )
    .bind(id)
    .bind(&updated.name)
    .bind(status_str(&updated.status))
    .bind(plan_json)
    .bind(expected_version)
    .execute(&mut *executor)
    .await?;
    if res.rows_affected() == 0 {
        return Ok(false);
    }
    Ok(true)
}

/// Outcome of a DR-plan delete attempt (xmin CAS + test-run history guard).
#[derive(Debug, PartialEq, Eq)]
pub enum DeleteOutcome {
    /// The plan row was deleted.
    Deleted,
    /// No row with this id (already gone).
    NotFound,
    /// The plan has test-run history; the delete is refused to protect the runs.
    HasHistory,
    /// The row was modified concurrently (xmin moved); caller should reload.
    StaleVersion,
}

/// Delete a DR plan IFF it still matches `expected_version` (xmin CAS) AND has no
/// test-run history. The `NOT EXISTS` is the friendly common-case precheck; the
/// `ON DELETE RESTRICT` FK (migration 124) is the structural race backstop — a
/// concurrent `dr_test_start` that inserts a run AFTER the `NOT EXISTS` snapshot
/// makes the DELETE itself error with FK `23503`, which we map to `HasHistory`.
/// On 0 rows we re-read to disambiguate `NotFound` / `HasHistory` / `StaleVersion`.
pub async fn delete(
    executor: &mut sqlx::PgConnection,
    id: &str,
    expected_version: &str,
) -> Result<DeleteOutcome, sqlx::Error> {
    let res = sqlx::query(
        "DELETE FROM dr_plans \
         WHERE id = $1 AND xmin = $2::xid \
           AND NOT EXISTS (SELECT 1 FROM dr_test_runs WHERE plan_id = $1)",
    )
    .bind(id)
    .bind(expected_version)
    .execute(&mut *executor)
    .await;

    match res {
        Ok(r) if r.rows_affected() == 1 => Ok(DeleteOutcome::Deleted),
        Ok(_) => {
            // 0 rows: the row is gone, runs exist, or xmin moved. Re-read to
            // disambiguate so the handler returns a precise status.
            let current_version: Option<String> =
                sqlx::query_scalar("SELECT xmin::text FROM dr_plans WHERE id = $1")
                    .bind(id)
                    .fetch_optional(&mut *executor)
                    .await?;
            match current_version {
                None => Ok(DeleteOutcome::NotFound),
                Some(version) => {
                    let has_history: bool = sqlx::query_scalar(
                        "SELECT EXISTS (SELECT 1 FROM dr_test_runs WHERE plan_id = $1)",
                    )
                    .bind(id)
                    .fetch_one(&mut *executor)
                    .await?;
                    if has_history {
                        Ok(DeleteOutcome::HasHistory)
                    } else {
                        // Row present, no history: the 0-row delete can only be a
                        // CAS miss (the row was modified between read and delete).
                        let _ = version;
                        Ok(DeleteOutcome::StaleVersion)
                    }
                }
            }
        }
        Err(e) => {
            // FK 23503: a run was inserted concurrently (after the NOT EXISTS
            // snapshot), so ON DELETE RESTRICT blocked the delete — history exists.
            if e.as_database_error()
                .and_then(|d| d.code())
                .map(|c| c == "23503")
                .unwrap_or(false)
            {
                Ok(DeleteOutcome::HasHistory)
            } else {
                Err(e)
            }
        }
    }
}
