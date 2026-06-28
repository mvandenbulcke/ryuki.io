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

pub async fn list_by_site(pool: &PgPool, site: &str) -> Result<Vec<DrPlan>, sqlx::Error> {
    let rows: Vec<DrPlanRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM dr_plans WHERE site = $1 ORDER BY created_at DESC, id DESC"
    ))
    .bind(site)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(|r| r.into_model()).collect()
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
