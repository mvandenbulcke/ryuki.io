//! Repository functions for `dr_test_runs`.
//!
//! Full `DrTestRun` round-tripped through `run_json` JSONB column.
//! Scalar `completed` boolean kept in sync for queryability.
//! xmin CAS in `transition` guards all mutations.

use ryuki_engine::dr_testing::DrTestRun;
use sqlx::PgPool;

pub const COLUMNS: &str =
    "id, plan_id, completed, run_json::text AS run_json, xmin::text AS row_version";

#[derive(sqlx::FromRow)]
pub struct DrTestRunRow {
    pub id: String,
    #[allow(dead_code)]
    pub plan_id: String,
    #[allow(dead_code)]
    pub completed: bool,
    pub run_json: Option<String>,
    pub row_version: String,
}

impl DrTestRunRow {
    pub fn into_model(self) -> Result<DrTestRun, sqlx::Error> {
        let raw = self
            .run_json
            .ok_or_else(|| sqlx::Error::Decode("dr_test_runs.run_json: NULL".into()))?;
        let mut entity: DrTestRun = serde_json::from_str(&raw).map_err(|e| {
            sqlx::Error::Decode(
                format!("dr_test_runs.run_json: corrupt persisted value: {e}").into(),
            )
        })?;
        // DB id is authoritative on read
        entity.id = self.id;
        Ok(entity)
    }
}

pub async fn insert(
    executor: impl sqlx::PgExecutor<'_>,
    run: &DrTestRun,
) -> Result<(), sqlx::Error> {
    let run_json = serde_json::to_value(run)
        .map_err(|e| sqlx::Error::Decode(format!("dr_test_runs: serialize failed: {e}").into()))?;
    sqlx::query(
        "INSERT INTO dr_test_runs (id, plan_id, site, completed, run_json) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&run.id)
    .bind(&run.plan_id)
    .bind(&run.site)
    .bind(run.completed_at.is_some())
    .bind(run_json)
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn get(pool: &PgPool, id: &str) -> Result<Option<(DrTestRun, String)>, sqlx::Error> {
    let row: Option<DrTestRunRow> =
        sqlx::query_as(&format!("SELECT {COLUMNS} FROM dr_test_runs WHERE id = $1"))
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

pub async fn list_by_plan(pool: &PgPool, plan_id: &str) -> Result<Vec<DrTestRun>, sqlx::Error> {
    let rows: Vec<DrTestRunRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM dr_test_runs WHERE plan_id = $1 ORDER BY created_at DESC, id DESC"
    ))
    .bind(plan_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(|r| r.into_model()).collect()
}

#[allow(dead_code)]
pub async fn transition(
    executor: &mut sqlx::PgConnection,
    id: &str,
    expected_version: &str,
    updated: &DrTestRun,
) -> Result<bool, sqlx::Error> {
    let run_json = serde_json::to_value(updated)
        .map_err(|e| sqlx::Error::Decode(format!("dr_test_runs: serialize failed: {e}").into()))?;
    let res = sqlx::query(
        "UPDATE dr_test_runs SET \
         completed = $2, \
         run_json = $3, \
         updated_at = NOW() \
         WHERE id = $1 AND xmin = $4::xid",
    )
    .bind(id)
    .bind(updated.completed_at.is_some())
    .bind(run_json)
    .bind(expected_version)
    .execute(&mut *executor)
    .await?;
    if res.rows_affected() == 0 {
        return Ok(false);
    }
    Ok(true)
}
