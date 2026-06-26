//! Repository functions for `incident_contexts`.
//! Full entity round-tripped through `incident_json` JSONB column.

use ryuki_engine::incident_context::IncidentContext;
use sqlx::PgPool;

pub const COLUMNS: &str =
    "incident_id, status, incident_json::text AS incident_json, xmin::text AS row_version";

#[derive(sqlx::FromRow)]
pub struct IncidentContextRow {
    pub incident_id: String,
    pub status: String,
    pub incident_json: Option<String>,
    pub row_version: String,
}

impl IncidentContextRow {
    pub fn into_model(self) -> Result<IncidentContext, sqlx::Error> {
        let raw = self
            .incident_json
            .ok_or_else(|| sqlx::Error::Decode("incident_contexts.incident_json: NULL".into()))?;
        let mut entity: IncidentContext = serde_json::from_str(&raw).map_err(|e| {
            sqlx::Error::Decode(
                format!("incident_contexts.incident_json: corrupt value: {e}").into(),
            )
        })?;
        // DB columns are authoritative on read
        entity.status = self.status;
        entity.incident_id = self.incident_id;
        Ok(entity)
    }
}

/// Accepts any `sqlx::PgExecutor` — pass `pool` for a standalone call, or
/// `&mut *tx` to share a transaction with an audit write.
pub async fn insert(
    executor: impl sqlx::PgExecutor<'_>,
    ctx: &IncidentContext,
) -> Result<(), sqlx::Error> {
    let incident_json = serde_json::to_value(ctx).map_err(|e| {
        sqlx::Error::Decode(format!("incident_contexts: serialize failed: {e}").into())
    })?;
    sqlx::query(
        "INSERT INTO incident_contexts \
         (incident_id, title, severity, status, incident_json) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&ctx.incident_id)
    .bind(&ctx.title)
    .bind(&ctx.severity)
    .bind(&ctx.status)
    .bind(incident_json)
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn get(
    pool: &PgPool,
    id: &str,
) -> Result<Option<(IncidentContext, String)>, sqlx::Error> {
    let row: Option<IncidentContextRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM incident_contexts WHERE incident_id = $1"
    ))
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

#[allow(dead_code)]
pub async fn list(pool: &PgPool) -> Result<Vec<IncidentContext>, sqlx::Error> {
    let rows: Vec<IncidentContextRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM incident_contexts ORDER BY created_at DESC, incident_id DESC"
    ))
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(|r| r.into_model()).collect()
}

pub async fn list_active(pool: &PgPool) -> Result<Vec<IncidentContext>, sqlx::Error> {
    let rows: Vec<IncidentContextRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM incident_contexts WHERE status = 'active' ORDER BY created_at DESC, incident_id DESC"
    ))
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(|r| r.into_model()).collect()
}

pub async fn transition(
    conn: &mut sqlx::PgConnection,
    id: &str,
    expected_version: &str,
    updated: &IncidentContext,
) -> Result<bool, sqlx::Error> {
    let incident_json = serde_json::to_value(updated).map_err(|e| {
        sqlx::Error::Decode(format!("incident_contexts: serialize failed: {e}").into())
    })?;
    let res = sqlx::query(
        "UPDATE incident_contexts SET \
         status = $2, \
         incident_json = $3, \
         updated_at = NOW() \
         WHERE incident_id = $1 AND xmin = $4::xid",
    )
    .bind(id)
    .bind(&updated.status)
    .bind(incident_json)
    .bind(expected_version)
    .execute(conn)
    .await?;
    if res.rows_affected() == 0 {
        return Ok(false);
    }
    Ok(true)
}
