//! Repository functions for `incident_contexts`.
//! Full entity round-tripped through `incident_json` JSONB column.

use ryuki_engine::incident_context::IncidentContext;
use sqlx::{PgConnection, PgPool};

pub const COLUMNS: &str = "incident.incident_id, incident.site, incident.status, \
     incident.incident_json::text AS incident_json, incident.xmin::text AS row_version";

#[derive(sqlx::FromRow)]
pub struct IncidentContextRow {
    pub incident_id: String,
    pub site: String,
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
        // Dedicated DB columns are authoritative on read. Embedded JSON from a
        // pre-binding record is never allowed to select the authorization site.
        entity.status = self.status;
        entity.incident_id = self.incident_id;
        entity.site = self.site.clone();
        for ci in &mut entity.affected_ci {
            ci.site = self.site.clone();
        }
        Ok(entity)
    }
}

/// Trusted incident input resolved from the durable CMDB and canonical active
/// site registry. Callers must require one row per requested unique CI and one
/// shared site before creating or extending an incident.
#[derive(Debug, sqlx::FromRow)]
pub struct IncidentCiBinding {
    pub ci_name: String,
    pub ci_type: String,
    pub site: String,
}

/// Resolve and lock CMDB rows for incident assembly/add-CI. The join requires
/// the CMDB's site value to map exactly to an active canonical registry key;
/// missing, inactive, non-canonical, or unknown relations are omitted so the
/// caller can fail closed without trusting request fields.
pub async fn resolve_ci_bindings(
    conn: &mut PgConnection,
    ci_names: &[String],
) -> Result<Vec<IncidentCiBinding>, sqlx::Error> {
    sqlx::query_as(
        "SELECT ci.ci_name, ci.ci_type, sr.unlocode AS site \
         FROM configuration_items ci \
         JOIN site_registry sr \
           ON sr.unlocode = ci.site AND sr.active = true \
         WHERE ci.ci_name = ANY($1::text[]) \
         ORDER BY ci.ci_name \
         FOR SHARE OF ci, sr",
    )
    .bind(ci_names)
    .fetch_all(conn)
    .await
}

/// Accepts any `sqlx::PgExecutor` — pass `pool` for a standalone call, or
/// `&mut *tx` to share a transaction with an audit write. Migration 167's
/// trigger independently locks and validates the exact active site/CMDB
/// provenance so standalone and rolling-deployment writers cannot bypass it.
pub async fn insert(
    executor: impl sqlx::PgExecutor<'_>,
    ctx: &IncidentContext,
) -> Result<(), sqlx::Error> {
    let incident_json = serde_json::to_value(ctx).map_err(|e| {
        sqlx::Error::Decode(format!("incident_contexts: serialize failed: {e}").into())
    })?;
    sqlx::query(
        "INSERT INTO incident_contexts \
         (incident_id, site, title, severity, status, incident_json) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&ctx.incident_id)
    .bind(&ctx.site)
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
        "SELECT {COLUMNS} FROM incident_contexts incident \
         JOIN site_registry registry \
           ON registry.unlocode = incident.site AND registry.active = true \
         WHERE incident.incident_id = $1"
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

/// Lock one incident and its exact active site binding for a lifecycle change.
/// The site-registry share lock prevents deactivation until the caller commits,
/// while the incident update lock keeps the model/version pair coherent.
pub async fn get_for_update(
    conn: &mut PgConnection,
    id: &str,
) -> Result<Option<(IncidentContext, String)>, sqlx::Error> {
    let row: Option<IncidentContextRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM incident_contexts incident \
         JOIN site_registry registry \
           ON registry.unlocode = incident.site AND registry.active = true \
         WHERE incident.incident_id = $1 \
         FOR UPDATE OF incident FOR SHARE OF registry"
    ))
    .bind(id)
    .fetch_optional(conn)
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
        "SELECT {COLUMNS} FROM incident_contexts incident \
         JOIN site_registry registry \
           ON registry.unlocode = incident.site AND registry.active = true \
         ORDER BY incident.created_at DESC, incident.incident_id DESC"
    ))
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Return active incident contexts, newest first, capped at `limit` rows. The
/// `limit` is a defense-in-depth bound (callers pass the shared `MAX_LIST_ROWS`)
/// so a sustained-incident burst can never return an unbounded result set —
/// mirroring the other capped list reads.
pub async fn list_active(pool: &PgPool, limit: i64) -> Result<Vec<IncidentContext>, sqlx::Error> {
    let rows: Vec<IncidentContextRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM incident_contexts incident \
         JOIN site_registry registry \
           ON registry.unlocode = incident.site AND registry.active = true \
         WHERE incident.status = 'active' \
         ORDER BY incident.created_at DESC, incident.incident_id DESC LIMIT $1"
    ))
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Scoped active-incident list with the site predicate applied before LIMIT,
/// preventing both cross-site disclosure and a short-page side channel.
pub async fn list_active_for_sites(
    pool: &PgPool,
    sites: &[String],
    limit: i64,
) -> Result<Vec<IncidentContext>, sqlx::Error> {
    let rows: Vec<IncidentContextRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM incident_contexts incident \
         JOIN site_registry registry \
           ON registry.unlocode = incident.site AND registry.active = true \
         WHERE incident.status = 'active' \
           AND incident.site = ANY($1::text[]) \
         ORDER BY incident.created_at DESC, incident.incident_id DESC LIMIT $2"
    ))
    .bind(sites)
    .bind(limit)
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
        "WITH active_site AS MATERIALIZED ( \
             SELECT registry.unlocode \
             FROM site_registry registry \
             WHERE registry.unlocode = $5 AND registry.active = true \
             FOR SHARE \
         ) \
         UPDATE incident_contexts AS incident SET \
             status = $2, \
             incident_json = $3, \
             updated_at = NOW() \
         FROM active_site \
         WHERE incident.incident_id = $1 \
           AND incident.xmin = $4::xid \
           AND incident.site = $5 \
           AND incident.site = active_site.unlocode",
    )
    .bind(id)
    .bind(&updated.status)
    .bind(incident_json)
    .bind(expected_version)
    .bind(&updated.site)
    .execute(conn)
    .await?;
    if res.rows_affected() == 0 {
        return Ok(false);
    }
    Ok(true)
}
