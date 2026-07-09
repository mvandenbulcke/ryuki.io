//! Repository functions for `backup_coverage_reports`.
//!
//! All functions are pure over `&PgPool`; callers (handlers in `contracts.rs`)
//! are responsible for mapping `sqlx::Error` → 500 and `None` → 404.
//!
//! # Immutability
//! Coverage reports are immutable once generated — there is no `transition` fn.
//! `insert` persists the model and returns the DB-authoritative row; `get` and
//! `list_page`/`count` provide read access.

use chrono::{DateTime, Utc};
use ryuki_engine::models::{BackupCoverageReport, CoverageReportStatus};
use sqlx::PgPool;
use uuid::Uuid;

// ─── Column list ─────────────────────────────────────────────────────────────

/// SELECT column list. UUID → text so sqlx binds into String; JSONB → text
/// so we can `serde_json::from_str` it. The DB-managed `created_at` column is
/// not part of the model (`generation_time` is the model's timestamp), so it is
/// neither selected nor decoded.
pub const COLUMNS: &str = "id::text AS id, \
     site_scope::text AS site_scope, \
     environment_scope::text AS environment_scope, \
     generation_time, \
     total_assets, \
     covered_assets, \
     missing_backup, \
     missing_dr_replica, \
     stale_policy, \
     critical_gaps::text AS critical_gaps, \
     coverage_percentage, \
     status, \
     recommendations::text AS recommendations, \
     metadata::text AS metadata";

// ─── Row struct ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct BackupCoverageReportRow {
    pub id: String,
    /// Raw JSON text from JSONB::text cast, e.g. `["GBLON","DEFRA"]`.
    pub site_scope: String,
    pub environment_scope: String,
    /// DB timestamp; converted to RFC-3339 and used as model's `generation_time`.
    pub generation_time: DateTime<Utc>,
    /// Integer counts stored as i32 in Postgres; cast to u32 in into_model.
    pub total_assets: i32,
    pub covered_assets: i32,
    pub missing_backup: i32,
    pub missing_dr_replica: i32,
    pub stale_policy: i32,
    pub critical_gaps: String,
    pub coverage_percentage: f64,
    pub status: String,
    pub recommendations: String,
    pub metadata: String,
}

impl BackupCoverageReportRow {
    /// Convert a DB row into the engine model.
    ///
    /// JSONB-text and enum-name fields are deserialized via `serde_json`. A
    /// parse failure means the persisted row is corrupt; we surface it as a
    /// decode error (caller → 500) rather than silently substituting defaults.
    pub fn into_model(self) -> Result<BackupCoverageReport, sqlx::Error> {
        fn decode<T: serde::de::DeserializeOwned>(
            raw: &str,
            field: &str,
        ) -> Result<T, sqlx::Error> {
            serde_json::from_str(raw).map_err(|e| {
                sqlx::Error::Decode(
                    format!("backup_coverage_reports.{field}: corrupt persisted value: {e}").into(),
                )
            })
        }

        let site_scope: Vec<String> = decode(&self.site_scope, "site_scope")?;
        let environment_scope: Vec<String> = decode(&self.environment_scope, "environment_scope")?;
        let critical_gaps: Vec<String> = decode(&self.critical_gaps, "critical_gaps")?;
        let recommendations: Vec<String> = decode(&self.recommendations, "recommendations")?;
        let metadata: std::collections::HashMap<String, String> =
            decode(&self.metadata, "metadata")?;

        // Counts are non-negative in the model. A negative DB value is corrupt
        // data — surface it as a decode error rather than wrapping to a huge u32.
        fn to_u32(v: i32, field: &str) -> Result<u32, sqlx::Error> {
            u32::try_from(v).map_err(|_| {
                sqlx::Error::Decode(
                    format!("backup_coverage_reports.{field}: negative count {v}").into(),
                )
            })
        }

        // Enum variants are stored as their serde name (e.g. "Generated"); decode
        // via the engine's Deserialize impl. A DB CHECK constraint (migration 060)
        // keeps these in the legal set.
        let status: CoverageReportStatus = decode(&format!("\"{}\"", self.status), "status")?;

        Ok(BackupCoverageReport {
            id: self.id,
            site_scope,
            environment_scope,
            generation_time: self.generation_time.to_rfc3339(),
            total_assets: to_u32(self.total_assets, "total_assets")?,
            covered_assets: to_u32(self.covered_assets, "covered_assets")?,
            missing_backup: to_u32(self.missing_backup, "missing_backup")?,
            missing_dr_replica: to_u32(self.missing_dr_replica, "missing_dr_replica")?,
            stale_policy: to_u32(self.stale_policy, "stale_policy")?,
            critical_gaps,
            coverage_percentage: self.coverage_percentage,
            status,
            recommendations,
            metadata,
        })
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

/// Canonical serde variant name for a `CoverageReportStatus` value as stored
/// in the DB (e.g. `"Generated"`, `"Reviewing"`).
pub fn status_str(s: &CoverageReportStatus) -> &'static str {
    match s {
        CoverageReportStatus::Generated => "Generated",
        CoverageReportStatus::Reviewing => "Reviewing",
        CoverageReportStatus::ActionRequired => "ActionRequired",
        CoverageReportStatus::Accepted => "Accepted",
    }
}

// ─── Repository functions ─────────────────────────────────────────────────────

/// Insert a new coverage report and return the persisted row. The caller
/// supplies the model with an already-generated UUID string as `id`; we parse
/// it for the PK.
///
/// `created_at` is not bound here — the DB column default (NOW()) owns it.
/// We `RETURNING` the inserted row so the returned model carries the
/// DB-authoritative `generation_time` (stored as the DB column of the same
/// name) so the response matches a subsequent `get`.
pub async fn insert(
    pool: &PgPool,
    r: &BackupCoverageReport,
) -> Result<BackupCoverageReport, sqlx::Error> {
    let id = Uuid::parse_str(&r.id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let site_scope = serde_json::to_string(&r.site_scope).unwrap_or_else(|_| "[]".into());
    let environment_scope =
        serde_json::to_string(&r.environment_scope).unwrap_or_else(|_| "[]".into());
    let critical_gaps = serde_json::to_string(&r.critical_gaps).unwrap_or_else(|_| "[]".into());
    let recommendations = serde_json::to_string(&r.recommendations).unwrap_or_else(|_| "[]".into());
    let metadata = serde_json::to_string(&r.metadata).unwrap_or_else(|_| "{}".into());

    // generation_time is stored as a TIMESTAMPTZ; parse the RFC-3339 string from
    // the engine and bind it as a DateTime<Utc> so Postgres stores it correctly.
    let generation_time = r
        .generation_time
        .parse::<DateTime<Utc>>()
        .map_err(|e| sqlx::Error::Decode(format!("generation_time: {e}").into()))?;

    // Postgres INTEGER is i32; reject counts that would overflow rather than
    // wrapping to a negative value.
    fn to_i32(v: u32, field: &str) -> Result<i32, sqlx::Error> {
        i32::try_from(v).map_err(|_| {
            sqlx::Error::Decode(format!("backup_coverage_reports.{field}: {v} exceeds i32").into())
        })
    }
    let total_assets = to_i32(r.total_assets, "total_assets")?;
    let covered_assets = to_i32(r.covered_assets, "covered_assets")?;
    let missing_backup = to_i32(r.missing_backup, "missing_backup")?;
    let missing_dr_replica = to_i32(r.missing_dr_replica, "missing_dr_replica")?;
    let stale_policy = to_i32(r.stale_policy, "stale_policy")?;

    let row: BackupCoverageReportRow = sqlx::query_as(&format!(
        "INSERT INTO backup_coverage_reports \
         (id, site_scope, environment_scope, generation_time, total_assets, covered_assets, \
          missing_backup, missing_dr_replica, stale_policy, critical_gaps, coverage_percentage, \
          status, recommendations, metadata) \
         VALUES ($1, $2::jsonb, $3::jsonb, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12, \
                 $13::jsonb, $14::jsonb) \
         RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(&site_scope)
    .bind(&environment_scope)
    .bind(generation_time)
    .bind(total_assets)
    .bind(covered_assets)
    .bind(missing_backup)
    .bind(missing_dr_replica)
    .bind(stale_policy)
    .bind(&critical_gaps)
    .bind(r.coverage_percentage)
    .bind(status_str(&r.status))
    .bind(&recommendations)
    .bind(&metadata)
    .fetch_one(pool)
    .await?;

    row.into_model()
}

/// Fetch one coverage report by string id. A malformed (non-UUID) id is treated
/// as `Ok(None)` (callers map to 404) rather than an error.
pub async fn get(pool: &PgPool, id: &str) -> Result<Option<BackupCoverageReport>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<BackupCoverageReportRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM backup_coverage_reports WHERE id = $1"
    ))
    .bind(uid)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Build the per-axis TARGET-SET scope predicate (#2/#14) shared by
/// [`list_page`] and [`count`] so a page and its total can never drift apart.
///
/// A coverage report's `site_scope`/`environment_scope` are JSONB arrays (the
/// report's footprint), so this is the SQL push-down of the handler's old
/// in-memory `multi_scope_permits` retain: `None` = the principal is
/// unrestricted on that axis → no predicate; `Some(scopes)` = the report's
/// array on that axis must be NON-EMPTY (an empty footprint means "all" and
/// fails closed for a scoped caller) and contained in `scopes`
/// (`jsonb_array_length > 0 AND axis <@ scopes`). Containment compares entries
/// EXACTLY; the handler passes trimmed scope entries, so this only diverges
/// from the in-memory `r.trim()` comparison for a whitespace-padded PERSISTED
/// entry — impossible via the create path (entries are validated site codes)
/// and strictly narrower (hides, never leaks) if hand-seeded. Predicates are
/// built PER BRANCH — never a `($n IS NULL OR ...)` over the column (the
/// generic-plan seq-scan trap). Column names are compile-time literals; every
/// value is a bound parameter (injection-safe).
fn scope_preds(
    sites: Option<&[String]>,
    environments: Option<&[String]>,
) -> (String, Vec<String>) {
    let mut preds: Vec<String> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    if let Some(s) = sites {
        binds.push(serde_json::to_string(s).unwrap_or_else(|_| "[]".into()));
        preds.push(format!(
            "(jsonb_array_length(site_scope) > 0 AND site_scope <@ ${}::jsonb)",
            binds.len()
        ));
    }
    if let Some(e) = environments {
        binds.push(serde_json::to_string(e).unwrap_or_else(|_| "[]".into()));
        preds.push(format!(
            "(jsonb_array_length(environment_scope) > 0 AND environment_scope <@ ${}::jsonb)",
            binds.len()
        ));
    }
    let clause = if preds.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", preds.join(" AND "))
    };
    (clause, binds)
}

/// One `LIMIT`/`OFFSET` page of coverage reports (#14), generation time
/// descending, with the principal's multi-target scope pushed into SQL — the
/// paged replacement for the old fetch-all `list` + in-memory
/// `multi_scope_permits` retain. `ORDER BY generation_time DESC, id DESC` ends
/// in the unique PK, so equal timestamps still yield a stable page cut.
pub async fn list_page(
    pool: &PgPool,
    sites: Option<&[String]>,
    environments: Option<&[String]>,
    limit: i64,
    offset: i64,
) -> Result<Vec<BackupCoverageReport>, sqlx::Error> {
    let (where_clause, binds) = scope_preds(sites, environments);
    let sql = format!(
        "SELECT {COLUMNS} FROM backup_coverage_reports{where_clause} \
         ORDER BY generation_time DESC, id DESC LIMIT ${} OFFSET ${}",
        binds.len() + 1,
        binds.len() + 2
    );
    let mut q = sqlx::query_as::<_, BackupCoverageReportRow>(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    let rows = q.bind(limit).bind(offset).fetch_all(pool).await?;
    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Count coverage reports under the SAME scope predicate as [`list_page`] —
/// the pagination total (`X-Total-Count`).
pub async fn count(
    pool: &PgPool,
    sites: Option<&[String]>,
    environments: Option<&[String]>,
) -> Result<i64, sqlx::Error> {
    let (where_clause, binds) = scope_preds(sites, environments);
    let sql = format!("SELECT COUNT(*) FROM backup_coverage_reports{where_clause}");
    let mut q = sqlx::query_scalar::<_, i64>(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    q.fetch_one(pool).await
}
