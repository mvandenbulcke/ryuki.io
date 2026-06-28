//! Repository functions for `synthetic_health`.
//!
//! All functions are pure over `&PgPool`; callers (handlers in `contracts.rs`)
//! are responsible for mapping `sqlx::Error` → 500 and `None` → 404.
//!
//! # UUID discipline
//! Both `health_checks.id` and `check_results.id`/`check_id` are UUID columns.
//! SELECTs cast them to TEXT (`id::text AS id`, `check_id::text AS check_id`).
//! On writes, string ids are parsed via `Uuid::parse_str`; a malformed id is
//! treated as `Ok(None)` (caller → 404) rather than an error.
//!
//! # Integer coercion
//! `expected_status u16`, `interval_seconds u32`, and `latency_ms u64` map to
//! DB `INTEGER` (i32). Decoding uses `try_from` (negative/out-of-range → Decode
//! error); binding uses `i32::try_from` (error → Decode).
//!
//! # Timestamps
//! `executed_at TIMESTAMPTZ` is decoded as a `DateTime<Utc>` and converted to a
//! stable RFC-3339 string in `into_model` (the engine parses it back with
//! `parse_from_rfc3339`; Postgres's own `::text` rendering is NOT RFC-3339, so a
//! text cast would make the engine silently drop every persisted result). On
//! writes the RFC-3339 string from the model is bound with `::timestamptz`.

use chrono::{DateTime, Utc};
use ryuki_engine::synthetic_health::{CheckResult, CheckResultStatus, CheckType, HealthCheck};
use sqlx::PgPool;
use uuid::Uuid;

// ─── Column lists ─────────────────────────────────────────────────────────────

/// SELECT column list for `health_checks`. UUID cast to TEXT.
pub const HC_COLUMNS: &str = "id::text AS id, \
     name, \
     check_type, \
     endpoint, \
     expected_status, \
     expected_body_contains, \
     interval_seconds, \
     site, \
     enabled";

/// SELECT column list for `check_results`. UUIDs cast to TEXT; `executed_at`
/// stays a TIMESTAMPTZ and is decoded as `DateTime<Utc>` (then rendered RFC-3339
/// in `into_model`) — a `::text` cast would yield a non-RFC-3339 string.
pub const CR_COLUMNS: &str = "id::text AS id, \
     check_id::text AS check_id, \
     status, \
     latency_ms, \
     message, \
     executed_at";

// ─── Row structs ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct HealthCheckRow {
    pub id: String,
    pub name: String,
    pub check_type: String,
    pub endpoint: String,
    pub expected_status: i32,
    pub expected_body_contains: Option<String>,
    pub interval_seconds: i32,
    pub site: String,
    pub enabled: bool,
}

impl HealthCheckRow {
    /// Convert a DB row into the engine model.
    ///
    /// `check_type` is decoded strictly from its snake_case serde name (matching
    /// the DB CHECK constraint). A corrupt value → Decode error (caller → 500).
    /// Integer fields use `try_from` — a negative DB value → Decode error.
    pub fn into_model(self) -> Result<HealthCheck, sqlx::Error> {
        let check_type = decode_check_type(&self.check_type)?;

        let expected_status = u16::try_from(self.expected_status).map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "health_checks.expected_status: out-of-range value {}: {e}",
                    self.expected_status
                )
                .into(),
            )
        })?;

        let interval_seconds = u32::try_from(self.interval_seconds).map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "health_checks.interval_seconds: negative value {}: {e}",
                    self.interval_seconds
                )
                .into(),
            )
        })?;

        Ok(HealthCheck {
            id: self.id,
            name: self.name,
            check_type,
            endpoint: self.endpoint,
            expected_status,
            expected_body_contains: self.expected_body_contains,
            interval_seconds,
            site: self.site,
            enabled: self.enabled,
        })
    }
}

#[derive(sqlx::FromRow)]
pub struct CheckResultRow {
    pub id: String,
    pub check_id: String,
    pub status: String,
    pub latency_ms: i32,
    pub message: String,
    pub executed_at: DateTime<Utc>,
}

impl CheckResultRow {
    /// Convert a DB row into the engine model.
    ///
    /// `status` is decoded strictly from its snake_case serde name (matching the
    /// DB CHECK constraint). A corrupt value → Decode error. `latency_ms` uses
    /// `try_from` — a negative DB value → Decode error.
    pub fn into_model(self) -> Result<CheckResult, sqlx::Error> {
        let status = decode_result_status(&self.status)?;

        let latency_ms = u64::try_from(self.latency_ms).map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "check_results.latency_ms: negative value {}: {e}",
                    self.latency_ms
                )
                .into(),
            )
        })?;

        Ok(CheckResult {
            id: self.id,
            check_id: self.check_id,
            status,
            latency_ms,
            message: self.message,
            executed_at: self.executed_at.to_rfc3339(),
        })
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

/// Canonical snake_case serde variant name for `CheckType` as stored in the DB.
/// Matches the DB CHECK constraint values exactly.
#[allow(dead_code)]
pub fn check_type_str(t: &CheckType) -> &'static str {
    match t {
        CheckType::Http => "http",
        CheckType::Tcp => "tcp",
        CheckType::Dns => "dns",
        CheckType::Certificate => "certificate",
    }
}

/// Canonical snake_case serde variant name for `CheckResultStatus` as stored in DB.
/// Matches the DB CHECK constraint values exactly.
pub fn result_status_str(s: &CheckResultStatus) -> &'static str {
    match s {
        CheckResultStatus::Pass => "pass",
        CheckResultStatus::Fail => "fail",
    }
}

/// Decode a `check_type` string from the DB into the engine enum.
/// Uses serde's snake_case wire names (as stored by `check_type_str`).
fn decode_check_type(raw: &str) -> Result<CheckType, sqlx::Error> {
    serde_json::from_str(&format!("\"{}\"", raw)).map_err(|e| {
        sqlx::Error::Decode(
            format!("health_checks.check_type: corrupt persisted value '{raw}': {e}").into(),
        )
    })
}

/// Decode a `status` string from the DB into the engine enum.
/// Uses serde's snake_case wire names (as stored by `result_status_str`).
fn decode_result_status(raw: &str) -> Result<CheckResultStatus, sqlx::Error> {
    serde_json::from_str(&format!("\"{}\"", raw)).map_err(|e| {
        sqlx::Error::Decode(
            format!("check_results.status: corrupt persisted value '{raw}': {e}").into(),
        )
    })
}

// ─── health_checks repository functions ───────────────────────────────────────

/// Fetch one health check by string id. A malformed (non-UUID) id is treated as
/// `Ok(None)` (callers → 404) rather than an error.
pub async fn get_check(pool: &PgPool, id: &str) -> Result<Option<HealthCheck>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<HealthCheckRow> = sqlx::query_as(&format!(
        "SELECT {HC_COLUMNS} FROM health_checks WHERE id = $1"
    ))
    .bind(uid)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Return all health checks, optionally filtered by site. An empty `site`
/// string returns all rows. Results are ordered by `site, name`.
pub async fn list_checks(pool: &PgPool, site: &str) -> Result<Vec<HealthCheck>, sqlx::Error> {
    let rows: Vec<HealthCheckRow> = if site.is_empty() {
        sqlx::query_as(&format!(
            "SELECT {HC_COLUMNS} FROM health_checks ORDER BY site, name"
        ))
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {HC_COLUMNS} FROM health_checks WHERE site = $1 ORDER BY name"
        ))
        .bind(site)
        .fetch_all(pool)
        .await?
    };

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Return only enabled health checks for a given site. Used by handlers that
/// need to run all checks for a site.
pub async fn list_checks_for_site(
    pool: &PgPool,
    site: &str,
) -> Result<Vec<HealthCheck>, sqlx::Error> {
    let rows: Vec<HealthCheckRow> = sqlx::query_as(&format!(
        "SELECT {HC_COLUMNS} FROM health_checks WHERE site = $1 AND enabled = true ORDER BY name"
    ))
    .bind(site)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Return every ENABLED health check across all sites, for the platform-wide
/// background scheduler (`synthetic_health_run`). Unlike `list_checks_for_site`
/// this has no site filter — the scheduler runs as an internal platform principal,
/// not a scoped user. Executor-generic so the scheduler can run it INSIDE its tick
/// transaction (pass `&mut *conn`), keeping the run atomic with its savepoint.
pub async fn list_all_enabled_checks<'e, E>(executor: E) -> Result<Vec<HealthCheck>, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows: Vec<HealthCheckRow> = sqlx::query_as(&format!(
        "SELECT {HC_COLUMNS} FROM health_checks WHERE enabled = true ORDER BY site, name"
    ))
    .fetch_all(executor)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

// ─── check_results repository functions ───────────────────────────────────────

/// Insert a new check result and return the persisted row. The caller supplies
/// a model with an already-generated UUID string as `id`.
///
/// `check_id` must reference an existing `health_checks.id` (FK constraint).
/// `executed_at` is bound as `::timestamptz` from the RFC-3339 string in the
/// model. `latency_ms` is bound as `i32` after range-checking. Executor-generic so
/// it works with both a `&PgPool` (handlers) and a `&mut *tx` (the scheduler tick,
/// so a failed insert rolls back within that schedule's savepoint).
pub async fn insert_result<'e, E>(executor: E, r: &CheckResult) -> Result<CheckResult, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let id = Uuid::parse_str(&r.id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
    let check_id = Uuid::parse_str(&r.check_id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let latency_ms_i32 = i32::try_from(r.latency_ms).map_err(|e| {
        sqlx::Error::Decode(format!("check_results.latency_ms: value too large: {e}").into())
    })?;

    let row: CheckResultRow = sqlx::query_as(&format!(
        "INSERT INTO check_results \
         (id, check_id, status, latency_ms, message, executed_at) \
         VALUES ($1, $2, $3, $4, $5, $6::timestamptz) \
         RETURNING {CR_COLUMNS}"
    ))
    .bind(id)
    .bind(check_id)
    .bind(result_status_str(&r.status))
    .bind(latency_ms_i32)
    .bind(&r.message)
    .bind(&r.executed_at)
    .fetch_one(executor)
    .await?;

    row.into_model()
}

/// Fetch the most recent check result for a given check id. A malformed (non-UUID)
/// id is treated as `Ok(None)` (caller → 404). Returns `None` when no results
/// exist yet for the check.
pub async fn get_latest_result(
    pool: &PgPool,
    check_id: &str,
) -> Result<Option<CheckResult>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(check_id) else {
        return Ok(None);
    };

    let row: Option<CheckResultRow> = sqlx::query_as(&format!(
        "SELECT {CR_COLUMNS} FROM check_results \
         WHERE check_id = $1 \
         ORDER BY executed_at DESC \
         LIMIT 1"
    ))
    .bind(uid)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Fetch all check results for a given check id, ordered most-recent first.
/// A malformed (non-UUID) id returns an empty vec (caller treats as no results).
#[allow(dead_code)]
pub async fn list_results_for_check(
    pool: &PgPool,
    check_id: &str,
) -> Result<Vec<CheckResult>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(check_id) else {
        return Ok(vec![]);
    };

    let rows: Vec<CheckResultRow> = sqlx::query_as(&format!(
        "SELECT {CR_COLUMNS} FROM check_results \
         WHERE check_id = $1 \
         ORDER BY executed_at DESC"
    ))
    .bind(uid)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Fetch the most recent result per enabled check for a given site.
/// Used by the dashboard and outage handlers to build aggregated views.
///
/// Implemented as a correlated subquery so no CTE or window function is needed,
/// and no extra index beyond the existing FK is required.
pub async fn get_latest_results_for_site(
    pool: &PgPool,
    site: &str,
) -> Result<Vec<CheckResult>, sqlx::Error> {
    let rows: Vec<CheckResultRow> = sqlx::query_as(&format!(
        "SELECT {CR_COLUMNS} FROM check_results cr \
         WHERE cr.check_id IN (\
             SELECT id FROM health_checks WHERE site = $1 AND enabled = true\
         ) \
         AND cr.executed_at = (\
             SELECT MAX(cr2.executed_at) FROM check_results cr2 WHERE cr2.check_id = cr.check_id\
         ) \
         ORDER BY cr.check_id"
    ))
    .bind(site)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Fetch the FULL result history for every enabled check at `site`, ordered by
/// check then time ascending. The outage report needs the whole history to
/// compute each check's CURRENT consecutive-failure streak — a latest-result-only
/// view would miss an outage that began several minutes ago (its first failure
/// is older than the latest sample).
pub async fn list_results_for_site(
    pool: &PgPool,
    site: &str,
) -> Result<Vec<CheckResult>, sqlx::Error> {
    let rows: Vec<CheckResultRow> = sqlx::query_as(&format!(
        "SELECT {CR_COLUMNS} FROM check_results cr \
         WHERE cr.check_id IN (\
             SELECT id FROM health_checks WHERE site = $1 AND enabled = true\
         ) \
         ORDER BY cr.check_id, cr.executed_at"
    ))
    .bind(site)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}
