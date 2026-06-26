//! Repository functions for `certificates`.
//!
//! All functions are pure over `&PgPool`; callers (handlers in `contracts.rs`)
//! are responsible for mapping `sqlx::Error` → 500 and `None` → 404.
//!
//! # Audit parameter
//! `transition` accepts an `_audit_action: Option<&str>` parameter for
//! signature parity with the snapshots template, but certificates do not have
//! a dedicated audit table — the parameter is intentionally unused.

use chrono::{DateTime, Utc};
use ryuki_engine::certificate_lifecycle::{CertificateRecord, CertificateStatus};
use sqlx::PgPool;
use uuid::Uuid;

// ─── Column list ─────────────────────────────────────────────────────────────

/// SELECT column list. UUID → text so sqlx binds into String. `valid_from`,
/// `valid_to`, and `created_at` are `DateTime<Utc>` in the row and converted
/// to RFC-3339 strings in `into_model`. `subject` is nullable in the DB.
pub const COLUMNS: &str = "id::text AS id, \
     common_name, \
     subject, \
     valid_from, \
     valid_to, \
     service_type, \
     hostname, \
     site, \
     status, \
     created_at";

// ─── Row struct ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct CertificateRow {
    pub id: String,
    pub common_name: String,
    /// Nullable in the DB; `into_model` coalesces to empty string via
    /// `unwrap_or_default` so `CertificateRecord.subject` stays a `String`.
    pub subject: Option<String>,
    pub valid_from: DateTime<Utc>,
    pub valid_to: DateTime<Utc>,
    pub service_type: String,
    pub hostname: String,
    pub site: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

impl CertificateRow {
    /// Convert a DB row into the engine model.
    ///
    /// The status enum is stored as its serde PascalCase name and decoded via
    /// `serde_json`. A parse failure means the persisted row is corrupt; we
    /// surface it as a decode error (caller → 500) rather than substituting a
    /// default — a subsequent `transition` would otherwise CAS against the wrong
    /// status string. A DB CHECK constraint (migration 061) keeps status in the
    /// legal set.
    pub fn into_model(self) -> Result<CertificateRecord, sqlx::Error> {
        fn decode<T: serde::de::DeserializeOwned>(
            raw: &str,
            field: &str,
        ) -> Result<T, sqlx::Error> {
            serde_json::from_str(raw).map_err(|e| {
                sqlx::Error::Decode(
                    format!("certificates.{field}: corrupt persisted value: {e}").into(),
                )
            })
        }

        let status: CertificateStatus = decode(&format!("\"{}\"", self.status), "status")?;

        Ok(CertificateRecord {
            id: self.id,
            common_name: self.common_name,
            subject: self.subject.unwrap_or_default(),
            valid_from: self.valid_from.to_rfc3339(),
            valid_to: self.valid_to.to_rfc3339(),
            service_type: self.service_type,
            hostname: self.hostname,
            site: self.site,
            status,
            created_at: self.created_at.to_rfc3339(),
        })
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

/// Canonical serde variant name for a `CertificateStatus` value as stored in
/// the DB (e.g. `"Active"`, `"Revoked"`). `pub` so transition handlers can
/// supply the `expected_status` argument to `transition` without duplicating
/// this table.
pub fn status_str(s: &CertificateStatus) -> &'static str {
    match s {
        CertificateStatus::Active => "Active",
        CertificateStatus::Expiring => "Expiring",
        CertificateStatus::Expired => "Expired",
        CertificateStatus::Revoked => "Revoked",
    }
}

// ─── Repository functions ─────────────────────────────────────────────────────

/// Insert a new certificate and return the persisted row. The caller supplies
/// the model with an already-generated UUID string as `id`.
///
/// `valid_from` and `valid_to` are real certificate validity dates set by the
/// engine — they are bound explicitly (unlike `created_at`, which the DB
/// defaults to NOW()'). We `RETURNING` the inserted row so the returned model
/// carries the DB-authoritative `created_at` (the response then matches a
/// subsequent `get`).
///
/// Accepts any `sqlx::PgExecutor` — pass `pool` for a standalone call, or
/// `&mut *tx` to share a transaction with an audit write.
pub async fn insert(
    executor: impl sqlx::PgExecutor<'_>,
    r: &CertificateRecord,
) -> Result<CertificateRecord, sqlx::Error> {
    let id = Uuid::parse_str(&r.id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let valid_from: DateTime<Utc> = chrono::DateTime::parse_from_rfc3339(&r.valid_from)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let valid_to: DateTime<Utc> = chrono::DateTime::parse_from_rfc3339(&r.valid_to)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let row: CertificateRow = sqlx::query_as(&format!(
        "INSERT INTO certificates \
         (id, common_name, subject, valid_from, valid_to, service_type, hostname, site, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(&r.common_name)
    .bind(if r.subject.is_empty() {
        None
    } else {
        Some(&r.subject)
    })
    .bind(valid_from)
    .bind(valid_to)
    .bind(&r.service_type)
    .bind(&r.hostname)
    .bind(&r.site)
    .bind(status_str(&r.status))
    .fetch_one(executor)
    .await?;

    row.into_model()
}

/// Fetch one certificate by string id. A malformed (non-UUID) id is treated as
/// `Ok(None)` (callers map to 404) rather than an error — keeping every
/// handler's not-found behaviour uniform. `Err` is reserved for genuine DB
/// failures (callers map to 500).
pub async fn get(pool: &PgPool, id: &str) -> Result<Option<CertificateRecord>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<CertificateRow> =
        sqlx::query_as(&format!("SELECT {COLUMNS} FROM certificates WHERE id = $1"))
            .bind(uid)
            .fetch_optional(pool)
            .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Return all certificates ordered by creation time descending.
pub async fn list(pool: &PgPool) -> Result<Vec<CertificateRecord>, sqlx::Error> {
    let rows: Vec<CertificateRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM certificates ORDER BY created_at DESC, id DESC"
    ))
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Atomically transition a certificate to its new state IFF the DB row still
/// matches BOTH the `expected_status` AND the `expected_valid_to` it was read
/// with (optimistic lock). Returns `Ok(None)` when the row is absent or was
/// concurrently modified (caller → 409), or `Ok(Some(persisted))` on success.
///
/// Guarding on `valid_to` (not just `status`) is required because `renew` is a
/// same-status transition (Active → Active): a status-only CAS would let two
/// concurrent renews both succeed (lost update). `renew` always advances
/// `valid_to`, so the prior `valid_to` is the version token; `revoke` changes
/// `status`, so the status guard covers it. The table has no `updated_at`.
///
/// `_audit_action` is accepted for signature parity with the snapshots template
/// but is intentionally unused — certificates have no audit table.
///
/// Accepts any `sqlx::PgExecutor` — pass `pool` for a standalone call, or
/// `&mut *tx` to share a transaction with an audit write.
pub async fn transition(
    executor: impl sqlx::PgExecutor<'_>,
    expected_status: &str,
    expected_valid_to: &str,
    r: &CertificateRecord,
    _audit_action: Option<&str>,
) -> Result<Option<CertificateRecord>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(&r.id) else {
        return Ok(None);
    };

    let valid_from: DateTime<Utc> = chrono::DateTime::parse_from_rfc3339(&r.valid_from)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let valid_to: DateTime<Utc> = chrono::DateTime::parse_from_rfc3339(&r.valid_to)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    // The optimistic-lock token: the valid_to the caller read before mutating.
    let expected_valid_to: DateTime<Utc> = chrono::DateTime::parse_from_rfc3339(expected_valid_to)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let row: Option<CertificateRow> = sqlx::query_as(&format!(
        "UPDATE certificates SET \
         common_name = $2, \
         subject = $3, \
         valid_from = $4, \
         valid_to = $5, \
         service_type = $6, \
         hostname = $7, \
         site = $8, \
         status = $9 \
         WHERE id = $1 AND status = $10 AND valid_to = $11 \
         RETURNING {COLUMNS}"
    ))
    .bind(uid)
    .bind(&r.common_name)
    .bind(if r.subject.is_empty() {
        None
    } else {
        Some(&r.subject)
    })
    .bind(valid_from)
    .bind(valid_to)
    .bind(&r.service_type)
    .bind(&r.hostname)
    .bind(&r.site)
    .bind(status_str(&r.status))
    .bind(expected_status)
    .bind(expected_valid_to)
    .fetch_optional(executor)
    .await?;

    row.map(|row| row.into_model()).transpose()
}
