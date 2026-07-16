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
use sqlx::{PgConnection, PgPool, Postgres, QueryBuilder};
use uuid::Uuid;

/// Canonical site codes are at most 32 ASCII octets. Migration 172 uses the
/// same bound for its new-write constraint and partial read indexes, so legacy
/// outliers never enter a bounded certificate page or an index tuple.
pub const MAX_CERTIFICATE_SITE_QUERY_BYTES: usize = 32;

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
/// The `INSERT ... SELECT` repeats the exact active `site_registry` relation at
/// the write boundary. The handler also holds that site `FOR SHARE`, preventing
/// concurrent deactivation until the audited transaction commits. `None`
/// means the site is not currently canonical and active.
///
/// Accepts any `sqlx::PgExecutor` — callers should pass `&mut *tx` so the
/// authority lock, insert, and audit remain atomic.
pub async fn insert(
    executor: impl sqlx::PgExecutor<'_>,
    r: &CertificateRecord,
) -> Result<Option<CertificateRecord>, sqlx::Error> {
    let id = Uuid::parse_str(&r.id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let valid_from: DateTime<Utc> = chrono::DateTime::parse_from_rfc3339(&r.valid_from)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let valid_to: DateTime<Utc> = chrono::DateTime::parse_from_rfc3339(&r.valid_to)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let row: Option<CertificateRow> = sqlx::query_as(&format!(
        "WITH inserted AS ( \
             INSERT INTO certificates \
             (id, common_name, subject, valid_from, valid_to, service_type, hostname, site, status) \
             SELECT $1, $2, $3, $4, $5, $6, $7, sr.unlocode, $9 \
             FROM site_registry AS sr \
             WHERE sr.unlocode = $8 AND sr.active = true \
             RETURNING * \
         ) \
         SELECT {COLUMNS} FROM inserted"
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
    .fetch_optional(executor)
    .await?;

    row.map(|row| row.into_model()).transpose()
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

/// Fully normalized, authorization-aware inventory keyset query. `sites = None`
/// means an unrestricted principal.  `Some` is bounded by the handler and is
/// evaluated as a fixed per-site top-N merge, so sparse multi-site scopes do not
/// scan a global index past an attacker-independent page budget.
pub struct CertificateListQuery {
    pub sites: Option<Vec<String>>,
    pub after: Option<(DateTime<Utc>, Uuid)>,
    pub limit: i64,
}

const RAW_COLUMNS: &str = "candidate.id, candidate.common_name, candidate.subject, \
    candidate.valid_from, candidate.valid_to, candidate.service_type, \
    candidate.hostname, candidate.site, candidate.status, candidate.created_at";

fn push_created_before<'args>(
    builder: &mut QueryBuilder<'args, Postgres>,
    prefix: &str,
    after: &'args Option<(DateTime<Utc>, Uuid)>,
) {
    if let Some((created_at, id)) = after.as_ref() {
        builder
            .push(" AND (")
            .push(prefix)
            .push("created_at, ")
            .push(prefix)
            .push("id) < (")
            .push_bind(created_at)
            .push(", ")
            .push_bind(id)
            .push(")");
    }
}

/// Fetch one bounded newest-first keyset page.  Unrestricted callers use the
/// global `(created_at,id)` index.  Scoped callers take at most `limit` rows
/// from each of at most 64 authorized sites through the matching site index,
/// then merge only that bounded candidate set into the global order.
pub async fn list_page(
    pool: &PgPool,
    query: &CertificateListQuery,
) -> Result<Vec<CertificateRecord>, sqlx::Error> {
    let mut builder = if let Some(sites) = query.sites.as_ref() {
        let mut builder = QueryBuilder::<Postgres>::new(
            "WITH site_candidates AS ( \
             SELECT candidate.* FROM ( \
                 SELECT DISTINCT site FROM unnest(",
        );
        builder
            .push_bind(sites.as_slice())
            .push(
                "::text[]) AS scoped(site) \
             ) AS authorized \
             CROSS JOIN LATERAL ( \
                 SELECT ",
            )
            .push(RAW_COLUMNS)
            .push(
                " FROM certificates AS candidate \
                 WHERE octet_length(candidate.site) BETWEEN 1 AND 32 \
                   AND candidate.site = authorized.site",
            );
        push_created_before(&mut builder, "candidate.", &query.after);
        builder
            .push(" ORDER BY candidate.created_at DESC, candidate.id DESC LIMIT ")
            .push_bind(query.limit)
            .push(
                ") AS candidate \
             ) SELECT id::text AS id, common_name, subject, valid_from, valid_to, \
                      service_type, hostname, site, status, created_at \
               FROM site_candidates \
               ORDER BY site_candidates.created_at DESC, \
                        site_candidates.id DESC LIMIT ",
            )
            .push_bind(query.limit);
        builder
    } else {
        let mut builder = QueryBuilder::<Postgres>::new(format!(
            "SELECT {COLUMNS} FROM certificates \
             WHERE octet_length(site) BETWEEN 1 AND 32"
        ));
        push_created_before(&mut builder, "certificates.", &query.after);
        builder
            .push(" ORDER BY certificates.created_at DESC, certificates.id DESC LIMIT ")
            .push_bind(query.limit);
        builder
    };

    let rows: Vec<CertificateRow> = builder.build_query_as().fetch_all(pool).await?;
    rows.into_iter().map(CertificateRow::into_model).collect()
}

/// Fetch a bounded, index-ordered expiry page. The optional tuple is the last
/// `(valid_to,id)` from the preceding page, so later pages remain keyset-bound
/// rather than paying attacker-selected OFFSET discard work.
pub async fn list_expiring_page(
    pool: &PgPool,
    site: Option<&str>,
    expires_before: &DateTime<Utc>,
    after: Option<(&DateTime<Utc>, &Uuid)>,
    limit: i64,
) -> Result<Vec<CertificateRecord>, sqlx::Error> {
    let mut builder = QueryBuilder::<Postgres>::new(format!(
        "SELECT {COLUMNS} FROM certificates \
         WHERE octet_length(site) BETWEEN 1 AND 32 AND "
    ));
    if let Some(site) = site {
        builder.push("site = ").push_bind(site).push(" AND ");
    }
    builder.push("valid_to <= ").push_bind(expires_before);
    if let Some((valid_to, id)) = after {
        builder
            .push(" AND (valid_to, id) > (")
            .push_bind(valid_to)
            .push(", ")
            .push_bind(id)
            .push(")");
    }
    builder
        .push(" ORDER BY valid_to ASC, certificates.id ASC LIMIT ")
        .push_bind(limit);

    let rows: Vec<CertificateRow> = builder.build_query_as().fetch_all(pool).await?;
    rows.into_iter().map(CertificateRow::into_model).collect()
}

/// Only a TERMINAL certificate (`Expired`|`Revoked`) may be DELETED — operational
/// cleanup of a record that no longer represents a usable certificate. An
/// `Active`/`Expiring` certificate is LIVE (still serving or imminently so); removing
/// its record at the `execute` tier would lose tracking of an in-use certificate (the
/// patch-wave delete lesson). SINGLE source of truth for the handler 409 gate AND the
/// repo defense-in-depth guard below. (A mistaken Active cert still has an audited path
/// to removal: revoke it → `Revoked` → then deletable.)
pub fn certificate_status_deletable(status: &CertificateStatus) -> bool {
    matches!(
        status,
        CertificateStatus::Expired | CertificateStatus::Revoked
    )
}

/// Outcome of a certificate delete attempt (status+site CAS + deletability guard).
#[derive(Debug, PartialEq, Eq)]
pub enum DeleteOutcome {
    /// The certificate row was deleted (certificates are a leaf table — no cascade).
    Deleted,
    /// No row with this id (already gone).
    NotFound,
    /// The row's status OR site moved since it was read (CAS miss) — caller reloads.
    StaleStatus,
    /// `expected` is not a deletable status — defense-in-depth if a caller bypassed
    /// the handler's `certificate_status_deletable` check.
    BlockedStatus,
}

/// Delete a certificate IFF it still matches `expected` status AND `expected_site`
/// (CAS) AND `expected` is a deletable (terminal) status. The `site` guard closes the
/// window where a concurrent `transition` (which rewrites `site`) moves the cert out of
/// the scope the handler authorized between the load and the delete (codex). No FK
/// references `certificates`, so there is no cascade. On 0 rows we re-read to
/// disambiguate `NotFound` vs `StaleStatus`.
pub async fn delete(
    conn: &mut PgConnection,
    id: &str,
    expected: &CertificateStatus,
    expected_site: &str,
) -> Result<DeleteOutcome, sqlx::Error> {
    if !certificate_status_deletable(expected) {
        return Ok(DeleteOutcome::BlockedStatus);
    }
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(DeleteOutcome::NotFound);
    };
    let res = sqlx::query("DELETE FROM certificates WHERE id = $1 AND status = $2 AND site = $3")
        .bind(uid)
        .bind(status_str(expected))
        .bind(expected_site)
        .execute(&mut *conn)
        .await?;
    if res.rows_affected() == 1 {
        return Ok(DeleteOutcome::Deleted);
    }
    // 0 rows: the row is gone, or its status/site moved since the read.
    let current: Option<String> =
        sqlx::query_scalar("SELECT status FROM certificates WHERE id = $1")
            .bind(uid)
            .fetch_optional(&mut *conn)
            .await?;
    match current {
        None => Ok(DeleteOutcome::NotFound),
        Some(_) => Ok(DeleteOutcome::StaleStatus),
    }
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
