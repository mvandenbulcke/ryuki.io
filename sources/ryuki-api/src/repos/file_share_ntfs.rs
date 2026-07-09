//! Repository functions for `file_shares` and `ntfs_permissions`.
//!
//! All functions are pure over `&PgPool`; callers (handlers in `contracts.rs`)
//! are responsible for mapping `sqlx::Error` → 500 and `None` → 404.
//!
//! # UUID discipline
//! Both tables use UUID primary keys. In SELECT, `id::text AS id` (and
//! `file_share_id::text`) so sqlx decodes into `String`. On bind, `Uuid::parse_str`
//! with malformed-id guard (malformed → `Ok(None)`).
//!
//! # TIMESTAMPTZ ↔ String
//! The engine models carry timestamps as RFC-3339 strings. We decode them from
//! the DB as `DateTime<Utc>` and convert via `.to_rfc3339()`. On insert/update we
//! parse the RFC-3339 string back to `DateTime<Utc>` and bind it directly (sqlx
//! knows how to write a `DateTime<Utc>` into a TIMESTAMPTZ column).
//!
//! # NUMERIC(12,2) ↔ f64
//! `size_gb` is stored as NUMERIC. We cast `size_gb::float8` in SELECT so sqlx
//! decodes it into `f64`. On insert we bind the `f64` directly and cast with
//! `$N::numeric` in the query.
//!
//! # Enum encoding
//! `ShareStatus` and `PermissionType` are stored as PascalCase serde variant names
//! (e.g. `"Compliant"`, `"FullControl"`). A parse failure means the persisted row
//! is corrupt; we surface a decode error (caller → 500) rather than defaulting.

use chrono::{DateTime, Utc};
use ryuki_engine::file_share_ntfs::{FileShare, NTFSFolder, PermissionType, ShareStatus};
use sqlx::PgPool;
use uuid::Uuid;

// ─── Column lists ─────────────────────────────────────────────────────────────

/// SELECT column list for `file_shares`.
/// UUID → text; NUMERIC → float8; TIMESTAMPTZ decoded as `DateTime<Utc>`.
pub const SHARE_COLUMNS: &str = "id::text AS id, \
     unc_path, \
     server_name, \
     site, \
     size_gb::float8 AS size_gb, \
     owner, \
     last_recertification, \
     recertification_due, \
     status";

/// SELECT column list for `ntfs_permissions`.
/// UUID and FK UUID → text; TIMESTAMPTZ decoded as `DateTime<Utc>`.
pub const PERM_COLUMNS: &str = "id::text AS id, \
     file_share_id::text AS file_share_id, \
     folder_path, \
     permission_type, \
     ad_group, \
     principal, \
     inherited, \
     last_reviewed";

// ─── Row structs ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct FileShareRow {
    pub id: String,
    pub unc_path: String,
    pub server_name: String,
    pub site: String,
    pub size_gb: f64,
    pub owner: String,
    pub last_recertification: DateTime<Utc>,
    pub recertification_due: DateTime<Utc>,
    pub status: String,
}

impl FileShareRow {
    /// Convert a DB row into the engine model.
    ///
    /// `status` is stored as its serde PascalCase name and decoded via
    /// `serde_json`. A parse failure means the persisted row is corrupt; we
    /// surface it as a decode error (caller → 500) rather than defaulting.
    pub fn into_model(self) -> Result<FileShare, sqlx::Error> {
        let status: ShareStatus =
            serde_json::from_str(&format!("\"{}\"", self.status)).map_err(|e| {
                sqlx::Error::Decode(
                    format!("file_shares.status: corrupt persisted value: {e}").into(),
                )
            })?;

        Ok(FileShare {
            id: self.id,
            unc_path: self.unc_path,
            server_name: self.server_name,
            site: self.site,
            size_gb: self.size_gb,
            owner: self.owner,
            last_recertification: self.last_recertification.to_rfc3339(),
            recertification_due: self.recertification_due.to_rfc3339(),
            status,
        })
    }
}

#[derive(sqlx::FromRow)]
pub struct NTFSFolderRow {
    pub id: String,
    pub file_share_id: String,
    pub folder_path: String,
    pub permission_type: String,
    pub ad_group: String,
    pub principal: String,
    pub inherited: bool,
    pub last_reviewed: DateTime<Utc>,
}

impl NTFSFolderRow {
    /// Convert a DB row into the engine model.
    ///
    /// `permission_type` is decoded via `serde_json`. Corrupt value → decode error.
    pub fn into_model(self) -> Result<NTFSFolder, sqlx::Error> {
        let permission_type: PermissionType =
            serde_json::from_str(&format!("\"{}\"", self.permission_type)).map_err(|e| {
                sqlx::Error::Decode(
                    format!("ntfs_permissions.permission_type: corrupt persisted value: {e}")
                        .into(),
                )
            })?;

        Ok(NTFSFolder {
            id: self.id,
            file_share_id: self.file_share_id,
            folder_path: self.folder_path,
            permission_type,
            ad_group: self.ad_group,
            principal: self.principal,
            inherited: self.inherited,
            last_reviewed: self.last_reviewed.to_rfc3339(),
        })
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

/// Canonical serde variant name for a `ShareStatus` as stored in the DB.
pub fn share_status_str(s: &ShareStatus) -> &'static str {
    match s {
        ShareStatus::Compliant => "Compliant",
        ShareStatus::Overdue => "Overdue",
        ShareStatus::NeedsRecertification => "NeedsRecertification",
    }
}

/// Canonical serde variant name for a `PermissionType` as stored in the DB.
#[allow(dead_code)]
pub fn permission_type_str(p: &PermissionType) -> &'static str {
    match p {
        PermissionType::Read => "Read",
        PermissionType::Write => "Write",
        PermissionType::Modify => "Modify",
        PermissionType::FullControl => "FullControl",
    }
}

// ─── Repository functions — file_shares ──────────────────────────────────────

/// Fetch one file share by string id. A malformed (non-UUID) id is treated as
/// `Ok(None)` (callers map to 404) rather than an error.
pub async fn get_share(pool: &PgPool, id: &str) -> Result<Option<FileShare>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<FileShareRow> = sqlx::query_as(&format!(
        "SELECT {SHARE_COLUMNS} FROM file_shares WHERE id = $1"
    ))
    .bind(uid)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Return all file shares, optionally filtered by site. An empty `site` returns
/// all rows. Results are ordered by `site, unc_path` for stable output.
pub async fn list_shares(
    pool: &PgPool,
    site: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<FileShare>, sqlx::Error> {
    // `unc_path` is NOT unique (the same path can be seeded per site), so `id`
    // (the PK) is appended as the tie-breaker — without it, LIMIT/OFFSET pages
    // could overlap or skip rows sharing a `unc_path` (#14).
    let rows: Vec<FileShareRow> = if site.is_empty() {
        sqlx::query_as(&format!(
            "SELECT {SHARE_COLUMNS} FROM file_shares ORDER BY site, unc_path, id LIMIT $1 OFFSET $2"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {SHARE_COLUMNS} FROM file_shares \
             WHERE site = $1 ORDER BY unc_path, id LIMIT $2 OFFSET $3"
        ))
        .bind(site)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    };

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Count file shares (optionally site-filtered) — the pagination total for
/// [`list_shares`], using the SAME `WHERE` so the count matches the paged set.
pub async fn count_shares(pool: &PgPool, site: &str) -> Result<i64, sqlx::Error> {
    if site.is_empty() {
        sqlx::query_scalar("SELECT COUNT(*) FROM file_shares")
            .fetch_one(pool)
            .await
    } else {
        sqlx::query_scalar("SELECT COUNT(*) FROM file_shares WHERE site = $1")
            .bind(site)
            .fetch_one(pool)
            .await
    }
}

/// Return all file shares whose `recertification_due` is at or before `now`,
/// optionally filtered by site.
pub async fn list_recertification_due(
    pool: &PgPool,
    site: &str,
    now: DateTime<Utc>,
) -> Result<Vec<FileShare>, sqlx::Error> {
    let rows: Vec<FileShareRow> = if site.is_empty() {
        sqlx::query_as(&format!(
            "SELECT {SHARE_COLUMNS} FROM file_shares \
             WHERE recertification_due <= $1 ORDER BY recertification_due"
        ))
        .bind(now)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {SHARE_COLUMNS} FROM file_shares \
             WHERE site = $1 AND recertification_due <= $2 ORDER BY recertification_due"
        ))
        .bind(site)
        .bind(now)
        .fetch_all(pool)
        .await?
    };

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Return all file shares whose `last_recertification` is older than `threshold`,
/// optionally filtered by site.
pub async fn list_stale_owners(
    pool: &PgPool,
    site: &str,
    threshold: DateTime<Utc>,
) -> Result<Vec<FileShare>, sqlx::Error> {
    let rows: Vec<FileShareRow> = if site.is_empty() {
        sqlx::query_as(&format!(
            "SELECT {SHARE_COLUMNS} FROM file_shares \
             WHERE last_recertification < $1 ORDER BY last_recertification"
        ))
        .bind(threshold)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {SHARE_COLUMNS} FROM file_shares \
             WHERE site = $1 AND last_recertification < $2 ORDER BY last_recertification"
        ))
        .bind(site)
        .bind(threshold)
        .fetch_all(pool)
        .await?
    };

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Insert a new file share and return the persisted row.
/// The caller supplies a model with an already-generated UUID string as `id`.
#[allow(dead_code)]
pub async fn insert_share(pool: &PgPool, r: &FileShare) -> Result<FileShare, sqlx::Error> {
    let id = Uuid::parse_str(&r.id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let last_recertification: DateTime<Utc> =
        chrono::DateTime::parse_from_rfc3339(&r.last_recertification)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let recertification_due: DateTime<Utc> =
        chrono::DateTime::parse_from_rfc3339(&r.recertification_due)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let row: FileShareRow = sqlx::query_as(&format!(
        "INSERT INTO file_shares \
         (id, unc_path, server_name, site, size_gb, owner, last_recertification, recertification_due, status) \
         VALUES ($1, $2, $3, $4, $5::numeric, $6, $7, $8, $9) \
         RETURNING {SHARE_COLUMNS}"
    ))
    .bind(id)
    .bind(&r.unc_path)
    .bind(&r.server_name)
    .bind(&r.site)
    .bind(r.size_gb)
    .bind(&r.owner)
    .bind(last_recertification)
    .bind(recertification_due)
    .bind(share_status_str(&r.status))
    .fetch_one(pool)
    .await?;

    row.into_model()
}

/// Persist a recertified share. The new `last_recertification`,
/// `recertification_due`, and `status` are computed by the pure engine
/// (`file_share_ntfs::recertify_share`) and written here, but only if the row's
/// current `recertification_due` still equals `expected_due` (optimistic lock,
/// like the certificate-renew pattern — a same-field advance needs a CAS token,
/// not a status CAS, since the status may stay `Compliant`).
///
/// Returns `Ok(None)` when the share is absent OR was concurrently recertified;
/// the caller distinguishes via a prior load (absent → 404, concurrent → 409).
pub async fn recertify_share(
    pool: &PgPool,
    id: &str,
    recertified: &FileShare,
    expected_due: DateTime<Utc>,
) -> Result<Option<FileShare>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<FileShareRow> = sqlx::query_as(&format!(
        "UPDATE file_shares \
         SET last_recertification = $2::timestamptz, \
             recertification_due = $3::timestamptz, \
             status = $4 \
         WHERE id = $1 AND recertification_due = $5 \
         RETURNING {SHARE_COLUMNS}"
    ))
    .bind(uid)
    .bind(&recertified.last_recertification)
    .bind(&recertified.recertification_due)
    .bind(share_status_str(&recertified.status))
    .bind(expected_due)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

// ─── Repository functions — ntfs_permissions ─────────────────────────────────

/// Return all NTFS permission rows for a given `file_share_id`, ordered by `folder_path`.
pub async fn list_permissions(
    pool: &PgPool,
    file_share_id: &str,
) -> Result<Vec<NTFSFolder>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(file_share_id) else {
        return Ok(Vec::new());
    };

    let rows: Vec<NTFSFolderRow> = sqlx::query_as(&format!(
        "SELECT {PERM_COLUMNS} FROM ntfs_permissions WHERE file_share_id = $1 ORDER BY folder_path"
    ))
    .bind(uid)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Insert a new NTFS permission row and return the persisted row.
#[allow(dead_code)]
pub async fn insert_permission(pool: &PgPool, r: &NTFSFolder) -> Result<NTFSFolder, sqlx::Error> {
    let id = Uuid::parse_str(&r.id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
    let file_share_id =
        Uuid::parse_str(&r.file_share_id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let last_reviewed: DateTime<Utc> = chrono::DateTime::parse_from_rfc3339(&r.last_reviewed)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let row: NTFSFolderRow = sqlx::query_as(&format!(
        "INSERT INTO ntfs_permissions \
         (id, file_share_id, folder_path, permission_type, ad_group, principal, inherited, last_reviewed) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         RETURNING {PERM_COLUMNS}"
    ))
    .bind(id)
    .bind(file_share_id)
    .bind(&r.folder_path)
    .bind(permission_type_str(&r.permission_type))
    .bind(&r.ad_group)
    .bind(&r.principal)
    .bind(r.inherited)
    .bind(last_reviewed)
    .fetch_one(pool)
    .await?;

    row.into_model()
}

/// Revoke (DELETE) an NTFS permission row identified by `(file_share_id, ad_group)`.
/// Returns `Ok(Some(()))` if a row was deleted, `Ok(None)` if no matching row
/// existed (caller → 404). Malformed `file_share_id` → `Ok(None)`.
///
/// Accepts any `sqlx::PgExecutor<'_>` (pool reference OR `&mut *tx`) so a
/// handler can compose the deletion and an audit row in a single atomic tx.
pub async fn revoke_permission(
    executor: impl sqlx::PgExecutor<'_>,
    file_share_id: &str,
    ad_group: &str,
) -> Result<Option<()>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(file_share_id) else {
        return Ok(None);
    };

    let result =
        sqlx::query("DELETE FROM ntfs_permissions WHERE file_share_id = $1 AND ad_group = $2")
            .bind(uid)
            .bind(ad_group)
            .execute(executor)
            .await?;

    if result.rows_affected() == 0 {
        Ok(None)
    } else {
        Ok(Some(()))
    }
}
