//! Repository functions for `snapshots`.
//!
//! All functions are pure over `&PgPool`; callers (handlers in `contracts.rs`)
//! are responsible for mapping `sqlx::Error` → 500 and `None` → 404.
//!
//! # Audit parameter
//! `transition` accepts an `_audit_action: Option<&str>` parameter for
//! signature parity with the patch_waves template, but snapshots do not have
//! a dedicated audit table — the parameter is intentionally unused.

use chrono::{DateTime, Utc};
use ryuki_engine::models::{SnapshotRecord, SnapshotStatus};
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

// ─── Column list ─────────────────────────────────────────────────────────────

/// SELECT column list. UUID → text so sqlx binds into String; JSONB → text
/// so we can `serde_json::from_str` it. `created_at` and `updated_at` are
/// part of `SnapshotRecord` (as RFC-3339 strings), so they must be selected.
pub const COLUMNS: &str = "id::text AS id, \
     platform_ci_key, \
     snapshot_purpose, \
     requested_expiry, \
     owner, \
     support_group, \
     change_context, \
     status, \
     policy_decision, \
     backup_impact, \
     remediation_plan, \
     metadata::text AS metadata, \
     created_at, \
     updated_at";

// ─── Row struct ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct SnapshotRow {
    pub id: String,
    pub platform_ci_key: String,
    pub snapshot_purpose: String,
    pub requested_expiry: String,
    pub owner: String,
    pub support_group: String,
    pub change_context: String,
    pub status: String,
    /// Nullable TEXT columns — decoded directly, not via JSONB.
    pub policy_decision: Option<String>,
    pub backup_impact: Option<String>,
    pub remediation_plan: Option<String>,
    /// Raw JSON text from JSONB::text cast, e.g. `{"key":"value"}`.
    pub metadata: String,
    /// Timestamps decoded as chrono types; converted to RFC-3339 strings in
    /// `into_model`.
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SnapshotRow {
    /// Convert a DB row into the engine model.
    ///
    /// JSONB-text and enum-name fields are deserialized via `serde_json`. A
    /// parse failure means the persisted row is corrupt; we surface it as a
    /// decode error (caller → 500) rather than silently substituting defaults —
    /// a subsequent `transition` would otherwise persist those defaults over the
    /// real data, since the CAS only guards `status`, not the other columns.
    pub fn into_model(self) -> Result<SnapshotRecord, sqlx::Error> {
        fn decode<T: serde::de::DeserializeOwned>(
            raw: &str,
            field: &str,
        ) -> Result<T, sqlx::Error> {
            serde_json::from_str(raw).map_err(|e| {
                sqlx::Error::Decode(
                    format!("snapshots.{field}: corrupt persisted value: {e}").into(),
                )
            })
        }

        let metadata: HashMap<String, String> = decode(&self.metadata, "metadata")?;

        // Enum variants are stored as their serde name (e.g. "Draft",
        // "ReviewRequested"); decode via the engine's Deserialize impl. A DB
        // CHECK constraint (migration 059) keeps these in the legal set.
        let status: SnapshotStatus = decode(&format!("\"{}\"", self.status), "status")?;

        Ok(SnapshotRecord {
            id: self.id,
            platform_ci_key: self.platform_ci_key,
            snapshot_purpose: self.snapshot_purpose,
            requested_expiry: self.requested_expiry,
            owner: self.owner,
            support_group: self.support_group,
            change_context: self.change_context,
            status,
            policy_decision: self.policy_decision,
            backup_impact: self.backup_impact,
            remediation_plan: self.remediation_plan,
            created_at: self.created_at.to_rfc3339(),
            updated_at: self.updated_at.to_rfc3339(),
            metadata,
        })
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

/// Canonical serde variant name for a `SnapshotStatus` value as stored in the
/// DB (e.g. `"Draft"`, `"ReviewRequested"`). `pub` so transition handlers can
/// supply the `expected_status` argument to `transition` without duplicating
/// this table.
pub fn status_str(s: &SnapshotStatus) -> &'static str {
    match s {
        SnapshotStatus::Draft => "Draft",
        SnapshotStatus::ReviewRequested => "ReviewRequested",
        SnapshotStatus::ExpiryApproved => "ExpiryApproved",
        SnapshotStatus::StaleFlagged => "StaleFlagged",
        SnapshotStatus::RemediationPlanned => "RemediationPlanned",
        SnapshotStatus::Expired => "Expired",
        SnapshotStatus::Completed => "Completed",
        SnapshotStatus::Failed => "Failed",
    }
}

// ─── Repository functions ─────────────────────────────────────────────────────

/// Insert a new snapshot and return the persisted row. The caller supplies the
/// model with an already-generated UUID string as `id`; we parse it for the PK.
///
/// `created_at`/`updated_at` are not bound here — the DB column defaults (NOW())
/// own them. We `RETURNING` the inserted row so the returned model carries the
/// DB-authoritative timestamps (the response then matches a subsequent `get`).
pub async fn insert(
    executor: impl sqlx::PgExecutor<'_>,
    r: &SnapshotRecord,
) -> Result<SnapshotRecord, sqlx::Error> {
    let id = Uuid::parse_str(&r.id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let meta = serde_json::to_string(&r.metadata).unwrap_or_else(|_| "{}".into());

    let row: SnapshotRow = sqlx::query_as(&format!(
        "INSERT INTO snapshots \
         (id, platform_ci_key, snapshot_purpose, requested_expiry, owner, support_group, \
          change_context, status, policy_decision, backup_impact, remediation_plan, metadata) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb) \
         RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(&r.platform_ci_key)
    .bind(&r.snapshot_purpose)
    .bind(&r.requested_expiry)
    .bind(&r.owner)
    .bind(&r.support_group)
    .bind(&r.change_context)
    .bind(status_str(&r.status))
    .bind(&r.policy_decision)
    .bind(&r.backup_impact)
    .bind(&r.remediation_plan)
    .bind(&meta)
    .fetch_one(executor)
    .await?;

    row.into_model()
}

/// Fetch one snapshot by string id. A malformed (non-UUID) id is treated as
/// `Ok(None)` (callers map to 404) rather than an error — keeping every
/// handler's not-found behaviour uniform. `Err` is reserved for genuine DB
/// failures (callers map to 500).
pub async fn get(pool: &PgPool, id: &str) -> Result<Option<SnapshotRecord>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<SnapshotRow> =
        sqlx::query_as(&format!("SELECT {COLUMNS} FROM snapshots WHERE id = $1"))
            .bind(uid)
            .fetch_optional(pool)
            .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Return all snapshots ordered by creation time descending.
pub async fn list(pool: &PgPool) -> Result<Vec<SnapshotRecord>, sqlx::Error> {
    let rows: Vec<SnapshotRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM snapshots ORDER BY created_at DESC, id DESC"
    ))
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Atomically transition a snapshot to its new state IFF its current DB status
/// still equals `expected_status` (optimistic lock). Returns `Ok(None)` when the
/// row is absent or its status had already changed (caller → 409), or
/// `Ok(Some(persisted))` on success — the DB row after the write (with the
/// DB-owned `updated_at`) so the caller's response matches a subsequent `get`.
///
/// All mutable columns are updated together with `status` so a single CAS write
/// keeps all fields in sync. `updated_at` is set to NOW() by the DB.
///
/// `_audit_action` is accepted for signature parity with the patch_waves
/// template but is intentionally unused — snapshots have no audit table yet.
pub async fn transition(
    executor: impl sqlx::PgExecutor<'_>,
    expected_status: &str,
    r: &SnapshotRecord,
    _audit_action: Option<&str>,
) -> Result<Option<SnapshotRecord>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(&r.id) else {
        return Ok(None);
    };

    let meta = serde_json::to_string(&r.metadata).unwrap_or_else(|_| "{}".into());

    let row: Option<SnapshotRow> = sqlx::query_as(&format!(
        "UPDATE snapshots SET \
         status = $2, \
         policy_decision = $3, \
         backup_impact = $4, \
         remediation_plan = $5, \
         metadata = $6::jsonb, \
         updated_at = NOW() \
         WHERE id = $1 AND status = $7 \
         RETURNING {COLUMNS}"
    ))
    .bind(uid)
    .bind(status_str(&r.status))
    .bind(&r.policy_decision)
    .bind(&r.backup_impact)
    .bind(&r.remediation_plan)
    .bind(&meta)
    .bind(expected_status)
    .fetch_optional(executor)
    .await?;

    row.map(|row| row.into_model()).transpose()
}
