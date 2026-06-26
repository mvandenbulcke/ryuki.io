//! Repository functions for `patch_waves`.
//!
//! Mutation functions (`insert`, `transition`) accept either a `PgPool`
//! reference (standalone call) or a `&mut PgConnection` (caller-owned tx) so
//! that handlers can compose the repo mutation and an audit row atomically.
//! Read functions (`get`, `list`) remain `&PgPool`-only. Callers are
//! responsible for mapping `sqlx::Error` → 500 and `None` → 404.
//!
//! # Audit parameter
//! `transition` accepts an `_audit_action: Option<&str>` parameter for
//! signature parity with the decommission template. Audit rows are written by
//! the handler via `audit::record_audit_tx` on the same connection.

use ryuki_engine::models::{PatchSchedule, PatchWave, PatchWaveStatus, RebootPolicy};
use sqlx::{PgConnection, PgPool};
use std::collections::HashMap;
use uuid::Uuid;

// ─── Column list ─────────────────────────────────────────────────────────────

/// SELECT column list. UUID → text so sqlx binds into String; JSONB → text
/// so we can `serde_json::from_str` them.
pub const COLUMNS: &str = "id::text AS id, \
     name, \
     servers::text AS servers, \
     site_scope::text AS site_scope, \
     environment_scope::text AS environment_scope, \
     schedule::text AS schedule, \
     reboot_policy, \
     blackout_dates::text AS blackout_dates, \
     validation_errors::text AS validation_errors, \
     status, \
     metadata::text AS metadata";

// ─── Row struct ──────────────────────────────────────────────────────────────

/// The DB-managed `created_at`/`updated_at` columns are not part of the
/// `PatchWave` model, so they are not selected/decoded here. `list` still
/// orders by `created_at` in SQL (a column need not be in the SELECT list to be
/// ordered by).
#[derive(sqlx::FromRow)]
pub struct PatchWaveRow {
    pub id: String,
    pub name: String,
    /// Raw JSON text from JSONB::text cast, e.g. `["srv-01","srv-02"]`
    pub servers: String,
    /// Raw JSON text from JSONB::text cast, e.g. `["DEFRA"]`
    pub site_scope: String,
    /// Raw JSON text from JSONB::text cast, e.g. `["production"]`
    pub environment_scope: String,
    /// Raw JSON text from JSONB::text cast (PatchSchedule object)
    pub schedule: String,
    pub reboot_policy: String,
    /// Raw JSON text from JSONB::text cast, e.g. `[]`
    pub blackout_dates: String,
    /// Raw JSON text from JSONB::text cast, e.g. `[]`
    pub validation_errors: String,
    pub status: String,
    /// Raw JSON text from JSONB::text cast, e.g. `{"k":"v"}`
    pub metadata: String,
}

impl PatchWaveRow {
    /// Convert a DB row into the engine model.
    ///
    /// JSONB-text and enum-name fields are deserialized via `serde_json`. A
    /// parse failure means the persisted row is corrupt; we surface it as a
    /// decode error (caller → 500) rather than silently substituting defaults —
    /// a subsequent `transition` would otherwise persist those defaults over the
    /// real data, since the CAS only guards `status`, not the other columns.
    pub fn into_model(self) -> Result<PatchWave, sqlx::Error> {
        fn decode<T: serde::de::DeserializeOwned>(
            raw: &str,
            field: &str,
        ) -> Result<T, sqlx::Error> {
            serde_json::from_str(raw).map_err(|e| {
                sqlx::Error::Decode(
                    format!("patch_waves.{field}: corrupt persisted value: {e}").into(),
                )
            })
        }

        let servers: Vec<String> = decode(&self.servers, "servers")?;
        let site_scope: Vec<String> = decode(&self.site_scope, "site_scope")?;
        let environment_scope: Vec<String> = decode(&self.environment_scope, "environment_scope")?;
        let schedule: PatchSchedule = decode(&self.schedule, "schedule")?;
        let blackout_dates: Vec<String> = decode(&self.blackout_dates, "blackout_dates")?;
        let validation_errors: Vec<String> = decode(&self.validation_errors, "validation_errors")?;
        let metadata: HashMap<String, String> = decode(&self.metadata, "metadata")?;

        // Enum variants are stored as their serde name (e.g. "Draft",
        // "RebootIfRequired"); decode via the engine's Deserialize impl. A DB
        // CHECK constraint (migration 058) keeps these in the legal set.
        let status: PatchWaveStatus = decode(&format!("\"{}\"", self.status), "status")?;
        let reboot_policy: RebootPolicy =
            decode(&format!("\"{}\"", self.reboot_policy), "reboot_policy")?;

        Ok(PatchWave {
            id: self.id,
            name: self.name,
            servers,
            site_scope,
            environment_scope,
            schedule,
            reboot_policy,
            blackout_dates,
            validation_errors,
            status,
            metadata,
        })
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

/// Canonical serde variant name for a `PatchWaveStatus` value as stored in the
/// DB (e.g. `"Draft"`, `"Validated"`). `pub` so transition handlers can supply
/// the `expected_status` argument to `transition` without duplicating this table.
pub fn status_str(s: &PatchWaveStatus) -> &'static str {
    match s {
        PatchWaveStatus::Draft => "Draft",
        PatchWaveStatus::Validated => "Validated",
        PatchWaveStatus::Approved => "Approved",
        PatchWaveStatus::Scheduled => "Scheduled",
        PatchWaveStatus::InProgress => "InProgress",
        PatchWaveStatus::Completed => "Completed",
        PatchWaveStatus::Failed => "Failed",
    }
}

/// Canonical serde variant name for a `RebootPolicy` value as stored in the DB
/// (e.g. `"RebootIfRequired"`, `"NoReboot"`).
pub fn reboot_policy_str(p: &RebootPolicy) -> &'static str {
    match p {
        RebootPolicy::RebootIfRequired => "RebootIfRequired",
        RebootPolicy::RebootAlways => "RebootAlways",
        RebootPolicy::NoReboot => "NoReboot",
        RebootPolicy::ScheduleOnly => "ScheduleOnly",
    }
}

// ─── Repository functions ─────────────────────────────────────────────────────

/// Insert a new patch wave. The caller supplies the model with an
/// already-generated UUID string as `id`; we parse it for the PK column.
///
/// The legacy `site` and `os_family` columns (nullable as of migration 058) are
/// derived from the model: `site` from `site_scope.first()` and `os_family` from
/// `metadata["os_family"]`, or NULL when the model carries no such value.
///
/// Accepts any `sqlx::PgExecutor` — pass `pool` for a standalone call, or
/// `&mut *tx` to share a transaction with an audit write.
pub async fn insert(executor: impl sqlx::PgExecutor<'_>, w: &PatchWave) -> Result<(), sqlx::Error> {
    let id = Uuid::parse_str(&w.id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let servers = serde_json::to_string(&w.servers).unwrap_or_else(|_| "[]".into());
    let site_scope = serde_json::to_string(&w.site_scope).unwrap_or_else(|_| "[]".into());
    let environment_scope =
        serde_json::to_string(&w.environment_scope).unwrap_or_else(|_| "[]".into());
    let schedule = serde_json::to_string(&w.schedule).unwrap_or_else(|_| "{}".into());
    let blackout_dates = serde_json::to_string(&w.blackout_dates).unwrap_or_else(|_| "[]".into());
    let validation_errors =
        serde_json::to_string(&w.validation_errors).unwrap_or_else(|_| "[]".into());
    let meta = serde_json::to_string(&w.metadata).unwrap_or_else(|_| "{}".into());

    // Legacy denormalized columns (nullable as of migration 058): the model's
    // authoritative values live in site_scope / metadata. Record NULL — never an
    // empty string in a would-be-NOT-NULL column — when the model has no value.
    let site = w.site_scope.first().cloned().filter(|s| !s.is_empty());
    let os_family = w
        .metadata
        .get("os_family")
        .cloned()
        .filter(|s| !s.is_empty());

    sqlx::query(
        "INSERT INTO patch_waves \
         (id, site, os_family, name, servers, site_scope, environment_scope, \
          schedule, reboot_policy, blackout_dates, validation_errors, status, metadata) \
         VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, \
                 $8::jsonb, $9, $10::jsonb, $11::jsonb, $12, $13::jsonb)",
    )
    .bind(id)
    .bind(site)
    .bind(os_family)
    .bind(&w.name)
    .bind(&servers)
    .bind(&site_scope)
    .bind(&environment_scope)
    .bind(&schedule)
    .bind(reboot_policy_str(&w.reboot_policy))
    .bind(&blackout_dates)
    .bind(&validation_errors)
    .bind(status_str(&w.status))
    .bind(&meta)
    .execute(executor)
    .await?;

    Ok(())
}

/// Fetch one patch wave by string id. A malformed (non-UUID) id is treated as
/// `Ok(None)` (callers map to 404) rather than an error — keeping every
/// handler's not-found behaviour uniform. `Err` is reserved for genuine DB
/// failures (callers map to 500).
pub async fn get(pool: &PgPool, id: &str) -> Result<Option<PatchWave>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<PatchWaveRow> =
        sqlx::query_as(&format!("SELECT {COLUMNS} FROM patch_waves WHERE id = $1"))
            .bind(uid)
            .fetch_optional(pool)
            .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Return all patch waves ordered by creation time descending.
pub async fn list(pool: &PgPool) -> Result<Vec<PatchWave>, sqlx::Error> {
    let rows: Vec<PatchWaveRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM patch_waves ORDER BY created_at DESC, id DESC"
    ))
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Atomically transition a patch wave to its new state IFF its current DB
/// status still equals `expected_status` (optimistic lock). Returns `Ok(false)`
/// when the row is absent or its status had already changed (caller → 409).
/// `Ok(true)` on success.
///
/// The caller opens the tx, passes `conn = &mut *tx`, and commits on success.
/// An `Ok(false)` (CAS miss) returns without mutating — the caller drops the tx
/// (rollback). Only `Ok(true)` callers should commit.
///
/// `_audit_action` is accepted for signature parity with the decommission
/// template but is intentionally unused — patch wave audit rows are written by
/// the handler via `audit::record_audit_tx` on the same connection.
pub async fn transition(
    conn: &mut PgConnection,
    expected_status: &str,
    w: &PatchWave,
    _audit_action: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(&w.id) else {
        return Ok(false);
    };

    let servers = serde_json::to_string(&w.servers).unwrap_or_else(|_| "[]".into());
    let site_scope = serde_json::to_string(&w.site_scope).unwrap_or_else(|_| "[]".into());
    let environment_scope =
        serde_json::to_string(&w.environment_scope).unwrap_or_else(|_| "[]".into());
    let schedule = serde_json::to_string(&w.schedule).unwrap_or_else(|_| "{}".into());
    let blackout_dates = serde_json::to_string(&w.blackout_dates).unwrap_or_else(|_| "[]".into());
    let validation_errors =
        serde_json::to_string(&w.validation_errors).unwrap_or_else(|_| "[]".into());
    let meta = serde_json::to_string(&w.metadata).unwrap_or_else(|_| "{}".into());

    let res = sqlx::query(
        "UPDATE patch_waves SET \
         name = $2, \
         servers = $3::jsonb, \
         site_scope = $4::jsonb, \
         environment_scope = $5::jsonb, \
         schedule = $6::jsonb, \
         reboot_policy = $7, \
         blackout_dates = $8::jsonb, \
         validation_errors = $9::jsonb, \
         status = $10, \
         metadata = $11::jsonb, \
         updated_at = NOW() \
         WHERE id = $1 AND status = $12",
    )
    .bind(uid)
    .bind(&w.name)
    .bind(&servers)
    .bind(&site_scope)
    .bind(&environment_scope)
    .bind(&schedule)
    .bind(reboot_policy_str(&w.reboot_policy))
    .bind(&blackout_dates)
    .bind(&validation_errors)
    .bind(status_str(&w.status))
    .bind(&meta)
    .bind(expected_status)
    .execute(&mut *conn)
    .await?;

    Ok(res.rows_affected() > 0)
}
