//! Repository functions for `decommission_requests` and `quarantine_log`.
//!
//! All functions are pure over `&PgPool`; callers (handlers in `contracts.rs`)
//! are responsible for mapping `sqlx::Error` → 500 and `None` → 404.

use chrono::{DateTime, Utc};
use ryuki_engine::models::{DecommissionRequest, DecommissionStatus, ServerType};
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

// ─── Column list ─────────────────────────────────────────────────────────────

/// SELECT column list. UUID → text so sqlx binds into String; JSONB → text
/// so we can `serde_json::from_str` them.
pub const COLUMNS: &str = "id::text AS id, \
     server_name, site, os_family, server_type, reason, \
     final_backup_required, quarantine_days, status, \
     dependencies_identified::text AS dependencies_identified, \
     backup_confirmed, \
     approvals_collected::text AS approvals_collected, \
     quarantine_until, created_at, updated_at, \
     metadata::text AS metadata";

// ─── Row struct ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct DecommissionRow {
    pub id: String,
    pub server_name: String,
    pub site: String,
    pub os_family: String,
    pub server_type: String,
    pub reason: String,
    pub final_backup_required: bool,
    pub quarantine_days: i32,
    pub status: String,
    /// Raw JSON text from JSONB::text cast, e.g. `["dep-a","dep-b"]`
    pub dependencies_identified: String,
    pub backup_confirmed: bool,
    /// Raw JSON text from JSONB::text cast, e.g. `["alice","bob"]`
    pub approvals_collected: String,
    pub quarantine_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Raw JSON text from JSONB::text cast, e.g. `{"k":"v"}`
    pub metadata: String,
}

impl DecommissionRow {
    /// Convert a DB row into the engine model.
    ///
    /// # Panics
    /// Only if the DB contains values that are not valid JSON arrays/objects —
    /// which indicates data corruption. All other conversion errors fall back
    /// to safe defaults to avoid aborting the whole list query.
    pub fn into_model(self) -> DecommissionRequest {
        let server_type = match self.server_type.as_str() {
            "Physical" => ServerType::Physical,
            _ => ServerType::VM,
        };

        // Parse status from the serde variant name stored in the DB
        // (e.g. "Planned", "RolledBack"). Deserialize via serde JSON so we
        // stay in sync with the engine's Deserialize impl automatically.
        let status: DecommissionStatus = serde_json::from_str(&format!("\"{}\"", self.status))
            .unwrap_or(DecommissionStatus::Draft);

        let dependencies_identified: Vec<String> =
            serde_json::from_str(&self.dependencies_identified).unwrap_or_default();

        let approvals_collected: Vec<String> =
            serde_json::from_str(&self.approvals_collected).unwrap_or_default();

        let metadata: HashMap<String, String> =
            serde_json::from_str(&self.metadata).unwrap_or_default();

        DecommissionRequest {
            id: self.id,
            server_name: self.server_name,
            site: self.site,
            os_family: self.os_family,
            server_type,
            reason: self.reason,
            final_backup_required: self.final_backup_required,
            quarantine_days: self.quarantine_days as u32,
            status,
            dependencies_identified,
            backup_confirmed: self.backup_confirmed,
            approvals_collected,
            quarantine_until: self.quarantine_until.map(|dt| dt.to_rfc3339()),
            created_at: self.created_at.to_rfc3339(),
            updated_at: self.updated_at.to_rfc3339(),
            metadata,
        }
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

fn server_type_str(t: &ServerType) -> &'static str {
    match t {
        ServerType::VM => "VM",
        ServerType::Physical => "Physical",
    }
}

/// Canonical serde variant name for a `DecommissionStatus` value as stored in
/// the DB (matches what `serde_json::to_value` produces for a unit variant,
/// e.g. `"Planned"`, `"RolledBack"`). `pub` so transition handlers can supply
/// the `expected_status` argument to `transition` without duplicating this table.
pub fn status_str(s: &DecommissionStatus) -> &'static str {
    match s {
        DecommissionStatus::Draft => "Draft",
        DecommissionStatus::Planned => "Planned",
        DecommissionStatus::Validated => "Validated",
        DecommissionStatus::Approved => "Approved",
        DecommissionStatus::Quarantined => "Quarantined",
        DecommissionStatus::Executed => "Executed",
        DecommissionStatus::Verified => "Verified",
        DecommissionStatus::Completed => "Completed",
        DecommissionStatus::RolledBack => "RolledBack",
        DecommissionStatus::Failed => "Failed",
    }
}

// ─── Repository functions ─────────────────────────────────────────────────────

/// Insert a new decommission request. The caller supplies the model (with an
/// already-generated `id` string); we parse it into a `Uuid` for the PK column.
pub async fn insert(pool: &PgPool, req: &DecommissionRequest) -> Result<(), sqlx::Error> {
    let id = Uuid::parse_str(&req.id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let deps =
        serde_json::to_string(&req.dependencies_identified).unwrap_or_else(|_| "[]".to_string());
    let approvals =
        serde_json::to_string(&req.approvals_collected).unwrap_or_else(|_| "[]".to_string());
    let meta = serde_json::to_string(&req.metadata).unwrap_or_else(|_| "{}".to_string());

    let quarantine_until: Option<DateTime<Utc>> = req
        .quarantine_until
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let created_at = DateTime::parse_from_rfc3339(&req.created_at)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    let updated_at = DateTime::parse_from_rfc3339(&req.updated_at)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    sqlx::query(
        "INSERT INTO decommission_requests \
         (id, server_name, site, os_family, server_type, reason, \
          final_backup_required, quarantine_days, status, \
          dependencies_identified, backup_confirmed, approvals_collected, \
          quarantine_until, created_at, updated_at, metadata) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, \
                 $10::jsonb, $11, $12::jsonb, $13, $14, $15, $16::jsonb)",
    )
    .bind(id)
    .bind(&req.server_name)
    .bind(&req.site)
    .bind(&req.os_family)
    .bind(server_type_str(&req.server_type))
    .bind(&req.reason)
    .bind(req.final_backup_required)
    .bind(req.quarantine_days as i32)
    .bind(status_str(&req.status))
    .bind(&deps)
    .bind(req.backup_confirmed)
    .bind(&approvals)
    .bind(quarantine_until)
    .bind(created_at)
    .bind(updated_at)
    .bind(&meta)
    .execute(pool)
    .await?;

    Ok(())
}

/// Fetch one request by string id. A malformed id cannot identify an existing
/// row, so it is treated as `Ok(None)` (callers map to 404) rather than an
/// error — keeping every handler's not-found behaviour uniform. `Err` is
/// reserved for genuine DB failures (callers map to 500).
pub async fn get(pool: &PgPool, id: &str) -> Result<Option<DecommissionRequest>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<DecommissionRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM decommission_requests WHERE id = $1"
    ))
    .bind(uid)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.into_model()))
}

/// Return all requests whose status is one of the active quarantine states
/// (Quarantined, Executed, Verified). Used to build the quarantine inventory.
pub async fn list_quarantine(pool: &PgPool) -> Result<Vec<DecommissionRequest>, sqlx::Error> {
    let rows: Vec<DecommissionRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM decommission_requests \
         WHERE status IN ('Quarantined', 'Executed', 'Verified')"
    ))
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into_model()).collect())
}

/// Atomically transition a request to its new state IFF its current DB status
/// still equals `expected_status` (optimistic lock), and (optionally) append an
/// audit-log row in the SAME transaction. Returns `Ok(false)` when the row was
/// absent or its status had already changed (caller → 409). `Ok(true)` on success.
pub async fn transition(
    pool: &PgPool,
    expected_status: &str,
    req: &DecommissionRequest,
    audit_action: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(&req.id) else {
        return Ok(false);
    };

    let deps =
        serde_json::to_string(&req.dependencies_identified).unwrap_or_else(|_| "[]".to_string());
    let approvals =
        serde_json::to_string(&req.approvals_collected).unwrap_or_else(|_| "[]".to_string());
    let meta = serde_json::to_string(&req.metadata).unwrap_or_else(|_| "{}".to_string());

    let quarantine_until: Option<DateTime<Utc>> = req
        .quarantine_until
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let updated_at = DateTime::parse_from_rfc3339(&req.updated_at)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    let mut tx = pool.begin().await?;

    let res = sqlx::query(
        "UPDATE decommission_requests SET \
         server_name = $2, site = $3, os_family = $4, server_type = $5, \
         reason = $6, final_backup_required = $7, quarantine_days = $8, \
         status = $9, dependencies_identified = $10::jsonb, \
         backup_confirmed = $11, approvals_collected = $12::jsonb, \
         quarantine_until = $13, updated_at = $14, metadata = $15::jsonb \
         WHERE id = $1 AND status = $16",
    )
    .bind(uid)
    .bind(&req.server_name)
    .bind(&req.site)
    .bind(&req.os_family)
    .bind(server_type_str(&req.server_type))
    .bind(&req.reason)
    .bind(req.final_backup_required)
    .bind(req.quarantine_days as i32)
    .bind(status_str(&req.status))
    .bind(&deps)
    .bind(req.backup_confirmed)
    .bind(&approvals)
    .bind(quarantine_until)
    .bind(updated_at)
    .bind(&meta)
    .bind(expected_status)
    .execute(&mut *tx)
    .await?;

    if res.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(false);
    }

    if let Some(action) = audit_action {
        sqlx::query(
            "INSERT INTO quarantine_log (id, server_name, action, timestamp) \
             VALUES (gen_random_uuid(), $1, $2, NOW())",
        )
        .bind(&req.server_name)
        .bind(action)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(true)
}
