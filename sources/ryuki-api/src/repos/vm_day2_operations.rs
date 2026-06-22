//! Repository functions for `vm_day2_operations`.
//!
//! All functions are pure over `&PgPool`; callers (handlers in `contracts.rs`)
//! are responsible for mapping `sqlx::Error` → 500 and `None` → 404.
//!
//! The full `VmDay2ChangeRequest` is round-tripped through the `plan_json`
//! JSONB column so later calls can reconstruct the entity faithfully. The
//! scalar columns (`target_ci_key`, `change_type`, `target_value`, `site`,
//! `environment`, `owner`, `maintenance_window`, `status`) are kept in sync
//! for queryability but are not used during reconstruction.

use ryuki_engine::models::{VmChangeStatus, VmDay2ChangeRequest};
use sqlx::PgPool;
use uuid::Uuid;

// ─── Column list ─────────────────────────────────────────────────────────────

/// SELECT column list. UUID → text so sqlx binds into String; JSONB → text
/// so we can `serde_json::from_str` the full entity.
pub const COLUMNS: &str = "id::text AS id, status, plan_json::text AS plan_json";

// ─── Row struct ──────────────────────────────────────────────────────────────

/// Minimal row struct — the full entity lives in `plan_json`; the `status`
/// column is selected separately so `transition` can apply the CAS guard.
#[derive(sqlx::FromRow)]
pub struct VmDay2OperationRow {
    pub id: String,
    pub status: String,
    /// Raw JSON text from JSONB::text cast — the full `VmDay2ChangeRequest`.
    pub plan_json: Option<String>,
}

impl VmDay2OperationRow {
    /// Convert a DB row into the engine model by deserialising `plan_json`.
    ///
    /// The `status` column is kept in sync with the value encoded inside
    /// `plan_json`, but we use the column value to patch the status after
    /// transitions so that the status is always authoritative from the DB.
    pub fn into_model(self) -> Result<VmDay2ChangeRequest, sqlx::Error> {
        let raw = self
            .plan_json
            .ok_or_else(|| sqlx::Error::Decode("vm_day2_operations.plan_json: NULL".into()))?;

        let mut entity: VmDay2ChangeRequest = serde_json::from_str(&raw).map_err(|e| {
            sqlx::Error::Decode(
                format!("vm_day2_operations.plan_json: corrupt persisted value: {e}").into(),
            )
        })?;

        // Override the embedded status with the authoritative DB column value
        // (it may have been updated by `transition` after the initial insert).
        entity.status = decode_status(&self.status)
            .map_err(|e| sqlx::Error::Decode(format!("vm_day2_operations.status: {e}").into()))?;

        // Override the id with the DB-authoritative UUID string.
        entity.id = self.id;

        Ok(entity)
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

/// Canonical serde variant name for a `VmChangeStatus` as stored in the DB.
pub fn status_str(s: &VmChangeStatus) -> &'static str {
    match s {
        VmChangeStatus::Draft => "Draft",
        VmChangeStatus::Validated => "Validated",
        VmChangeStatus::Planned => "Planned",
        VmChangeStatus::Approved => "Approved",
        VmChangeStatus::Locked => "Locked",
        VmChangeStatus::Executed => "Executed",
        VmChangeStatus::Verified => "Verified",
        VmChangeStatus::Completed => "Completed",
        VmChangeStatus::Failed => "Failed",
    }
}

fn decode_status(s: &str) -> Result<VmChangeStatus, String> {
    // Stored without quotes; wrap in quotes for serde_json to deserialise as
    // a unit-variant string (matches the engine's Serialize/Deserialize impl).
    serde_json::from_str(&format!("\"{s}\"")).map_err(|e| format!("unknown status '{s}': {e}"))
}

// ─── Repository functions ─────────────────────────────────────────────────────

/// Insert a new vm day-2 operation. The caller supplies the model with an
/// already-generated UUID string as `id`; we parse it for the PK column.
pub async fn insert(pool: &PgPool, op: &VmDay2ChangeRequest) -> Result<(), sqlx::Error> {
    let id = Uuid::parse_str(&op.id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let change_type = op.change_type.to_string();
    let plan_json = serde_json::to_string(op).unwrap_or_else(|_| "{}".into());

    sqlx::query(
        "INSERT INTO vm_day2_operations \
         (id, target_ci_key, change_type, target_value, site, environment, \
          owner, maintenance_window, status, plan_json) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)",
    )
    .bind(id)
    .bind(&op.target_ci_key)
    .bind(&change_type)
    .bind(op.target_value as i32)
    .bind(&op.site)
    .bind(&op.environment)
    .bind(&op.owner)
    .bind(&op.maintenance_window)
    .bind(status_str(&op.status))
    .bind(&plan_json)
    .execute(pool)
    .await?;

    Ok(())
}

/// Fetch one vm day-2 operation by string id. A malformed (non-UUID) id is
/// treated as `Ok(None)` (callers map to 404) rather than an error — keeping
/// every handler's not-found behaviour uniform.
pub async fn get(pool: &PgPool, id: &str) -> Result<Option<VmDay2ChangeRequest>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<VmDay2OperationRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM vm_day2_operations WHERE id = $1"
    ))
    .bind(uid)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Return all vm day-2 operations ordered by creation time descending.
#[allow(dead_code)]
pub async fn list(pool: &PgPool) -> Result<Vec<VmDay2ChangeRequest>, sqlx::Error> {
    let rows: Vec<VmDay2OperationRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM vm_day2_operations ORDER BY created_at DESC, id DESC"
    ))
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Atomically transition a vm day-2 operation to its new state IFF its current
/// DB status still equals `expected_status` (optimistic lock). Returns
/// `Ok(false)` when the row is absent or its status had already changed
/// (caller → 409). `Ok(true)` on success.
///
/// Both `status` (scalar column for queryability) and `plan_json` (full entity
/// snapshot) are updated atomically within a transaction.
pub async fn transition(
    pool: &PgPool,
    expected_status: &str,
    op: &VmDay2ChangeRequest,
) -> Result<bool, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(&op.id) else {
        return Ok(false);
    };

    let plan_json = serde_json::to_string(op).unwrap_or_else(|_| "{}".into());

    let mut tx = pool.begin().await?;

    let res = sqlx::query(
        "UPDATE vm_day2_operations SET \
         status = $2, \
         plan_json = $3::jsonb, \
         updated_at = NOW() \
         WHERE id = $1 AND status = $4",
    )
    .bind(uid)
    .bind(status_str(&op.status))
    .bind(&plan_json)
    .bind(expected_status)
    .execute(&mut *tx)
    .await?;

    if res.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(false);
    }

    tx.commit().await?;
    Ok(true)
}
