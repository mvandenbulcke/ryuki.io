//! Repository functions for `linux_deployment_requests`.
//!
//! All functions are pure over `&PgPool`; callers (handlers in `contracts.rs`)
//! are responsible for mapping `sqlx::Error` → 500 and `None` → 404.
//!
//! The full `LinuxDeploymentRequest` is round-tripped through the `plan`
//! JSONB column so later calls can reconstruct the entity faithfully. The
//! scalar columns (`distro`, `version`, `site`, `cpu`, `memory_gb`, `disk_gb`,
//! `hostname`, `network`, `hardening_profile`, `status`) are kept in sync for
//! queryability but are not used during reconstruction.

use ryuki_engine::models::{LinuxDeploymentRequest, LinuxDeploymentStatus};
use sqlx::PgPool;
use uuid::Uuid;

// ─── Column list ─────────────────────────────────────────────────────────────

/// SELECT column list. UUID → text so sqlx binds into String; JSONB → text
/// so we can `serde_json::from_str` the full entity.
pub const COLUMNS: &str = "id::text AS id, status, plan::text AS plan";

// ─── Row struct ──────────────────────────────────────────────────────────────

/// Minimal row struct — the full entity lives in `plan`; the `status`
/// column is selected separately so `transition` can apply the CAS guard.
#[derive(sqlx::FromRow)]
pub struct LinuxDeploymentRow {
    pub id: String,
    pub status: String,
    /// Raw JSON text from JSONB::text cast — the full `LinuxDeploymentRequest`.
    pub plan: Option<String>,
}

impl LinuxDeploymentRow {
    /// Convert a DB row into the engine model by deserialising `plan`.
    ///
    /// The `status` column is kept in sync with the value encoded inside
    /// `plan`, but we use the column value to patch the status after
    /// transitions so that the status is always authoritative from the DB.
    pub fn into_model(self) -> Result<LinuxDeploymentRequest, sqlx::Error> {
        let raw = self
            .plan
            .ok_or_else(|| sqlx::Error::Decode("linux_deployment_requests.plan: NULL".into()))?;

        let mut entity: LinuxDeploymentRequest = serde_json::from_str(&raw).map_err(|e| {
            sqlx::Error::Decode(
                format!("linux_deployment_requests.plan: corrupt persisted value: {e}").into(),
            )
        })?;

        // Override the embedded status with the authoritative DB column value
        // (it may have been updated by `transition` after the initial insert).
        entity.status = decode_status(&self.status).map_err(|e| {
            sqlx::Error::Decode(format!("linux_deployment_requests.status: {e}").into())
        })?;

        // Override the id with the DB-authoritative UUID string.
        entity.id = self.id;

        Ok(entity)
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

/// Canonical serde variant name for a `LinuxDeploymentStatus` as stored in the DB.
pub fn status_str(s: &LinuxDeploymentStatus) -> &'static str {
    match s {
        LinuxDeploymentStatus::Draft => "Draft",
        LinuxDeploymentStatus::Validated => "Validated",
        LinuxDeploymentStatus::Planned => "Planned",
        LinuxDeploymentStatus::Approved => "Approved",
        LinuxDeploymentStatus::Locked => "Locked",
        LinuxDeploymentStatus::Executed => "Executed",
        LinuxDeploymentStatus::Verified => "Verified",
        LinuxDeploymentStatus::Completed => "Completed",
        LinuxDeploymentStatus::Failed => "Failed",
    }
}

fn decode_status(s: &str) -> Result<LinuxDeploymentStatus, String> {
    // Stored without quotes; wrap in quotes for serde_json to deserialise as
    // a unit-variant string (matches the engine's Serialize/Deserialize impl).
    serde_json::from_str(&format!("\"{s}\"")).map_err(|e| format!("unknown status '{s}': {e}"))
}

// ─── Repository functions ─────────────────────────────────────────────────────

/// Insert a new linux deployment request. The caller supplies the model with
/// an already-generated UUID string as `id`; we parse it for the PK column.
pub async fn insert(pool: &PgPool, req: &LinuxDeploymentRequest) -> Result<(), sqlx::Error> {
    let id = Uuid::parse_str(&req.id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let hardening = req.hardening_profile.to_string();
    let plan_json = serde_json::to_string(req).unwrap_or_else(|_| "{}".into());

    // Checked u32 -> i32 so an out-of-range resource value is rejected up front
    // rather than silently wrapping to a negative scalar column (the queryable
    // columns must stay faithful to the JSONB `plan`).
    let cpu = i32::try_from(req.cpu).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
    let memory_gb = i32::try_from(req.memory_gb).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
    let disk_gb = i32::try_from(req.disk_gb).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    sqlx::query(
        "INSERT INTO linux_deployment_requests \
         (id, distro, version, site, cpu, memory_gb, disk_gb, hostname, \
          network, hardening_profile, status, plan) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb)",
    )
    .bind(id)
    .bind(req.distro.to_string())
    .bind(&req.version)
    .bind(&req.site)
    .bind(cpu)
    .bind(memory_gb)
    .bind(disk_gb)
    .bind(&req.hostname)
    .bind(&req.network)
    .bind(&hardening)
    .bind(status_str(&req.status))
    .bind(&plan_json)
    .execute(pool)
    .await?;

    Ok(())
}

/// Fetch one linux deployment request by string id. A malformed (non-UUID)
/// id is treated as `Ok(None)` (callers map to 404) rather than an error —
/// keeping every handler's not-found behaviour uniform.
pub async fn get(pool: &PgPool, id: &str) -> Result<Option<LinuxDeploymentRequest>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<LinuxDeploymentRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM linux_deployment_requests WHERE id = $1"
    ))
    .bind(uid)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Return all linux deployment requests ordered by creation time descending.
#[allow(dead_code)]
pub async fn list(pool: &PgPool) -> Result<Vec<LinuxDeploymentRequest>, sqlx::Error> {
    let rows: Vec<LinuxDeploymentRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM linux_deployment_requests ORDER BY created_at DESC, id DESC"
    ))
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Atomically transition a linux deployment request to its new state IFF its
/// current DB status still equals `expected_status` (optimistic lock). Returns
/// `Ok(false)` when the row is absent or its status had already changed
/// (caller → 409). `Ok(true)` on success.
///
/// Both `status` (scalar column for queryability) and `plan` (full entity
/// snapshot) are updated atomically within a transaction.
pub async fn transition(
    pool: &PgPool,
    expected_status: &str,
    req: &LinuxDeploymentRequest,
) -> Result<bool, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(&req.id) else {
        return Ok(false);
    };

    let plan_json = serde_json::to_string(req).unwrap_or_else(|_| "{}".into());

    let mut tx = pool.begin().await?;

    let res = sqlx::query(
        "UPDATE linux_deployment_requests SET \
         status = $2, \
         plan = $3::jsonb, \
         updated_at = NOW() \
         WHERE id = $1 AND status = $4",
    )
    .bind(uid)
    .bind(status_str(&req.status))
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
