//! Repository functions for `hardware_assets` + `firmware_history`.
//!
//! All functions are pure over `&PgPool`; callers (handlers in `contracts.rs`)
//! are responsible for mapping `sqlx::Error` → 500 and `None` → 404.
//!
//! # Design: engine vs. repo responsibility split
//! The engine functions (`add_asset`, `update_firmware`) validate inputs and
//! return a computed model value — they are pure and perform no I/O. The repo
//! functions persist those computed values. `apply_firmware_update` atomically
//! UPDATEs the asset row and INSERTs a `firmware_history` row in one transaction
//! so a firmware update can never land without its audit history (and vice versa).
//!
//! # Child table: firmware_history
//! `firmware_history` has NO `ON DELETE CASCADE` (migration 039). Tests must
//! therefore delete child rows for created assets BEFORE deleting the parent.
//!
//! # CAS note
//! `apply_firmware_update` does not use a compare-and-set on the old
//! `firmware_installed` value. `firmware_history` appends every update so no
//! history row is ever lost, and the last-write-wins semantics are acceptable
//! for firmware baseline tracking where two concurrent updates both represent
//! operator intent.

use chrono::{DateTime, Utc};
use ryuki_engine::hardware_lifecycle::{HardwareAsset, LifecycleStatus, SupportStatus, Vendor};
use sqlx::PgPool;
use uuid::Uuid;

// ─── Column list ─────────────────────────────────────────────────────────────

/// SELECT column list for `hardware_assets`. UUID → text so sqlx decodes into
/// `String`. `created_at` is DB-only (not in the model) — do NOT select it.
pub const COLUMNS: &str = "id::text AS id, \
     vendor, \
     model, \
     serial_number, \
     site, \
     cluster, \
     warranty_expiry, \
     firmware_baseline, \
     firmware_installed, \
     support_status, \
     lifecycle_status, \
     last_health_check";

// ─── Row struct ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct HardwareAssetRow {
    pub id: String,
    pub vendor: String,
    pub model: String,
    pub serial_number: String,
    pub site: String,
    pub cluster: String,
    pub warranty_expiry: DateTime<Utc>,
    pub firmware_baseline: String,
    pub firmware_installed: String,
    pub support_status: String,
    pub lifecycle_status: String,
    pub last_health_check: DateTime<Utc>,
}

impl HardwareAssetRow {
    /// Convert a DB row into the engine model.
    ///
    /// The three enum columns are stored as their serde PascalCase names and
    /// decoded via `serde_json`. A parse failure means the persisted row is
    /// corrupt; we surface it as a decode error (caller → 500) rather than
    /// substituting a default — a subsequent write would otherwise persist that
    /// default over the real data. DB CHECK constraints (migration 062) keep
    /// these columns in the legal set.
    pub fn into_model(self) -> Result<HardwareAsset, sqlx::Error> {
        fn decode<T: serde::de::DeserializeOwned>(
            raw: &str,
            field: &str,
        ) -> Result<T, sqlx::Error> {
            serde_json::from_str(raw).map_err(|e| {
                sqlx::Error::Decode(
                    format!("hardware_assets.{field}: corrupt persisted value: {e}").into(),
                )
            })
        }

        let vendor: Vendor = decode(&format!("\"{}\"", self.vendor), "vendor")?;
        let support_status: SupportStatus =
            decode(&format!("\"{}\"", self.support_status), "support_status")?;
        let lifecycle_status: LifecycleStatus = decode(
            &format!("\"{}\"", self.lifecycle_status),
            "lifecycle_status",
        )?;

        Ok(HardwareAsset {
            id: self.id,
            vendor,
            model: self.model,
            serial_number: self.serial_number,
            site: self.site,
            cluster: self.cluster,
            warranty_expiry: self.warranty_expiry.to_rfc3339(),
            firmware_baseline: self.firmware_baseline,
            firmware_installed: self.firmware_installed,
            support_status,
            lifecycle_status,
            last_health_check: self.last_health_check.to_rfc3339(),
        })
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

/// Canonical serde variant name for a `Vendor` value as stored in the DB.
pub fn vendor_str(v: &Vendor) -> &'static str {
    match v {
        Vendor::HPE => "HPE",
        Vendor::Lenovo => "Lenovo",
    }
}

/// Canonical serde variant name for a `SupportStatus` value as stored in the DB.
pub fn support_status_str(s: &SupportStatus) -> &'static str {
    match s {
        SupportStatus::Supported => "Supported",
        SupportStatus::Expiring => "Expiring",
        SupportStatus::Expired => "Expired",
    }
}

/// Canonical serde variant name for a `LifecycleStatus` value as stored in the
/// DB.
pub fn lifecycle_status_str(l: &LifecycleStatus) -> &'static str {
    match l {
        LifecycleStatus::Production => "Production",
        LifecycleStatus::Extended => "Extended",
        LifecycleStatus::Retiring => "Retiring",
        LifecycleStatus::Retired => "Retired",
    }
}

// ─── Repository functions ─────────────────────────────────────────────────────

/// Fetch one asset by string id. A malformed (non-UUID) id is treated as
/// `Ok(None)` (callers map to 404) rather than an error — keeping every
/// handler's not-found behaviour uniform. `Err` is reserved for genuine DB
/// failures (callers map to 500).
pub async fn get(pool: &PgPool, id: &str) -> Result<Option<HardwareAsset>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<HardwareAssetRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM hardware_assets WHERE id = $1"
    ))
    .bind(uid)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Return all assets, optionally filtered by site. An empty `site` returns all
/// assets. Results are ordered by `site, id` for stable pagination.
pub async fn list(pool: &PgPool, site: &str) -> Result<Vec<HardwareAsset>, sqlx::Error> {
    let rows: Vec<HardwareAssetRow> = if site.is_empty() {
        sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM hardware_assets ORDER BY site, id"
        ))
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM hardware_assets WHERE site = $1 ORDER BY id"
        ))
        .bind(site)
        .fetch_all(pool)
        .await?
    };

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Insert a new asset and return the persisted row. The caller supplies the
/// model with an already-generated UUID string as `id`.
///
/// `warranty_expiry` and `last_health_check` are bound from the RFC-3339 strings
/// in the model. `created_at` is left to the DB default (NOW()).
///
/// We `RETURNING` the inserted row so the returned model carries the
/// DB-authoritative values (the response then matches a subsequent `get`).
pub async fn insert(pool: &PgPool, r: &HardwareAsset) -> Result<HardwareAsset, sqlx::Error> {
    let id = Uuid::parse_str(&r.id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let warranty_expiry: DateTime<Utc> = chrono::DateTime::parse_from_rfc3339(&r.warranty_expiry)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let last_health_check: DateTime<Utc> =
        chrono::DateTime::parse_from_rfc3339(&r.last_health_check)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let row: HardwareAssetRow = sqlx::query_as(&format!(
        "INSERT INTO hardware_assets \
         (id, vendor, model, serial_number, site, cluster, \
          warranty_expiry, firmware_baseline, firmware_installed, \
          support_status, lifecycle_status, last_health_check) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
         RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(vendor_str(&r.vendor))
    .bind(&r.model)
    .bind(&r.serial_number)
    .bind(&r.site)
    .bind(&r.cluster)
    .bind(warranty_expiry)
    .bind(&r.firmware_baseline)
    .bind(&r.firmware_installed)
    .bind(support_status_str(&r.support_status))
    .bind(lifecycle_status_str(&r.lifecycle_status))
    .bind(last_health_check)
    .fetch_one(pool)
    .await?;

    row.into_model()
}

/// Atomically update the asset's `firmware_installed` column AND append a
/// `firmware_history` row, all in a single transaction. Returns `Ok(None)` when
/// no asset with `asset_id` exists (caller maps to 404).
///
/// The transaction sequence:
/// 1. UPDATE `hardware_assets` SET `firmware_installed = $2` WHERE `id = $1`.
///    If `rows_affected == 0`, roll back and return `Ok(None)`.
/// 2. INSERT INTO `firmware_history (asset_id, version)`.
/// 3. Commit.
/// 4. Re-read the asset via `get` and return it.
///
/// Note: no compare-and-set on the old `firmware_installed` value. Every update
/// appends a `firmware_history` row so the full audit trail is preserved even if
/// two concurrent updates race; last-write-wins is acceptable here.
pub async fn apply_firmware_update(
    pool: &PgPool,
    asset_id: &str,
    version: &str,
    scope_site: &str,
) -> Result<Option<HardwareAsset>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(asset_id) else {
        return Ok(None);
    };

    let mut tx = pool.begin().await?;

    // `AND site = $3` (#2): the firmware UPDATE is site-aware atomically, so an
    // asset re-homed out of the caller's scope between the handler's guard and
    // here matches 0 rows -> Ok(None) -> the handler's 404, and the
    // firmware_history INSERT below only runs for an in-scope write.
    // RETURNING the updated row makes the response come from the SAME scoped,
    // in-tx write — never a post-commit re-read that a concurrent re-home could
    // turn into an out-of-scope asset in the reply.
    let updated: Option<HardwareAssetRow> = sqlx::query_as(&format!(
        "UPDATE hardware_assets SET firmware_installed = $2 \
         WHERE id = $1 AND site = $3 RETURNING {COLUMNS}"
    ))
    .bind(uid)
    .bind(version)
    .bind(scope_site)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(updated) = updated else {
        tx.rollback().await?;
        return Ok(None);
    };

    sqlx::query("INSERT INTO firmware_history (asset_id, version) VALUES ($1, $2)")
        .bind(uid)
        .bind(version)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    updated.into_model().map(Some)
}
