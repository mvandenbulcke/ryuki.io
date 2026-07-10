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

/// Return ALL assets, optionally filtered by site. An empty `site` returns all
/// assets. Used by the aggregate read handlers (warranty-expiring, firmware
/// gaps, ...) via `hardware_assets_or_empty`, which need every asset; the
/// paginated inventory endpoint uses [`list_page`] instead.
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

/// List assets (optionally site-filtered) bounded to one `LIMIT`/`OFFSET` page
/// (#14). SEPARATE from [`list`] because the aggregate callers need the full
/// set — only the inventory list endpoint pages. `id` is the primary key, so
/// the `ORDER BY … id` is a unique, stable cut.
pub async fn list_page(
    pool: &PgPool,
    site: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<HardwareAsset>, sqlx::Error> {
    let rows: Vec<HardwareAssetRow> = if site.is_empty() {
        sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM hardware_assets ORDER BY site, id LIMIT $1 OFFSET $2"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM hardware_assets WHERE site = $1 ORDER BY id LIMIT $2 OFFSET $3"
        ))
        .bind(site)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    };

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Count assets (optionally site-filtered) — the pagination total for
/// [`list_page`], using the SAME `WHERE` so the count matches the paged set.
pub async fn count(pool: &PgPool, site: &str) -> Result<i64, sqlx::Error> {
    if site.is_empty() {
        sqlx::query_scalar("SELECT COUNT(*) FROM hardware_assets")
            .fetch_one(pool)
            .await
    } else {
        sqlx::query_scalar("SELECT COUNT(*) FROM hardware_assets WHERE site = $1")
            .bind(site)
            .fetch_one(pool)
            .await
    }
}

/// Insert a new asset and return the persisted row. The caller supplies the
/// model with an already-generated UUID string as `id`.
///
/// `warranty_expiry` and `last_health_check` are bound from the RFC-3339 strings
/// in the model. `created_at` is left to the DB default (NOW()).
///
/// We `RETURNING` the inserted row so the returned model carries the
/// DB-authoritative values (the response then matches a subsequent `get`).
pub async fn insert(
    executor: impl sqlx::PgExecutor<'_>,
    r: &HardwareAsset,
) -> Result<HardwareAsset, sqlx::Error> {
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
    .fetch_one(executor)
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
    conn: &mut sqlx::PgConnection,
    asset_id: &str,
    version: &str,
    scope_site: &str,
) -> Result<Option<HardwareAsset>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(asset_id) else {
        return Ok(None);
    };

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
    .fetch_optional(&mut *conn)
    .await?;

    let Some(updated) = updated else {
        return Ok(None);
    };

    sqlx::query("INSERT INTO firmware_history (asset_id, version) VALUES ($1, $2)")
        .bind(uid)
        .bind(version)
        .execute(&mut *conn)
        .await?;

    updated.into_model().map(Some)
}

#[cfg(test)]
mod hardware_assets_db_tests {
    use super::*;

    async fn test_pool() -> Option<PgPool> {
        let Ok(url) = std::env::var("RYUKI_DATABASE_URL") else {
            eprintln!("hardware_assets_db_tests: RYUKI_DATABASE_URL not set — skipping");
            return None;
        };
        let pool = PgPool::connect(&url)
            .await
            .expect("RYUKI_DATABASE_URL is set but connection failed");
        crate::database::run_migrations(&pool)
            .await
            .expect("migrations must apply cleanly when RYUKI_DATABASE_URL is set");
        Some(pool)
    }

    /// #14: `list_page` bounds to a LIMIT/OFFSET page, `count` returns the full
    /// filtered total (SAME WHERE), and the unique `ORDER BY … id` keeps offset
    /// pages disjoint. `list` (all rows, used by the aggregate handlers) is left
    /// unpaged.
    #[tokio::test]
    async fn test_list_page_and_count_pagination() {
        let Some(pool) = test_pool().await else {
            return;
        };
        let total = count(&pool, "").await.expect("count all");
        assert!(
            total >= 6,
            "migration seeds >=6 hardware assets, got {total}"
        );
        let all = list_page(&pool, "", 10_000, 0)
            .await
            .expect("list_page all");
        assert_eq!(
            all.len() as i64,
            total,
            "#14: count matches the full unpaged set"
        );
        // `list` (all rows) agrees with the large page — the aggregate path is intact.
        assert_eq!(
            list(&pool, "").await.expect("list all").len(),
            all.len(),
            "list (aggregate path) returns the same rows as an unbounded page"
        );

        // Site-filtered count matches the site page (GBLON has seeded assets).
        let gblon_total = count(&pool, "GBLON").await.expect("count GBLON");
        assert!(gblon_total >= 3, "GBLON has >=3 seeded assets");
        let gblon = list_page(&pool, "GBLON", 10_000, 0)
            .await
            .expect("list_page GBLON");
        assert_eq!(
            gblon.len() as i64,
            gblon_total,
            "#14: site-filtered count matches the site page"
        );

        // LIMIT bounds the page; OFFSET advances it disjointly under ORDER BY id.
        let page1 = list_page(&pool, "", 4, 0).await.expect("page1");
        let page2 = list_page(&pool, "", 4, 4).await.expect("page2");
        assert_eq!(page1.len(), 4, "LIMIT 4 bounds the first page");
        assert!(!page2.is_empty(), "second page continues (>=6 assets)");
        assert!(
            page1.iter().all(|a| page2.iter().all(|b| b.id != a.id)),
            "offset page is disjoint from the first (stable id order)"
        );
    }
}
