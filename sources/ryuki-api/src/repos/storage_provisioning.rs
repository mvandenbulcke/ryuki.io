//! Repository functions for `storage_arrays`, `storage_volumes`, and `storage_requests`.
//!
//! # ID type
//! All three tables use TEXT primary keys (e.g. "arr-defra-001", "vol-defra-001",
//! "sr-defra-001"). Ids are bound and decoded directly as `String`.
//!
//! # Enum encoding
//! All 6 enums derive `#[serde(rename_all = "kebab-case")]`. The DB CHECK constraints
//! store the kebab-case serde form (e.g. "lun", "pure-storage", "healthy").
//! Decode via `enum_from_db` (serde). Write via `enum_to_db`.
//!
//! # Integer widths
//! `size_gb`, `total_capacity_gb`, `used_capacity_gb` are `u64` in the engine
//! but `BIGINT` (i64) in Postgres.
//! Read: `u64::try_from(i64_val)` — negative value is a Decode error.
//! Write: `i64::try_from(u64_val)` — value > i64::MAX is a Decode error (rejected
//! before reaching the DB by handler validation).
//! `pool_count` is `u32` in the engine, `INTEGER` (i32) in Postgres.
//!
//! # TEXT[]
//! `storage_volumes.host_mappings` is `TEXT[]`. sqlx decodes natively into
//! `Vec<String>`. Writes bind a `Vec<String>` slice directly.
//!
//! # provision_volume transaction
//! Atomically: (1) UPDATE storage_arrays capacity (guard: used + size <= total)
//! — zero rows means insufficient capacity or array not found → ProvisionOutcome::InsufficientCapacity;
//! (2) INSERT INTO storage_volumes.
//! Unique violation on (name, site) → caller maps to 409.
//!
//! # extend_volume transaction
//! Atomically: (1) load volume; (2) UPDATE storage_arrays capacity (same guard);
//! (3) UPDATE storage_volumes size_gb.
//! Returns ExtendOutcome to distinguish not-found vs capacity-insufficient.

use ryuki_engine::storage_provisioning::{
    ArrayStatus, ProtectionType, StorageArray, StorageVendor, StorageVolume, VolumeStatus,
    VolumeType,
};
use serde_json::Value;
use sqlx::PgPool;

// ─── Enum helpers ─────────────────────────────────────────────────────────────

fn enum_to_db<T: serde::Serialize>(val: &T) -> String {
    serde_json::to_value(val)
        .expect("enum serialization cannot fail")
        .as_str()
        .expect("enum serde value must be a string")
        .to_owned()
}

fn enum_from_db<T: serde::de::DeserializeOwned>(raw: &str, column: &str) -> Result<T, sqlx::Error> {
    serde_json::from_value(Value::String(raw.to_owned()))
        .map_err(|e| sqlx::Error::Decode(format!("{column}: corrupt value '{raw}': {e}").into()))
}

// ─── Column constants ─────────────────────────────────────────────────────────

const ARRAY_COLUMNS: &str =
    "id, name, vendor, model, site, total_capacity_gb, used_capacity_gb, pool_count, status";

const VOLUME_COLUMNS: &str =
    "id, name, volume_type, size_gb, storage_array, pool, site, host_mappings, protection, status";

// ─── Row structs ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct StorageArrayRow {
    id: String,
    name: String,
    vendor: String,
    model: String,
    site: String,
    total_capacity_gb: i64,
    used_capacity_gb: i64,
    pool_count: i32,
    status: String,
}

impl StorageArrayRow {
    fn into_model(self) -> Result<StorageArray, sqlx::Error> {
        let vendor: StorageVendor = enum_from_db(&self.vendor, "storage_arrays.vendor")?;
        let status: ArrayStatus = enum_from_db(&self.status, "storage_arrays.status")?;
        let total_capacity_gb = u64::try_from(self.total_capacity_gb).map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "storage_arrays.total_capacity_gb: corrupt value {}: {e}",
                    self.total_capacity_gb
                )
                .into(),
            )
        })?;
        let used_capacity_gb = u64::try_from(self.used_capacity_gb).map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "storage_arrays.used_capacity_gb: corrupt value {}: {e}",
                    self.used_capacity_gb
                )
                .into(),
            )
        })?;
        let pool_count = u32::try_from(self.pool_count).map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "storage_arrays.pool_count: corrupt value {}: {e}",
                    self.pool_count
                )
                .into(),
            )
        })?;
        Ok(StorageArray {
            id: self.id,
            name: self.name,
            vendor,
            model: self.model,
            site: self.site,
            total_capacity_gb,
            used_capacity_gb,
            pool_count,
            status,
        })
    }
}

#[derive(sqlx::FromRow)]
struct StorageVolumeRow {
    id: String,
    name: String,
    volume_type: String,
    size_gb: i64,
    storage_array: String,
    pool: String,
    site: String,
    host_mappings: Vec<String>,
    protection: String,
    status: String,
}

impl StorageVolumeRow {
    fn into_model(self) -> Result<StorageVolume, sqlx::Error> {
        let volume_type: VolumeType =
            enum_from_db(&self.volume_type, "storage_volumes.volume_type")?;
        let protection: ProtectionType =
            enum_from_db(&self.protection, "storage_volumes.protection")?;
        let status: VolumeStatus = enum_from_db(&self.status, "storage_volumes.status")?;
        let size_gb = u64::try_from(self.size_gb).map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "storage_volumes.size_gb: corrupt value {}: {e}",
                    self.size_gb
                )
                .into(),
            )
        })?;
        Ok(StorageVolume {
            id: self.id,
            name: self.name,
            volume_type,
            size_gb,
            storage_array: self.storage_array,
            pool: self.pool,
            site: self.site,
            host_mappings: self.host_mappings,
            protection,
            status,
        })
    }
}

// NOTE: storage_requests is seeded (faithful to the engine's original state) but
// no handler exposes requests, so there is intentionally no request row struct /
// read path here. Wire one in if/when a request-listing endpoint is added.

// ─── Outcome types ────────────────────────────────────────────────────────────

/// Outcome of `provision_volume`.
#[derive(Debug)]
pub enum ProvisionOutcome {
    /// Volume created and array capacity decremented.
    Done,
    /// Array capacity was insufficient, or array id not found.
    InsufficientCapacity,
}

/// Outcome of `extend_volume`.
#[derive(Debug)]
pub enum ExtendOutcome {
    /// Volume extended and array capacity decremented.
    Done(StorageVolume),
    /// Volume id not found.
    NotFound,
    /// Array capacity insufficient for the extension.
    InsufficientCapacity,
}

// ─── Read functions ───────────────────────────────────────────────────────────

/// List volumes (optionally site-filtered), bounded to one `LIMIT`/`OFFSET`
/// page (#14). `ORDER BY id` is a unique key, so the page is a stable cut.
pub async fn list_volumes(
    pool: &PgPool,
    site: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<StorageVolume>, sqlx::Error> {
    let rows: Vec<StorageVolumeRow> = if site.is_empty() {
        sqlx::query_as(&format!(
            "SELECT {VOLUME_COLUMNS} FROM storage_volumes ORDER BY id LIMIT $1 OFFSET $2"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {VOLUME_COLUMNS} FROM storage_volumes \
             WHERE site = $1 ORDER BY id LIMIT $2 OFFSET $3"
        ))
        .bind(site)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    };
    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Count volumes (optionally site-filtered) — the pagination total for
/// [`list_volumes`], using the SAME `WHERE` so the count matches the paged set.
pub async fn count_volumes(pool: &PgPool, site: &str) -> Result<i64, sqlx::Error> {
    if site.is_empty() {
        sqlx::query_scalar("SELECT COUNT(*) FROM storage_volumes")
            .fetch_one(pool)
            .await
    } else {
        sqlx::query_scalar("SELECT COUNT(*) FROM storage_volumes WHERE site = $1")
            .bind(site)
            .fetch_one(pool)
            .await
    }
}

pub async fn get_volume(pool: &PgPool, id: &str) -> Result<Option<StorageVolume>, sqlx::Error> {
    let row: Option<StorageVolumeRow> = sqlx::query_as(&format!(
        "SELECT {VOLUME_COLUMNS} FROM storage_volumes WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.map(|r| r.into_model()).transpose()
}

/// List arrays (optionally site-filtered), bounded to one `LIMIT`/`OFFSET`
/// page (#14). `ORDER BY id` is a unique key, so the page is a stable cut.
pub async fn list_arrays(
    pool: &PgPool,
    site: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<StorageArray>, sqlx::Error> {
    let rows: Vec<StorageArrayRow> = if site.is_empty() {
        sqlx::query_as(&format!(
            "SELECT {ARRAY_COLUMNS} FROM storage_arrays ORDER BY id LIMIT $1 OFFSET $2"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {ARRAY_COLUMNS} FROM storage_arrays \
             WHERE site = $1 ORDER BY id LIMIT $2 OFFSET $3"
        ))
        .bind(site)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    };
    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Count arrays (optionally site-filtered) — the pagination total for
/// [`list_arrays`], using the SAME `WHERE` so the count matches the paged set.
pub async fn count_arrays(pool: &PgPool, site: &str) -> Result<i64, sqlx::Error> {
    if site.is_empty() {
        sqlx::query_scalar("SELECT COUNT(*) FROM storage_arrays")
            .fetch_one(pool)
            .await
    } else {
        sqlx::query_scalar("SELECT COUNT(*) FROM storage_arrays WHERE site = $1")
            .bind(site)
            .fetch_one(pool)
            .await
    }
}

pub async fn get_array(pool: &PgPool, id: &str) -> Result<Option<StorageArray>, sqlx::Error> {
    let row: Option<StorageArrayRow> = sqlx::query_as(&format!(
        "SELECT {ARRAY_COLUMNS} FROM storage_arrays WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.map(|r| r.into_model()).transpose()
}

/// Outcome of a storage-array delete.
pub enum ArrayDeleteResult {
    Deleted,
    NotFound,
    /// The array still has `0` < N volumes referencing it; it was not deleted.
    Blocked(i64),
}

/// Register (insert) a freshly-built storage array.
pub async fn create_array(
    executor: impl sqlx::PgExecutor<'_>,
    array: &StorageArray,
) -> Result<(), sqlx::Error> {
    sqlx::query(&format!(
        "INSERT INTO storage_arrays ({ARRAY_COLUMNS}) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
    ))
    .bind(&array.id)
    .bind(&array.name)
    .bind(enum_to_db(&array.vendor))
    .bind(&array.model)
    .bind(&array.site)
    .bind(i64::try_from(array.total_capacity_gb).unwrap_or(i64::MAX))
    .bind(i64::try_from(array.used_capacity_gb).unwrap_or(0))
    .bind(i32::try_from(array.pool_count).unwrap_or(i32::MAX))
    .bind(enum_to_db(&array.status))
    .execute(executor)
    .await?;
    Ok(())
}

/// Update an array's mutable fields. PARTIAL/atomic (`COALESCE` keeps a column
/// when its argument is `None`), so concurrent partial updates do not clobber.
/// The `used <= total` CHECK is the guard against lowering capacity below use —
/// the handler maps that DB check-violation to a 400. Returns the updated array,
/// or `Ok(None)` when no such array exists.
pub async fn update_array(
    executor: impl sqlx::PgExecutor<'_>,
    id: &str,
    model: Option<&str>,
    total_capacity_gb: Option<u64>,
    pool_count: Option<u32>,
    status: Option<&ArrayStatus>,
) -> Result<Option<StorageArray>, sqlx::Error> {
    let row: Option<StorageArrayRow> = sqlx::query_as(&format!(
        "UPDATE storage_arrays SET \
            model = COALESCE($2, model), \
            total_capacity_gb = COALESCE($3, total_capacity_gb), \
            pool_count = COALESCE($4, pool_count), \
            status = COALESCE($5, status), \
            updated_at = NOW() \
         WHERE id = $1 \
         RETURNING {ARRAY_COLUMNS}"
    ))
    .bind(id)
    .bind(model)
    .bind(total_capacity_gb.map(|v| i64::try_from(v).unwrap_or(i64::MAX)))
    .bind(pool_count.map(|v| i32::try_from(v).unwrap_or(i32::MAX)))
    .bind(status.map(enum_to_db))
    .fetch_optional(executor)
    .await?;
    row.map(|r| r.into_model()).transpose()
}

/// Decommission (delete) an array. Refuses (without deleting) when any volume
/// still references it. Runs in a transaction with `FOR UPDATE` on the array
/// row: with the `fk_storage_volumes_array` FK (migration 100), a concurrent
/// volume INSERT takes a KEY SHARE lock on that row which conflicts with this
/// lock, so the count check cannot be raced — and `ON DELETE RESTRICT` is the
/// DB-level backstop. The explicit count gives a clean 409 instead of a raw FK
/// violation.
pub async fn delete_array(
    conn: &mut sqlx::PgConnection,
    id: &str,
) -> Result<ArrayDeleteResult, sqlx::Error> {
    let exists: Option<(String,)> =
        sqlx::query_as("SELECT id FROM storage_arrays WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?;
    if exists.is_none() {
        return Ok(ArrayDeleteResult::NotFound);
    }
    let volume_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM storage_volumes WHERE storage_array = $1")
            .bind(id)
            .fetch_one(&mut *conn)
            .await?;
    if volume_count > 0 {
        return Ok(ArrayDeleteResult::Blocked(volume_count));
    }
    sqlx::query("DELETE FROM storage_arrays WHERE id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    Ok(ArrayDeleteResult::Deleted)
}

pub async fn get_storage_report(
    pool: &PgPool,
    site: &str,
) -> Result<(i64, i64, i64, i64), sqlx::Error> {
    let (total_gb, used_gb, array_count): (Option<i64>, Option<i64>, i64) = if site.is_empty() {
        sqlx::query_as(
            "SELECT SUM(total_capacity_gb)::bigint, SUM(used_capacity_gb)::bigint, COUNT(*) \
             FROM storage_arrays",
        )
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT SUM(total_capacity_gb)::bigint, SUM(used_capacity_gb)::bigint, COUNT(*) \
             FROM storage_arrays WHERE site = $1",
        )
        .bind(site)
        .fetch_one(pool)
        .await?
    };
    let (volume_count,): (i64,) = if site.is_empty() {
        sqlx::query_as("SELECT COUNT(*) FROM storage_volumes")
            .fetch_one(pool)
            .await?
    } else {
        sqlx::query_as("SELECT COUNT(*) FROM storage_volumes WHERE site = $1")
            .bind(site)
            .fetch_one(pool)
            .await?
    };
    Ok((
        total_gb.unwrap_or(0),
        used_gb.unwrap_or(0),
        volume_count,
        array_count,
    ))
}

// ─── Write functions ──────────────────────────────────────────────────────────

/// Atomically provision a volume:
/// 1. UPDATE storage_arrays: increment used_capacity_gb (with guard).
/// 2. INSERT INTO storage_volumes.
///
/// Returns `InsufficientCapacity` when the array is not found or has insufficient capacity.
/// Unique violation on (name, site) is propagated as `sqlx::Error` (handler maps to 409).
pub async fn provision_volume(
    db: &PgPool,
    volume: &StorageVolume,
) -> Result<ProvisionOutcome, sqlx::Error> {
    let size_i64 = i64::try_from(volume.size_gb).map_err(|e| {
        sqlx::Error::Decode(
            format!(
                "storage_volumes.size_gb: value {} out of i64 range: {e}",
                volume.size_gb
            )
            .into(),
        )
    })?;

    let mut tx = db.begin().await?;

    // Step 1: capacity guard UPDATE
    let updated = sqlx::query(
        "UPDATE storage_arrays \
         SET used_capacity_gb = used_capacity_gb + $1, updated_at = NOW() \
         WHERE id = $2 AND used_capacity_gb <= total_capacity_gb - $1",
    )
    .bind(size_i64)
    .bind(&volume.storage_array)
    .execute(&mut *tx)
    .await?;

    if updated.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(ProvisionOutcome::InsufficientCapacity);
    }

    // Step 2: INSERT volume
    sqlx::query(
        "INSERT INTO storage_volumes \
         (id, name, volume_type, size_gb, storage_array, pool, site, host_mappings, protection, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(&volume.id)
    .bind(&volume.name)
    .bind(enum_to_db(&volume.volume_type))
    .bind(size_i64)
    .bind(&volume.storage_array)
    .bind(&volume.pool)
    .bind(&volume.site)
    .bind(&volume.host_mappings)
    .bind(enum_to_db(&volume.protection))
    .bind(enum_to_db(&volume.status))
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(ProvisionOutcome::Done)
}

/// Atomically extend a volume's size_gb and increment array used_capacity_gb.
pub async fn extend_volume(
    db: &PgPool,
    id: &str,
    additional_gb: u64,
) -> Result<ExtendOutcome, sqlx::Error> {
    let additional_i64 = i64::try_from(additional_gb).map_err(|e| {
        sqlx::Error::Decode(
            format!(
                "extend_volume: additional_gb {} out of i64 range: {e}",
                additional_gb
            )
            .into(),
        )
    })?;

    let mut tx = db.begin().await?;

    // Step 1: load + LOCK the volume row (FOR UPDATE) to serialize concurrent
    // extends of the same volume, so the size increment below can't be lost.
    let row: Option<StorageVolumeRow> = sqlx::query_as(&format!(
        "SELECT {VOLUME_COLUMNS} FROM storage_volumes WHERE id = $1 FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(row) = row else {
        tx.rollback().await?;
        return Ok(ExtendOutcome::NotFound);
    };
    let volume = row.into_model()?;

    // Step 2: capacity guard UPDATE on the array
    let updated = sqlx::query(
        "UPDATE storage_arrays \
         SET used_capacity_gb = used_capacity_gb + $1, updated_at = NOW() \
         WHERE id = $2 AND used_capacity_gb <= total_capacity_gb - $1",
    )
    .bind(additional_i64)
    .bind(&volume.storage_array)
    .execute(&mut *tx)
    .await?;

    if updated.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(ExtendOutcome::InsufficientCapacity);
    }

    // Step 3: increment the volume size IN SQL (size_gb = size_gb + $1), NOT a
    // precomputed value, so two concurrent extends can't write the same result
    // and lose one increment. (The FOR UPDATE lock above already serializes them;
    // the in-SQL increment is correct regardless.)
    let updated_row: StorageVolumeRow = sqlx::query_as(&format!(
        "UPDATE storage_volumes \
         SET size_gb = size_gb + $1, status = 'available', updated_at = NOW() \
         WHERE id = $2 \
         RETURNING {VOLUME_COLUMNS}"
    ))
    .bind(additional_i64)
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(ExtendOutcome::Done(updated_row.into_model()?))
}

/// Add a hostname to volume's host_mappings and set status to 'mounted'.
/// Returns Ok(None) when the volume is not found.
pub async fn map_volume(
    pool: &PgPool,
    id: &str,
    hostname: &str,
) -> Result<Option<StorageVolume>, sqlx::Error> {
    let row: Option<StorageVolumeRow> = sqlx::query_as(&format!(
        "UPDATE storage_volumes \
         SET host_mappings = array_append(array_remove(host_mappings, $1::text), $1::text), \
             status = 'mounted', \
             updated_at = NOW() \
         WHERE id = $2 \
         RETURNING {VOLUME_COLUMNS}"
    ))
    .bind(hostname)
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.map(|r| r.into_model()).transpose()
}

/// Remove a hostname from volume's host_mappings; if mappings become empty, set status to 'available'.
/// Returns Ok(None) when the volume is not found.
pub async fn unmap_volume(
    pool: &PgPool,
    id: &str,
    hostname: &str,
) -> Result<Option<StorageVolume>, sqlx::Error> {
    let row: Option<StorageVolumeRow> = sqlx::query_as(&format!(
        "UPDATE storage_volumes \
         SET host_mappings = array_remove(host_mappings, $1::text), \
             status = CASE \
                 WHEN cardinality(array_remove(host_mappings, $1::text)) = 0 THEN 'available' \
                 ELSE status \
             END, \
             updated_at = NOW() \
         WHERE id = $2 \
         RETURNING {VOLUME_COLUMNS}"
    ))
    .bind(hostname)
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.map(|r| r.into_model()).transpose()
}

/// Set volume status to 'retiring'.
/// Returns Ok(None) when the volume is not found.
pub async fn retire_volume(pool: &PgPool, id: &str) -> Result<Option<StorageVolume>, sqlx::Error> {
    let row: Option<StorageVolumeRow> = sqlx::query_as(&format!(
        "UPDATE storage_volumes \
         SET status = 'retiring', updated_at = NOW() \
         WHERE id = $1 \
         RETURNING {VOLUME_COLUMNS}"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.map(|r| r.into_model()).transpose()
}

// Helper trait so tests can call .into_done() on ProvisionOutcome
// without a match in every test.
#[cfg(test)]
trait ProvisionDone {
    fn into_done(self);
}
#[cfg(test)]
impl ProvisionDone for ProvisionOutcome {
    fn into_done(self) {
        assert!(
            matches!(self, ProvisionOutcome::Done),
            "expected ProvisionOutcome::Done"
        );
    }
}

// ─── DB integration tests ─────────────────────────────────────────────────────
//
// Run with:
//   RYUKI_DATABASE_URL=postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform \
//     cargo test -p ryuki-api --lib -- --test-threads=1 storage_provisioning_db_tests
//
// Tests SKIP when RYUKI_DATABASE_URL is unset.
#[cfg(test)]
mod storage_provisioning_db_tests {
    use super::*;
    use ryuki_engine::storage_provisioning::{
        ArrayStatus, ProtectionType, StorageVendor, VolumeStatus, VolumeType,
    };
    use uuid::Uuid;

    async fn test_pool() -> Option<PgPool> {
        let url = match std::env::var("RYUKI_DATABASE_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("storage_provisioning_db_tests: RYUKI_DATABASE_URL not set — skipping");
                return None;
            }
        };
        let db = PgPool::connect(&url)
            .await
            .expect("RYUKI_DATABASE_URL is set but connection failed");
        crate::database::run_migrations(&db)
            .await
            .expect("migrations must apply cleanly");
        Some(db)
    }

    fn sfx() -> String {
        Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("x")
            .to_owned()
    }

    #[tokio::test]
    async fn test_list_and_count_seeded_volumes() {
        let Some(db) = test_pool().await else {
            return;
        };
        let all = list_volumes(&db, "", 1000, 0)
            .await
            .expect("list_volumes all failed");
        assert!(all.len() >= 6, "migration 080 seeds 6 volumes");
        assert_eq!(
            count_volumes(&db, "").await.expect("count_volumes all"),
            all.len() as i64,
            "#14: count_volumes matches the full unpaged set"
        );

        let defra = list_volumes(&db, "DEFRA", 1000, 0)
            .await
            .expect("list_volumes DEFRA failed");
        assert_eq!(defra.len(), 2, "DEFRA has 2 seeded volumes");
        assert_eq!(
            count_volumes(&db, "DEFRA")
                .await
                .expect("count_volumes DEFRA"),
            2,
            "#14: site-filtered count matches the site page"
        );

        // #14 pagination: LIMIT bounds the page; OFFSET advances it; the
        // `ORDER BY id` tie-breaker makes the two pages disjoint and stable.
        let page1 = list_volumes(&db, "", 3, 0).await.expect("page1");
        let page2 = list_volumes(&db, "", 3, 3).await.expect("page2");
        assert_eq!(page1.len(), 3, "LIMIT 3 bounds the first page");
        assert!(
            !page2.is_empty() && page2.len() <= 3,
            "second page continues"
        );
        assert!(
            page1.iter().all(|v| page2.iter().all(|w| w.id != v.id)),
            "offset page is disjoint from the first (stable id order)"
        );
    }

    #[tokio::test]
    async fn test_get_volume_and_absent() {
        let Some(db) = test_pool().await else {
            return;
        };
        let v = get_volume(&db, "vol-defra-001")
            .await
            .expect("get_volume failed")
            .expect("vol-defra-001 must be present");
        assert_eq!(v.site, "DEFRA");
        assert_eq!(v.volume_type, VolumeType::Lun);
        assert!(v.host_mappings.contains(&"defra-db-01".to_string()));
        assert!(v.host_mappings.contains(&"defra-db-02".to_string()));

        let absent = get_volume(&db, "vol-nonexistent")
            .await
            .expect("must not error for absent");
        assert!(absent.is_none());
    }

    #[tokio::test]
    async fn test_list_and_count_seeded_arrays() {
        let Some(db) = test_pool().await else {
            return;
        };
        let all = list_arrays(&db, "", 1000, 0)
            .await
            .expect("list_arrays all failed");
        assert!(all.len() >= 3, "migration 080 seeds 3 arrays");
        assert_eq!(
            count_arrays(&db, "").await.expect("count_arrays all"),
            all.len() as i64,
            "#14: count_arrays matches the full unpaged set"
        );

        let gblon = list_arrays(&db, "GBLON", 1000, 0)
            .await
            .expect("list_arrays GBLON failed");
        assert_eq!(gblon.len(), 1, "GBLON has 1 seeded array");

        // #14 pagination: a LIMIT-1 page returns one row and OFFSET advances.
        let a0 = list_arrays(&db, "", 1, 0).await.expect("array page0");
        let a1 = list_arrays(&db, "", 1, 1).await.expect("array page1");
        assert_eq!(a0.len(), 1, "LIMIT 1 bounds the page");
        assert_eq!(a1.len(), 1, "OFFSET 1 still returns a row (>=3 seeded)");
        assert_ne!(a0[0].id, a1[0].id, "offset advances past the first row");
    }

    #[tokio::test]
    async fn test_get_array_and_absent() {
        let Some(db) = test_pool().await else {
            return;
        };
        let arr = get_array(&db, "arr-defra-001")
            .await
            .expect("get_array failed")
            .expect("arr-defra-001 must be present");
        assert_eq!(arr.site, "DEFRA");
        assert_eq!(arr.vendor, StorageVendor::PureStorage);
        assert_eq!(arr.total_capacity_gb, 20480);
        assert_eq!(arr.used_capacity_gb, 3072);

        let absent = get_array(&db, "arr-nonexistent")
            .await
            .expect("must not error for absent");
        assert!(absent.is_none());
    }

    #[tokio::test]
    async fn test_array_register_update_delete_lifecycle() {
        let Some(db) = test_pool().await else {
            return;
        };
        let sfx = Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("x")
            .to_owned();
        let array = ryuki_engine::storage_provisioning::build_storage_array(
            &format!("test-array-{sfx}"),
            "PureStorage",
            "FlashArray//X",
            "TESTSITE",
            50_000,
        )
        .expect("build");
        let id = array.id.clone();
        let mut tx = db.begin().await.expect("begin");
        create_array(&mut *tx, &array).await.expect("create");
        tx.commit().await.expect("commit");

        // Partial update: model + capacity + status; pool_count omitted stays 0.
        let updated = update_array(
            &db,
            &id,
            Some("FlashArray//XL"),
            Some(80_000),
            None,
            Some(&ArrayStatus::Degraded),
        )
        .await
        .expect("update")
        .expect("present");
        assert_eq!(updated.model, "FlashArray//XL");
        assert_eq!(updated.total_capacity_gb, 80_000);
        assert_eq!(updated.status, ArrayStatus::Degraded);
        assert_eq!(updated.pool_count, 0, "omitted field preserved");

        // A volume referencing the array blocks the delete.
        let vol_id = format!("vol-test-{sfx}");
        sqlx::query(
            "INSERT INTO storage_volumes \
             (id, name, volume_type, size_gb, storage_array, pool, site, protection, status) \
             VALUES ($1, 'v', 'lun', 10, $2, 'p', 'TESTSITE', 'none', 'available')",
        )
        .bind(&vol_id)
        .bind(&id)
        .execute(&db)
        .await
        .unwrap();
        let mut tx = db.begin().await.expect("begin");
        match delete_array(&mut tx, &id).await.expect("delete-blocked") {
            ArrayDeleteResult::Blocked(n) => {
                tx.rollback().await.ok();
                assert_eq!(n, 1);
            }
            _ => panic!("delete must be blocked while a volume references the array"),
        }

        // Retire the volume, then the delete succeeds.
        sqlx::query("DELETE FROM storage_volumes WHERE id = $1")
            .bind(&vol_id)
            .execute(&db)
            .await
            .unwrap();
        let mut tx2 = db.begin().await.expect("begin");
        assert!(matches!(
            delete_array(&mut tx2, &id).await.expect("delete"),
            ArrayDeleteResult::Deleted
        ));
        tx2.commit().await.expect("commit");
        let mut tx3 = db.begin().await.expect("begin");
        assert!(matches!(
            delete_array(&mut tx3, &id).await.expect("delete-absent"),
            ArrayDeleteResult::NotFound
        ));
        tx3.rollback().await.ok();
    }

    #[tokio::test]
    async fn test_enum_roundtrip_vendor_and_host_mappings() {
        let Some(db) = test_pool().await else {
            return;
        };
        // DellEMC -> serde -> 'dell-emc' -> DB -> serde -> DellEmc
        let gblon = get_array(&db, "arr-gblon-001")
            .await
            .expect("get_array failed")
            .expect("arr-gblon-001 must be present");
        assert_eq!(gblon.vendor, StorageVendor::DellEmc);
        assert_eq!(gblon.status, ArrayStatus::Degraded);

        // NetApp
        let frpar = get_array(&db, "arr-frpar-001")
            .await
            .expect("get_array failed")
            .expect("arr-frpar-001 must be present");
        assert_eq!(frpar.vendor, StorageVendor::NetApp);

        // host_mappings TEXT[] round-trip
        let v = get_volume(&db, "vol-defra-001")
            .await
            .expect("get_volume failed")
            .unwrap();
        assert!(v.host_mappings.contains(&"defra-db-01".to_string()));
        assert!(v.host_mappings.contains(&"defra-db-02".to_string()));
        assert_eq!(v.protection, ProtectionType::Raid);

        // Object volume: empty host_mappings + 'none' protection
        let obj = get_volume(&db, "vol-gblon-002")
            .await
            .expect("get_volume failed")
            .unwrap();
        assert!(obj.host_mappings.is_empty());
        assert_eq!(obj.protection, ProtectionType::None);
        assert_eq!(obj.volume_type, VolumeType::Object);
    }

    #[tokio::test]
    async fn test_provision_volume_success_and_capacity_decrement() {
        let Some(db) = test_pool().await else {
            return;
        };
        let sfx = sfx();
        let array_before = get_array(&db, "arr-frpar-001")
            .await
            .expect("get_array")
            .unwrap();
        let avail_before = ryuki_engine::storage_provisioning::available_capacity_gb(&array_before);

        let volume = ryuki_engine::storage_provisioning::build_volume(
            &format!("frpar-test-vol-{sfx}"),
            128,
            ryuki_engine::storage_provisioning::VolumeType::Lun,
            "arr-frpar-001",
            "FRPAR",
        );
        let vol_id = volume.id.clone();

        let outcome = provision_volume(&db, &volume)
            .await
            .expect("provision_volume failed");
        assert!(matches!(outcome, ProvisionOutcome::Done));

        // Array capacity must have decremented by 128
        let array_after = get_array(&db, "arr-frpar-001")
            .await
            .expect("get_array after")
            .unwrap();
        assert_eq!(
            ryuki_engine::storage_provisioning::available_capacity_gb(&array_after),
            avail_before - 128,
            "array available capacity must decrease by 128"
        );

        // Volume must exist
        let v = get_volume(&db, &vol_id)
            .await
            .expect("get_volume after provision")
            .unwrap();
        assert_eq!(v.size_gb, 128);
        assert_eq!(v.site, "FRPAR");
        assert_eq!(v.status, VolumeStatus::Available);

        // Cleanup
        sqlx::query("DELETE FROM storage_volumes WHERE id = $1")
            .bind(&vol_id)
            .execute(&db)
            .await
            .ok();
        sqlx::query(
            "UPDATE storage_arrays SET used_capacity_gb = used_capacity_gb - 128, \
             updated_at = NOW() WHERE id = 'arr-frpar-001'",
        )
        .execute(&db)
        .await
        .ok();
    }

    #[tokio::test]
    async fn test_provision_volume_insufficient_capacity() {
        let Some(db) = test_pool().await else {
            return;
        };
        let sfx = sfx();
        let volume = ryuki_engine::storage_provisioning::build_volume(
            &format!("test-oversized-{sfx}"),
            999_999_999,
            ryuki_engine::storage_provisioning::VolumeType::Object,
            "arr-defra-001",
            "DEFRA",
        );
        let outcome = provision_volume(&db, &volume)
            .await
            .expect("provision_volume must not error");
        assert!(matches!(outcome, ProvisionOutcome::InsufficientCapacity));
    }

    #[tokio::test]
    async fn test_extend_volume_success_and_not_found() {
        let Some(db) = test_pool().await else {
            return;
        };
        let sfx = sfx();
        // Provision a volume first
        let volume = ryuki_engine::storage_provisioning::build_volume(
            &format!("frpar-extend-test-{sfx}"),
            64,
            ryuki_engine::storage_provisioning::VolumeType::Nfs,
            "arr-frpar-001",
            "FRPAR",
        );
        let vol_id = volume.id.clone();
        provision_volume(&db, &volume)
            .await
            .expect("provision for extend test")
            .into_done();

        // Extend by 64
        match extend_volume(&db, &vol_id, 64)
            .await
            .expect("extend_volume failed")
        {
            ExtendOutcome::Done(v) => {
                assert_eq!(v.size_gb, 128, "volume must have grown to 128 gb");
                assert_eq!(v.status, VolumeStatus::Available);
            }
            other => panic!("expected Done, got {:?}", std::mem::discriminant(&other)),
        }

        // Not found
        let absent = extend_volume(&db, "vol-nonexistent", 64)
            .await
            .expect("must not error");
        assert!(matches!(absent, ExtendOutcome::NotFound));

        // Cleanup
        sqlx::query("DELETE FROM storage_volumes WHERE id = $1")
            .bind(&vol_id)
            .execute(&db)
            .await
            .ok();
        sqlx::query(
            "UPDATE storage_arrays SET used_capacity_gb = used_capacity_gb - 128, \
             updated_at = NOW() WHERE id = 'arr-frpar-001'",
        )
        .execute(&db)
        .await
        .ok();
    }

    #[tokio::test]
    async fn test_extend_volume_insufficient_capacity() {
        let Some(db) = test_pool().await else {
            return;
        };
        let sfx = sfx();
        let volume = ryuki_engine::storage_provisioning::build_volume(
            &format!("frpar-extend-cap-test-{sfx}"),
            64,
            ryuki_engine::storage_provisioning::VolumeType::Lun,
            "arr-frpar-001",
            "FRPAR",
        );
        let vol_id = volume.id.clone();
        provision_volume(&db, &volume)
            .await
            .expect("provision")
            .into_done();

        let result = extend_volume(&db, &vol_id, 999_999_999)
            .await
            .expect("must not error");
        assert!(matches!(result, ExtendOutcome::InsufficientCapacity));

        // Cleanup
        sqlx::query("DELETE FROM storage_volumes WHERE id = $1")
            .bind(&vol_id)
            .execute(&db)
            .await
            .ok();
        sqlx::query(
            "UPDATE storage_arrays SET used_capacity_gb = used_capacity_gb - 64, \
             updated_at = NOW() WHERE id = 'arr-frpar-001'",
        )
        .execute(&db)
        .await
        .ok();
    }

    #[tokio::test]
    async fn test_map_and_unmap_volume() {
        let Some(db) = test_pool().await else {
            return;
        };
        let sfx = sfx();
        let volume = ryuki_engine::storage_provisioning::build_volume(
            &format!("gblon-map-test-{sfx}"),
            64,
            ryuki_engine::storage_provisioning::VolumeType::Nfs,
            "arr-gblon-001",
            "GBLON",
        );
        let vol_id = volume.id.clone();
        provision_volume(&db, &volume)
            .await
            .expect("provision")
            .into_done();

        let mapped = map_volume(&db, &vol_id, "gblon-test-host-01")
            .await
            .expect("map_volume failed")
            .expect("must return volume");
        assert_eq!(mapped.status, VolumeStatus::Mounted);
        assert!(mapped
            .host_mappings
            .contains(&"gblon-test-host-01".to_string()));

        // Map again with same host: must be idempotent (no duplicate)
        let mapped2 = map_volume(&db, &vol_id, "gblon-test-host-01")
            .await
            .expect("map_volume idempotent failed")
            .expect("must return volume");
        assert_eq!(
            mapped2
                .host_mappings
                .iter()
                .filter(|h| *h == "gblon-test-host-01")
                .count(),
            1
        );

        let unmapped = unmap_volume(&db, &vol_id, "gblon-test-host-01")
            .await
            .expect("unmap_volume failed")
            .expect("must return volume");
        assert!(unmapped.host_mappings.is_empty());
        assert_eq!(unmapped.status, VolumeStatus::Available);

        // Absent volume: None
        let absent = map_volume(&db, "vol-nonexistent", "host")
            .await
            .expect("must not error");
        assert!(absent.is_none());

        // Cleanup
        sqlx::query("DELETE FROM storage_volumes WHERE id = $1")
            .bind(&vol_id)
            .execute(&db)
            .await
            .ok();
        sqlx::query(
            "UPDATE storage_arrays SET used_capacity_gb = used_capacity_gb - 64, \
             updated_at = NOW() WHERE id = 'arr-gblon-001'",
        )
        .execute(&db)
        .await
        .ok();
    }

    #[tokio::test]
    async fn test_retire_volume() {
        let Some(db) = test_pool().await else {
            return;
        };
        let sfx = sfx();
        let volume = ryuki_engine::storage_provisioning::build_volume(
            &format!("defra-retire-test-{sfx}"),
            64,
            ryuki_engine::storage_provisioning::VolumeType::Cifs,
            "arr-defra-001",
            "DEFRA",
        );
        let vol_id = volume.id.clone();
        provision_volume(&db, &volume)
            .await
            .expect("provision")
            .into_done();

        let retired = retire_volume(&db, &vol_id)
            .await
            .expect("retire_volume failed")
            .expect("must return volume");
        assert_eq!(retired.status, VolumeStatus::Retiring);

        let absent = retire_volume(&db, "vol-nonexistent")
            .await
            .expect("must not error");
        assert!(absent.is_none());

        // Cleanup
        sqlx::query("DELETE FROM storage_volumes WHERE id = $1")
            .bind(&vol_id)
            .execute(&db)
            .await
            .ok();
        sqlx::query(
            "UPDATE storage_arrays SET used_capacity_gb = used_capacity_gb - 64, \
             updated_at = NOW() WHERE id = 'arr-defra-001'",
        )
        .execute(&db)
        .await
        .ok();
    }

    #[tokio::test]
    async fn test_check_capacity_via_get_array() {
        let Some(db) = test_pool().await else {
            return;
        };
        let arr = get_array(&db, "arr-defra-001")
            .await
            .expect("get_array")
            .unwrap();
        let result = ryuki_engine::storage_provisioning::check_capacity(&arr, 1024);
        assert_eq!(result["array_id"], "arr-defra-001");
        assert_eq!(result["can_provision"], true);

        let absent = get_array(&db, "arr-nonexistent")
            .await
            .expect("must not error");
        assert!(absent.is_none());
    }

    #[tokio::test]
    async fn test_unique_name_site_violation() {
        let Some(db) = test_pool().await else {
            return;
        };
        let sfx = sfx();
        let name = format!("defra-unique-test-{sfx}");
        let v1 = ryuki_engine::storage_provisioning::build_volume(
            &name,
            64,
            ryuki_engine::storage_provisioning::VolumeType::Lun,
            "arr-defra-001",
            "DEFRA",
        );
        let v2 = ryuki_engine::storage_provisioning::build_volume(
            &name,
            64,
            ryuki_engine::storage_provisioning::VolumeType::Nfs,
            "arr-defra-001",
            "DEFRA",
        );
        let id1 = v1.id.clone();
        let id2 = v2.id.clone();

        provision_volume(&db, &v1)
            .await
            .expect("first provision")
            .into_done();

        let err = provision_volume(&db, &v2)
            .await
            .expect_err("duplicate name+site must error");
        assert!(
            err.as_database_error()
                .map(|d| d.is_unique_violation())
                .unwrap_or(false),
            "expected unique-violation on (name, site), got: {err:?}"
        );

        // Cleanup
        for id in [&id1, &id2] {
            sqlx::query("DELETE FROM storage_volumes WHERE id = $1")
                .bind(id)
                .execute(&db)
                .await
                .ok();
        }
        sqlx::query(
            "UPDATE storage_arrays SET used_capacity_gb = used_capacity_gb - 64, \
             updated_at = NOW() WHERE id = 'arr-defra-001'",
        )
        .execute(&db)
        .await
        .ok();
    }

    #[tokio::test]
    async fn test_storage_report() {
        let Some(db) = test_pool().await else {
            return;
        };
        let (total, used, vols, arrs) = get_storage_report(&db, "FRPAR")
            .await
            .expect("get_storage_report failed");
        assert_eq!(arrs, 1, "FRPAR has 1 array");
        assert!(vols >= 2, "FRPAR has at least 2 volumes");
        assert!(total >= used, "total >= used");
        assert_eq!(total, 24576);

        let (all_total, all_used, all_vols, all_arrs) = get_storage_report(&db, "")
            .await
            .expect("report all failed");
        assert!(all_arrs >= 3);
        assert!(all_vols >= 6);
        assert!(all_total >= all_used);
    }
}
