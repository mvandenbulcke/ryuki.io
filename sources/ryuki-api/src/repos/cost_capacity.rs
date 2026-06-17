//! Repository functions for `vm_utilization`.
//!
//! All functions are pure over `&PgPool`; callers (handlers in `contracts.rs`)
//! are responsible for mapping `sqlx::Error` → 500.
//!
//! # Column rename
//! DB column `cluster_name` is mapped to model field `cluster` via
//! `cluster_name AS cluster` in SELECT. The model has no `id` field, so `id`
//! is deliberately excluded from the SELECT column list.
//!
//! # NUMERIC ↔ f64
//! `cpu_usage_pct`, `memory_usage_pct`, and `monthly_cost` are NUMERIC in the
//! DB. They are cast to `::float8` in SELECT so sqlx decodes them as `f64`.
//! There are no write operations in this batch — all handlers are reads.
//!
//! # Integer coercion
//! `cpu_cores`, `memory_gb`, `storage_gb`, and `orphaned_disk_gb` are stored
//! as DB `INTEGER` (decoded as Rust `i32`). They are coerced to `u32` via
//! `u32::try_from`; a negative value in the DB is surfaced as a decode error
//! (caller → 500) rather than silently wrapping via `as`.

use ryuki_engine::cost_capacity::VmUtilization;
use sqlx::PgPool;

// ─── Column list ──────────────────────────────────────────────────────────────

/// SELECT column list for `vm_utilization`.
/// - `id` is excluded — the engine model has no id field.
/// - `cluster_name` is aliased to `cluster` to match the model field.
/// - NUMERIC columns cast to `::float8` for direct `f64` decode.
pub const COLUMNS: &str = "vm_name, \
     site, \
     cluster_name AS cluster, \
     cpu_cores, \
     memory_gb, \
     storage_gb, \
     cpu_usage_pct::float8 AS cpu_usage_pct, \
     memory_usage_pct::float8 AS memory_usage_pct, \
     monthly_cost::float8 AS monthly_cost, \
     idle, \
     oversized, \
     orphaned_disk_gb";

// ─── Row struct ───────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct VmUtilizationRow {
    pub vm_name: String,
    pub site: String,
    pub cluster: String,
    pub cpu_cores: i32,
    pub memory_gb: i32,
    pub storage_gb: i32,
    pub cpu_usage_pct: f64,
    pub memory_usage_pct: f64,
    pub monthly_cost: f64,
    pub idle: bool,
    pub oversized: bool,
    pub orphaned_disk_gb: i32,
}

impl VmUtilizationRow {
    /// Convert a DB row into the engine `VmUtilization` model.
    ///
    /// Integer fields are coerced from `i32` (DB INTEGER) to `u32` via
    /// `u32::try_from`. A negative value means the persisted row is corrupt;
    /// we surface it as a decode error (caller → 500) rather than silently
    /// wrapping with `as`.
    pub fn into_model(self) -> Result<VmUtilization, sqlx::Error> {
        let cpu_cores = u32::try_from(self.cpu_cores).map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "vm_utilization.cpu_cores: negative value {}: {e}",
                    self.cpu_cores
                )
                .into(),
            )
        })?;
        let memory_gb = u32::try_from(self.memory_gb).map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "vm_utilization.memory_gb: negative value {}: {e}",
                    self.memory_gb
                )
                .into(),
            )
        })?;
        let storage_gb = u32::try_from(self.storage_gb).map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "vm_utilization.storage_gb: negative value {}: {e}",
                    self.storage_gb
                )
                .into(),
            )
        })?;
        let orphaned_disk_gb = u32::try_from(self.orphaned_disk_gb).map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "vm_utilization.orphaned_disk_gb: negative value {}: {e}",
                    self.orphaned_disk_gb
                )
                .into(),
            )
        })?;

        Ok(VmUtilization {
            vm_name: self.vm_name,
            site: self.site,
            cluster: self.cluster,
            cpu_cores,
            memory_gb,
            storage_gb,
            cpu_usage_pct: self.cpu_usage_pct,
            memory_usage_pct: self.memory_usage_pct,
            monthly_cost: self.monthly_cost,
            idle: self.idle,
            oversized: self.oversized,
            orphaned_disk_gb,
        })
    }
}

// ─── Repository functions ─────────────────────────────────────────────────────

/// Return all VMs for a given site, ordered by `vm_name` for determinism.
pub async fn list_vms_for_site(
    pool: &PgPool,
    site: &str,
) -> Result<Vec<VmUtilization>, sqlx::Error> {
    let rows: Vec<VmUtilizationRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM vm_utilization WHERE site = $1 ORDER BY vm_name"
    ))
    .bind(site)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Return all VMs across all sites, ordered by `site, vm_name` for determinism.
#[allow(dead_code)]
pub async fn list_all_vms(pool: &PgPool) -> Result<Vec<VmUtilization>, sqlx::Error> {
    let rows: Vec<VmUtilizationRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM vm_utilization ORDER BY site, vm_name"
    ))
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

// ─── Pure unit tests for VmUtilizationRow::into_model ────────────────────────
//
// No DB, no global_pool — construct VmUtilizationRow directly and verify the
// coercion logic.
#[cfg(test)]
mod into_model_tests {
    use super::*;

    fn valid_row() -> VmUtilizationRow {
        VmUtilizationRow {
            vm_name: "test-vm-01".to_string(),
            site: "TESTSITE".to_string(),
            cluster: "test-general-cluster".to_string(),
            cpu_cores: 4,
            memory_gb: 16,
            storage_gb: 100,
            cpu_usage_pct: 42.5,
            memory_usage_pct: 55.0,
            monthly_cost: 291.40,
            idle: false,
            oversized: false,
            orphaned_disk_gb: 0,
        }
    }

    /// (a) Negative cpu_cores must surface as a Decode error, not wrap silently.
    #[test]
    fn negative_cpu_cores_returns_decode_error() {
        let mut row = valid_row();
        row.cpu_cores = -1;
        let result = row.into_model();
        assert!(
            result.is_err(),
            "into_model must return Err for negative cpu_cores"
        );
        match result.unwrap_err() {
            sqlx::Error::Decode(_) => {}
            other => panic!("expected Decode error, got {other:?}"),
        }
    }

    /// (b) Valid row must decode monthly_cost and cluster field correctly.
    #[test]
    fn valid_row_decodes_monthly_cost_and_cluster() {
        let row = valid_row();
        let vm = row
            .into_model()
            .expect("valid row must decode without error");
        assert!(
            (vm.monthly_cost - 291.40).abs() < 0.001,
            "monthly_cost must round-trip as f64; got {}",
            vm.monthly_cost
        );
        assert_eq!(
            vm.cluster, "test-general-cluster",
            "cluster field must be preserved from the row"
        );
        assert_eq!(vm.cpu_cores, 4u32);
        assert_eq!(vm.memory_gb, 16u32);
        assert_eq!(vm.storage_gb, 100u32);
    }
}

// ─── DB integration tests ─────────────────────────────────────────────────────
//
// Run with:
//   RYUKI_DATABASE_URL=postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform \
//     cargo test -p ryuki-api -- --test-threads=1 cost_capacity_db_tests
//
// Tests SKIP when RYUKI_DATABASE_URL is unset; FAIL (panic) if the URL is set
// but connect or migrate fails.
#[cfg(test)]
mod cost_capacity_db_tests {
    use super::*;
    use crate::database::DB_TEST_SERIAL;

    /// Returns a FRESH owned pool per test invocation.
    /// Returns `None` only when `RYUKI_DATABASE_URL` is absent or empty —
    /// tests are skipped in that case. If the URL IS set but connect or
    /// migrate fails, this function panics.
    async fn global_pool() -> Option<PgPool> {
        let url = match std::env::var("RYUKI_DATABASE_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("cost_capacity_db_tests: RYUKI_DATABASE_URL not set — skipping");
                return None;
            }
        };
        let pool = PgPool::connect(&url)
            .await
            .expect("RYUKI_DATABASE_URL is set but connection failed");
        crate::database::run_migrations(&pool)
            .await
            .expect("migrations must apply cleanly when RYUKI_DATABASE_URL is set");
        Some(pool)
    }

    // ─── list_vms_for_site returns seeded rows ────────────────────────────────

    #[tokio::test]
    async fn test_list_vms_for_site_returns_seeded_rows() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        let vms = list_vms_for_site(pool, "DEFRA")
            .await
            .expect("list_vms_for_site DEFRA failed");

        // Migration 021 seeds 10 DEFRA VMs.
        assert!(
            !vms.is_empty(),
            "list_vms_for_site must return at least one row for DEFRA"
        );
        assert!(
            vms.iter().all(|v| v.site == "DEFRA"),
            "all returned rows must belong to DEFRA"
        );
        // Must not return GBLON rows.
        assert!(
            vms.iter().all(|v| v.site != "GBLON"),
            "list_vms_for_site must not return rows from other sites"
        );
    }

    // ─── into_model decodes NUMERIC + int + bool + cluster rename ────────────

    #[tokio::test]
    async fn test_into_model_decodes_seeded_vm() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        // Seeded row: defra-srv-01 / DEFRA / defra-general-cluster / 8 / 32 / 200 / 72.5 / 65.0
        let vms = list_vms_for_site(pool, "DEFRA")
            .await
            .expect("list_vms_for_site failed");

        let vm = vms
            .iter()
            .find(|v| v.vm_name == "defra-srv-01")
            .expect("seeded VM defra-srv-01 not found");

        // cluster_name → cluster rename
        assert_eq!(
            vm.cluster, "defra-general-cluster",
            "cluster_name must be aliased to cluster"
        );
        // NUMERIC → f64 decode
        assert!(
            (vm.cpu_usage_pct - 72.5).abs() < 0.01,
            "cpu_usage_pct NUMERIC→f64 must decode correctly"
        );
        assert!(
            (vm.memory_usage_pct - 65.0).abs() < 0.01,
            "memory_usage_pct NUMERIC→f64 must decode correctly"
        );
        // INTEGER → u32 coercion
        assert_eq!(vm.cpu_cores, 8u32, "cpu_cores must decode as u32");
        assert_eq!(vm.memory_gb, 32u32, "memory_gb must decode as u32");
        assert_eq!(vm.storage_gb, 200u32, "storage_gb must decode as u32");
        // bool
        assert!(!vm.idle, "defra-srv-01 must not be idle");
        assert!(!vm.oversized, "defra-srv-01 must not be oversized");
        assert_eq!(
            vm.orphaned_disk_gb, 0u32,
            "defra-srv-01 must have no orphaned disk"
        );
    }

    // ─── list_all_vms returns rows from all sites ─────────────────────────────

    #[tokio::test]
    async fn test_list_all_vms_non_empty() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        let vms = list_all_vms(pool).await.expect("list_all_vms failed");

        assert!(!vms.is_empty(), "list_all_vms must return at least one row");
        // Migration seeds both DEFRA and GBLON.
        let has_defra = vms.iter().any(|v| v.site == "DEFRA");
        let has_gblon = vms.iter().any(|v| v.site == "GBLON");
        assert!(has_defra, "list_all_vms must include DEFRA rows");
        assert!(has_gblon, "list_all_vms must include GBLON rows");
    }

    // ─── int-coercion round-trip via seeded row with orphaned_disk_gb > 0 ────

    #[tokio::test]
    async fn test_int_coercion_round_trip_orphaned_disk() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        // defra-dev-02 has orphaned_disk_gb = 50 (seeded in migration 021).
        let vms = list_vms_for_site(pool, "DEFRA")
            .await
            .expect("list_vms_for_site failed");

        let vm = vms
            .iter()
            .find(|v| v.vm_name == "defra-dev-02")
            .expect("seeded VM defra-dev-02 not found");

        assert_eq!(
            vm.orphaned_disk_gb, 50u32,
            "orphaned_disk_gb must round-trip as u32"
        );
        // Also verify the idle flag on a known-idle VM.
        assert!(vm.idle, "defra-dev-02 must be idle");
    }
}
