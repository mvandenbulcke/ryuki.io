//! Repository functions for `immutability_checks`.
//!
//! All functions are pure over `&PgPool`; callers (handlers in `contracts.rs`)
//! are responsible for mapping `sqlx::Error` → 500 and `None` → 404.
//!
//! # ID type
//! `immutability_checks.id` is a plain `TEXT` primary key (not UUID). IDs are
//! bound and decoded directly as `String` — no `Uuid::parse_str` and no
//! early-return guard for malformed UUIDs.
//!
//! # Enum encoding
//! `repository_type` and `status` are stored as their serde PascalCase variant
//! names (e.g. `"StoreOnce"`, `"Compliant"`). The DB CHECK constraints
//! (migration 037) keep the values in the legal set. A parse failure means the
//! persisted row is corrupt; we surface it as a decode error (caller → 500)
//! rather than substituting a default.
//!
//! # TIMESTAMPTZ ↔ String
//! `last_verified` is decoded as `chrono::DateTime<Utc>` then converted via
//! `.to_rfc3339()` in `into_model`. We do NOT cast `last_verified::text` in the
//! SELECT — Postgres text format is not RFC-3339.
//!
//! # u32 ↔ INTEGER
//! `min_retention_days` is `u32` in the model but `INTEGER` (i32) in the DB.
//! We decode via `u32::try_from(i32)` — a negative value is a Decode error.
//! We do NOT use `as`.

use chrono::{DateTime, Utc};
use ryuki_engine::immutability_compliance::{ComplianceStatus, ImmutabilityCheck, RepositoryType};
use sqlx::PgPool;

// ─── Column list ─────────────────────────────────────────────────────────────

/// SELECT column list. `id` is TEXT so no cast is needed.
/// `last_verified` is TIMESTAMPTZ — decoded as `DateTime<Utc>`, not text.
pub const COLUMNS: &str = "id, \
     repository_name, \
     repository_type, \
     site, \
     immutability_enabled, \
     retention_lock_set, \
     min_retention_days, \
     last_verified, \
     status";

// ─── Row struct ───────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct ImmutabilityCheckRow {
    pub id: String,
    pub repository_name: String,
    pub repository_type: String,
    pub site: String,
    pub immutability_enabled: bool,
    pub retention_lock_set: bool,
    pub min_retention_days: i32,
    pub last_verified: DateTime<Utc>,
    pub status: String,
}

impl ImmutabilityCheckRow {
    /// Convert a DB row into the engine `ImmutabilityCheck` model.
    ///
    /// `repository_type` and `status` are decoded via `serde_json::from_value`
    /// using the stored PascalCase variant name. A parse failure surfaces as a
    /// Decode error (caller → 500) — corrupt values must not silently default.
    ///
    /// `last_verified` is a `DateTime<Utc>` from the DB; we convert to RFC-3339
    /// string for the engine model.
    ///
    /// `min_retention_days` (i32 in DB) is decoded via `u32::try_from` — a
    /// negative value is a Decode error, not silently zeroed.
    pub fn into_model(self) -> Result<ImmutabilityCheck, sqlx::Error> {
        let repository_type: RepositoryType =
            serde_json::from_value(serde_json::Value::String(self.repository_type.clone()))
                .map_err(|e| {
                    sqlx::Error::Decode(
                        format!(
                    "immutability_checks.repository_type: corrupt persisted value '{}': {e}",
                    self.repository_type
                )
                        .into(),
                    )
                })?;

        let status: ComplianceStatus = serde_json::from_value(serde_json::Value::String(
            self.status.clone(),
        ))
        .map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "immutability_checks.status: corrupt persisted value '{}': {e}",
                    self.status
                )
                .into(),
            )
        })?;

        let min_retention_days = u32::try_from(self.min_retention_days).map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "immutability_checks.min_retention_days: negative value {}: {e}",
                    self.min_retention_days
                )
                .into(),
            )
        })?;

        Ok(ImmutabilityCheck {
            id: self.id,
            repository_name: self.repository_name,
            repository_type,
            site: self.site,
            immutability_enabled: self.immutability_enabled,
            retention_lock_set: self.retention_lock_set,
            min_retention_days,
            last_verified: self.last_verified.to_rfc3339(),
            status,
        })
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

/// Canonical serde PascalCase variant name for a `RepositoryType` as stored in
/// the DB. Matches the CHECK constraint values in migration 037.
#[allow(dead_code)]
pub fn repository_type_str(t: &RepositoryType) -> &'static str {
    match t {
        RepositoryType::StoreOnce => "StoreOnce",
        RepositoryType::HardenedLinux => "HardenedLinux",
        RepositoryType::ObjectStorage => "ObjectStorage",
    }
}

/// Canonical serde PascalCase variant name for a `ComplianceStatus` as stored
/// in the DB. Matches the CHECK constraint values in migration 037.
#[allow(dead_code)]
pub fn compliance_status_str(s: &ComplianceStatus) -> &'static str {
    match s {
        ComplianceStatus::Compliant => "Compliant",
        ComplianceStatus::AtRisk => "AtRisk",
        ComplianceStatus::NonCompliant => "NonCompliant",
    }
}

// ─── Repository functions ─────────────────────────────────────────────────────

/// Fetch one immutability check by id. Returns `Ok(None)` when no row is found
/// (caller → 404). `Err` is reserved for genuine DB failures (caller → 500).
///
/// Unlike UUID-keyed repos, there is no malformed-id early return: any string
/// is a valid TEXT key.
pub async fn get(pool: &PgPool, id: &str) -> Result<Option<ImmutabilityCheck>, sqlx::Error> {
    let row: Option<ImmutabilityCheckRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM immutability_checks WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Return all immutability checks for a given site, ordered by `id` for
/// determinism.
pub async fn list_by_site(
    pool: &PgPool,
    site: &str,
) -> Result<Vec<ImmutabilityCheck>, sqlx::Error> {
    let rows: Vec<ImmutabilityCheckRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM immutability_checks WHERE site = $1 ORDER BY id"
    ))
    .bind(site)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Return all immutability checks ordered by `site, id` for determinism.
pub async fn list_all(pool: &PgPool) -> Result<Vec<ImmutabilityCheck>, sqlx::Error> {
    let rows: Vec<ImmutabilityCheckRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM immutability_checks ORDER BY site, id"
    ))
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

// ─── DB integration tests ────────────────────────────────────────────────────
//
// Run with:
//   RYUKI_DATABASE_URL=postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform \
//     cargo test -p ryuki-api -- --test-threads=1 immutability_compliance_db_tests
//
// Tests SKIP when RYUKI_DATABASE_URL is unset; FAIL (panic) if the URL is set
// but connect or migrate fails.
#[cfg(test)]
mod immutability_compliance_db_tests {
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
                eprintln!(
                    "immutability_compliance_db_tests: RYUKI_DATABASE_URL not set — skipping"
                );
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

    // ─── get — seeded row roundtrip ───────────────────────────────────────────

    #[tokio::test]
    async fn test_get_seeded_row_roundtrip() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        // Migration seeds this row: StoreOnce, DEFRA, Compliant, enabled=true,
        // lock=true, min_retention=90.
        let check = get(pool, "imm-00000000-0000-0000-0000-000000000001")
            .await
            .expect("get must not fail")
            .expect("seeded row must be present");

        assert_eq!(check.id, "imm-00000000-0000-0000-0000-000000000001");
        assert_eq!(check.repository_name, "repo-defra-storeonce-01");
        assert_eq!(check.repository_type, RepositoryType::StoreOnce);
        assert_eq!(check.site, "DEFRA");
        assert!(
            check.immutability_enabled,
            "immutability_enabled must be true"
        );
        assert!(check.retention_lock_set, "retention_lock_set must be true");
        assert_eq!(
            check.min_retention_days, 90,
            "min_retention_days must be 90"
        );
        assert_eq!(check.status, ComplianceStatus::Compliant);
        // last_verified must be a non-empty RFC-3339 string.
        assert!(
            !check.last_verified.is_empty(),
            "last_verified must be non-empty"
        );
        // Smoke-test that it parses as RFC-3339 (TIMESTAMPTZ → to_rfc3339 → parseable).
        chrono::DateTime::parse_from_rfc3339(&check.last_verified)
            .expect("last_verified must be valid RFC-3339");
    }

    // ─── into_model — PascalCase enum decode ─────────────────────────────────

    #[tokio::test]
    async fn test_into_model_decodes_known_status_and_type() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        // id 002: HardenedLinux, AtRisk
        let check = get(pool, "imm-00000000-0000-0000-0000-000000000002")
            .await
            .expect("get must not fail")
            .expect("seeded row must be present");
        assert_eq!(check.repository_type, RepositoryType::HardenedLinux);
        assert_eq!(check.status, ComplianceStatus::AtRisk);

        // id 003: ObjectStorage, NonCompliant
        let check = get(pool, "imm-00000000-0000-0000-0000-000000000003")
            .await
            .expect("get must not fail")
            .expect("seeded row must be present");
        assert_eq!(check.repository_type, RepositoryType::ObjectStorage);
        assert_eq!(check.status, ComplianceStatus::NonCompliant);
    }

    // ─── list_by_site ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_list_by_site() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        let defra_rows = list_by_site(pool, "DEFRA")
            .await
            .expect("list_by_site DEFRA must not fail");

        assert!(
            !defra_rows.is_empty(),
            "DEFRA must have at least one seeded row"
        );
        assert!(
            defra_rows.iter().all(|r| r.site == "DEFRA"),
            "list_by_site must only return DEFRA rows"
        );
        // Migration seeds exactly one DEFRA row.
        assert!(
            defra_rows
                .iter()
                .any(|r| r.id == "imm-00000000-0000-0000-0000-000000000001"),
            "seeded DEFRA row must appear"
        );

        let gblon_rows = list_by_site(pool, "GBLON")
            .await
            .expect("list_by_site GBLON must not fail");
        assert!(
            gblon_rows.iter().all(|r| r.site == "GBLON"),
            "GBLON rows must only contain GBLON site"
        );
        assert!(
            gblon_rows
                .iter()
                .all(|r| r.id != "imm-00000000-0000-0000-0000-000000000001"),
            "DEFRA row must NOT appear in GBLON list"
        );
    }

    // ─── list_all — non-empty ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_list_all_non_empty() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        let all = list_all(pool).await.expect("list_all must not fail");

        // Migration seeds 4 rows.
        assert!(
            all.len() >= 4,
            "list_all must return at least 4 seeded rows"
        );

        // All rows must deserialize without error (implicit — into_model was called).
        // Verify ordering: site, id.
        let sites: Vec<&str> = all.iter().map(|r| r.site.as_str()).collect();
        let mut sorted = sites.clone();
        sorted.sort();
        assert_eq!(sites, sorted, "list_all must be ordered by site");
    }

    // ─── get — unknown id → Ok(None) ─────────────────────────────────────────

    #[tokio::test]
    async fn test_get_unknown_id_returns_none() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        let result = get(pool, "imm-nonexistent-id-that-does-not-exist")
            .await
            .expect("get must not fail for unknown id");
        assert!(result.is_none(), "unknown TEXT id must return Ok(None)");
    }
}
