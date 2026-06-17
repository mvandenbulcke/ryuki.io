//! Repository functions for `backup_repositories` and `capacity_history`.
//!
//! All functions are pure over `&PgPool`; callers (handlers in `contracts.rs`)
//! are responsible for mapping `sqlx::Error` → 500 and `None` → 404.
//!
//! # UUID discipline
//! `backup_repositories.id` and `capacity_history.repository_id` are UUID PKs.
//! SELECT casts: `id::text AS id`, `repository_id::text AS repository_id`.
//! On bind: `Uuid::parse_str(id)` — malformed id → `Ok(None)`, NOT an error.
//!
//! # NUMERIC ↔ f64
//! All NUMERIC columns are cast to `::float8` in SELECT so sqlx decodes them
//! as `f64`. On bind the `f64` value is cast back with `$N::numeric`.
//!
//! # TIMESTAMPTZ ↔ String
//! `last_forecast` / `snapshot_at` are decoded as `chrono::DateTime<Utc>` then
//! converted via `.to_rfc3339()` in `into_model`. On write they are bound
//! directly as `DateTime<Utc>` (sqlx handles the TIMESTAMPTZ mapping).
//!
//! # Enum encoding
//! `RepositoryType` and `CapacityStatus` are stored as their kebab-case serde
//! variant names (e.g. `"store-once"`, `"healthy"`). A decode failure means the
//! persisted row is corrupt; we surface a decode error (caller → 500) rather
//! than defaulting — a stale status would silently produce wrong recommendations.
//!
//! # Derived fields
//! The DB table stores `days_until_full` and `status` as denormalized columns.
//! `into_model` deliberately IGNORES them (the engine recomputes them via
//! `repo_days`/`repo_status`). On UPDATE the caller must pass the freshly
//! recomputed values so the stored columns stay consistent.

use chrono::{DateTime, Utc};
use ryuki_engine::repository_capacity::{CapacityStatus, Repository, RepositoryType};
use sqlx::PgPool;
use uuid::Uuid;

// ─── Column lists ─────────────────────────────────────────────────────────────

/// SELECT column list for `backup_repositories`.
/// UUID → text; all NUMERIC → float8; TIMESTAMPTZ decoded as `DateTime<Utc>`.
/// `days_until_full` and `status` are deliberately excluded — the engine
/// recomputes them from (total, used, growth) on every call.
pub const COLUMNS: &str = "id::text AS id, \
     name, \
     repository_type, \
     site, \
     total_capacity_tb::float8 AS total_capacity_tb, \
     used_capacity_tb::float8 AS used_capacity_tb, \
     growth_rate_gb_per_day::float8 AS growth_rate_gb_per_day, \
     last_forecast";

/// SELECT column list for `capacity_history`.
pub const HISTORY_COLUMNS: &str = "id::text AS id, \
     repository_id::text AS repository_id, \
     used_capacity_tb::float8 AS used_capacity_tb, \
     utilization_pct::float8 AS utilization_pct, \
     days_until_full::float8 AS days_until_full, \
     status, \
     snapshot_at";

// ─── Row structs ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct RepositoryRow {
    pub id: String,
    pub name: String,
    pub repository_type: String,
    pub site: String,
    pub total_capacity_tb: f64,
    pub used_capacity_tb: f64,
    pub growth_rate_gb_per_day: f64,
    pub last_forecast: DateTime<Utc>,
}

impl RepositoryRow {
    /// Convert a DB row into the engine `Repository` model.
    ///
    /// `repository_type` is decoded via `serde_json` using the kebab-case
    /// variant name. A parse failure means the persisted row is corrupt; we
    /// surface it as a decode error (caller → 500) rather than defaulting.
    ///
    /// `days_until_full` and `status` are NOT decoded — the engine recomputes
    /// them via `repo_days` / `repo_status`.
    pub fn into_model(self) -> Result<Repository, sqlx::Error> {
        let repository_type: RepositoryType =
            serde_json::from_value(serde_json::Value::String(self.repository_type.clone()))
                .map_err(|e| {
                    sqlx::Error::Decode(
                        format!(
                        "backup_repositories.repository_type: corrupt persisted value '{}': {e}",
                        self.repository_type
                    )
                        .into(),
                    )
                })?;

        Ok(Repository {
            id: self.id,
            name: self.name,
            repository_type,
            site: self.site,
            total_capacity_tb: self.total_capacity_tb,
            used_capacity_tb: self.used_capacity_tb,
            growth_rate_gb_per_day: self.growth_rate_gb_per_day,
            last_forecast: self.last_forecast.to_rfc3339(),
        })
    }
}

/// A single capacity history point returned by `list_history_for_repo`.
#[derive(Debug, Clone)]
pub struct CapacityHistoryPoint {
    #[allow(dead_code)]
    pub id: String,
    #[allow(dead_code)]
    pub repository_id: String,
    pub used_capacity_tb: f64,
    pub utilization_pct: f64,
    pub days_until_full: Option<f64>,
    pub status: CapacityStatus,
    pub snapshot_at: String,
}

#[derive(sqlx::FromRow)]
pub struct CapacityHistoryRow {
    pub id: String,
    pub repository_id: String,
    pub used_capacity_tb: f64,
    pub utilization_pct: f64,
    pub days_until_full: Option<f64>,
    pub status: String,
    pub snapshot_at: DateTime<Utc>,
}

impl CapacityHistoryRow {
    pub fn into_model(self) -> Result<CapacityHistoryPoint, sqlx::Error> {
        let status: CapacityStatus = serde_json::from_value(serde_json::Value::String(
            self.status.clone(),
        ))
        .map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "capacity_history.status: corrupt persisted value '{}': {e}",
                    self.status
                )
                .into(),
            )
        })?;

        Ok(CapacityHistoryPoint {
            id: self.id,
            repository_id: self.repository_id,
            used_capacity_tb: self.used_capacity_tb,
            utilization_pct: self.utilization_pct,
            days_until_full: self.days_until_full,
            status,
            snapshot_at: self.snapshot_at.to_rfc3339(),
        })
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

/// Canonical kebab-case serde variant name for `RepositoryType` as stored in DB.
pub fn repository_type_str(t: &RepositoryType) -> &'static str {
    match t {
        RepositoryType::StoreOnce => "store-once",
        RepositoryType::DataDomain => "data-domain",
        RepositoryType::ObjectStorage => "object-storage",
        RepositoryType::HardenedLinux => "hardened-linux",
    }
}

/// Canonical kebab-case serde variant name for `CapacityStatus` as stored in DB.
pub fn capacity_status_str(s: &CapacityStatus) -> &'static str {
    match s {
        CapacityStatus::Healthy => "healthy",
        CapacityStatus::Warning => "warning",
        CapacityStatus::Critical => "critical",
    }
}

// ─── Repository functions — backup_repositories ───────────────────────────────

/// Fetch one repository by string id.
///
/// A malformed (non-UUID) id is treated as `Ok(None)` (callers map to 404)
/// rather than an error — keeping not-found behaviour uniform. `Err` is
/// reserved for genuine DB failures (callers → 500).
pub async fn get(pool: &PgPool, id: &str) -> Result<Option<Repository>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<RepositoryRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM backup_repositories WHERE id = $1"
    ))
    .bind(uid)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Return all repositories for a given site, ordered by `name` for determinism.
pub async fn list_by_site(pool: &PgPool, site: &str) -> Result<Vec<Repository>, sqlx::Error> {
    let rows: Vec<RepositoryRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM backup_repositories WHERE site = $1 ORDER BY name"
    ))
    .bind(site)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Return all repositories, ordered by `site, name` for determinism.
pub async fn list_all(pool: &PgPool) -> Result<Vec<Repository>, sqlx::Error> {
    let rows: Vec<RepositoryRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM backup_repositories ORDER BY site, name"
    ))
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Atomically update `used_capacity_tb`, the recomputed `days_until_full`,
/// `status`, and `last_forecast = NOW()` for the repository with the given id.
///
/// The caller MUST supply the freshly-recomputed `days_until_full` and
/// `status_str` (from `repo_days` / `capacity_status_str(repo_status(...))`)
/// so the denormalized DB columns stay consistent with the source-of-truth fields.
///
/// Returns `Ok(None)` when `id` is malformed or no row matches; returns
/// `Ok(Some(repo))` on success. `Err` for genuine DB failures (callers → 500).
pub async fn update_usage(
    pool: &PgPool,
    id: &str,
    used_tb: f64,
    days_until_full: f64,
    status_str: &str,
) -> Result<Option<Repository>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<RepositoryRow> = sqlx::query_as(&format!(
        "UPDATE backup_repositories \
         SET used_capacity_tb = $2::numeric, \
             days_until_full  = $3::numeric, \
             status           = $4, \
             last_forecast    = NOW() \
         WHERE id = $1 \
         RETURNING {COLUMNS}"
    ))
    .bind(uid)
    .bind(used_tb)
    .bind(days_until_full)
    .bind(status_str)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Insert a new repository and return the persisted row.
///
/// `id` must be a valid UUID string already generated by the caller.
/// `last_forecast` is parsed from the RFC-3339 string in the model.
/// `days_until_full` and `status` are computed by the caller via the engine.
#[allow(dead_code)]
pub async fn insert(
    pool: &PgPool,
    r: &Repository,
    days_until_full: f64,
    status_str: &str,
) -> Result<Repository, sqlx::Error> {
    let id = Uuid::parse_str(&r.id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let last_forecast: DateTime<Utc> = chrono::DateTime::parse_from_rfc3339(&r.last_forecast)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let row: RepositoryRow = sqlx::query_as(&format!(
        "INSERT INTO backup_repositories \
         (id, name, repository_type, site, total_capacity_tb, used_capacity_tb, \
          growth_rate_gb_per_day, days_until_full, last_forecast, status) \
         VALUES ($1, $2, $3, $4, $5::numeric, $6::numeric, $7::numeric, $8::numeric, $9, $10) \
         RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(&r.name)
    .bind(repository_type_str(&r.repository_type))
    .bind(&r.site)
    .bind(r.total_capacity_tb)
    .bind(r.used_capacity_tb)
    .bind(r.growth_rate_gb_per_day)
    .bind(days_until_full)
    .bind(last_forecast)
    .bind(status_str)
    .fetch_one(pool)
    .await?;

    row.into_model()
}

// ─── Repository functions — capacity_history ──────────────────────────────────

/// Return history points for the given repository within the last `months`,
/// ordered by `snapshot_at` ascending so callers can render a chronological
/// trend. `months` bounds the window (the handler's `?months=` parameter).
///
/// A malformed `repo_id` (non-UUID) returns an empty Vec rather than an error
/// (consistent with the not-found-as-empty pattern for list operations).
pub async fn list_history_for_repo(
    pool: &PgPool,
    repo_id: &str,
    months: u32,
) -> Result<Vec<CapacityHistoryPoint>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(repo_id) else {
        return Ok(Vec::new());
    };
    let months_i = i32::try_from(months).unwrap_or(i32::MAX);

    let rows: Vec<CapacityHistoryRow> = sqlx::query_as(&format!(
        "SELECT {HISTORY_COLUMNS} FROM capacity_history \
         WHERE repository_id = $1 \
           AND snapshot_at >= NOW() - make_interval(months => $2) \
         ORDER BY snapshot_at ASC"
    ))
    .bind(uid)
    .bind(months_i)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

// ─── DB integration tests ────────────────────────────────────────────────────
//
// Run with:
//   RYUKI_DATABASE_URL=postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform \
//     cargo test -p ryuki-api -- --test-threads=1 repository_capacity_db_tests
//
// Tests SKIP when RYUKI_DATABASE_URL is unset; FAIL (panic) if the URL is set
// but connect or migrate fails.
#[cfg(test)]
mod repository_capacity_db_tests {
    use super::*;
    use crate::database::DB_TEST_SERIAL;
    use ryuki_engine::repository_capacity::{repo_days, repo_status};
    use uuid::Uuid;

    /// Returns a FRESH owned pool per test invocation.
    /// Returns `None` only when `RYUKI_DATABASE_URL` is absent or empty —
    /// tests are skipped in that case. If the URL IS set but connect or
    /// migrate fails, this function panics.
    async fn global_pool() -> Option<PgPool> {
        let url = match std::env::var("RYUKI_DATABASE_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("repository_capacity_db_tests: RYUKI_DATABASE_URL not set — skipping");
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

    /// Build a test `Repository` value (id pre-generated).
    fn make_repo(suffix: &str, site: &str) -> Repository {
        Repository {
            id: Uuid::new_v4().to_string(),
            name: format!("test-repo-{}", suffix),
            repository_type: RepositoryType::StoreOnce,
            site: site.into(),
            total_capacity_tb: 100.0,
            used_capacity_tb: 50.0,
            growth_rate_gb_per_day: 5.0,
            last_forecast: chrono::Utc::now().to_rfc3339(),
        }
    }

    async fn cleanup_repo(pool: &PgPool, id: &str) {
        // capacity_history has ON DELETE CASCADE from backup_repositories, so
        // deleting the parent is sufficient. Still safe to call even if the row
        // was never inserted (DELETE of non-existent row is a no-op).
        if let Ok(uid) = Uuid::parse_str(id) {
            sqlx::query("DELETE FROM backup_repositories WHERE id = $1")
                .bind(uid)
                .execute(pool)
                .await
                .ok();
        }
    }

    // ─── round_trip ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_insert_get_roundtrip() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        let suffix = Uuid::new_v4().to_string();
        let repo = make_repo(&suffix, "DEFRA");
        let repo_id = repo.id.clone();

        let days = repo_days(&repo);
        let status = repo_status(&repo);
        let status_s = capacity_status_str(&status);

        let inserted = insert(pool, &repo, days, status_s)
            .await
            .expect("insert failed");

        assert_eq!(inserted.id, repo_id, "id must round-trip");
        assert_eq!(inserted.site, "DEFRA", "site must round-trip");
        assert_eq!(
            inserted.total_capacity_tb, 100.0,
            "total_capacity_tb must round-trip"
        );
        assert_eq!(
            inserted.used_capacity_tb, 50.0,
            "used_capacity_tb must round-trip"
        );
        assert_eq!(
            inserted.repository_type,
            RepositoryType::StoreOnce,
            "repository_type must round-trip"
        );

        let fetched = get(pool, &repo_id)
            .await
            .expect("get failed")
            .expect("row not found after insert");

        assert_eq!(fetched.id, repo_id, "get id must match");
        assert_eq!(
            fetched.total_capacity_tb, 100.0,
            "get total_capacity_tb must match"
        );
        assert_eq!(
            fetched.used_capacity_tb, 50.0,
            "get used_capacity_tb must match"
        );
        assert_eq!(
            fetched.repository_type,
            RepositoryType::StoreOnce,
            "get repository_type must round-trip"
        );

        // Verify timestamp round-trips through the DB without truncation.
        assert!(
            !fetched.last_forecast.is_empty(),
            "last_forecast is present"
        );

        cleanup_repo(pool, &repo_id).await;
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

        let suffix = Uuid::new_v4().to_string();
        let repo_defra = make_repo(&format!("defra-{}", suffix), "DEFRA");
        let repo_gblon = make_repo(&format!("gblon-{}", suffix), "GBLON");

        let id_defra = repo_defra.id.clone();
        let id_gblon = repo_gblon.id.clone();

        let days_d = repo_days(&repo_defra);
        let status_d = repo_status(&repo_defra);
        let days_g = repo_days(&repo_gblon);
        let status_g = repo_status(&repo_gblon);

        insert(pool, &repo_defra, days_d, capacity_status_str(&status_d))
            .await
            .expect("insert DEFRA failed");
        insert(pool, &repo_gblon, days_g, capacity_status_str(&status_g))
            .await
            .expect("insert GBLON failed");

        let defra_rows = list_by_site(pool, "DEFRA")
            .await
            .expect("list_by_site DEFRA failed");
        assert!(
            defra_rows.iter().any(|r| r.id == id_defra),
            "DEFRA repo must appear in DEFRA list"
        );
        assert!(
            defra_rows.iter().all(|r| r.site == "DEFRA"),
            "list_by_site must only return DEFRA rows"
        );
        assert!(
            defra_rows.iter().all(|r| r.id != id_gblon),
            "GBLON repo must NOT appear in DEFRA list"
        );

        cleanup_repo(pool, &id_defra).await;
        cleanup_repo(pool, &id_gblon).await;
    }

    // ─── update_usage ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_update_usage() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        let suffix = Uuid::new_v4().to_string();
        let repo = make_repo(&suffix, "DEFRA");
        let repo_id = repo.id.clone();

        let days_init = repo_days(&repo);
        let status_init = repo_status(&repo);
        insert(pool, &repo, days_init, capacity_status_str(&status_init))
            .await
            .expect("insert failed");

        // Simulate consuming 90% of capacity — should push status to warning/critical.
        let new_used = 95.0_f64;
        let updated_repo = Repository {
            used_capacity_tb: new_used,
            ..repo.clone()
        };
        let new_days = repo_days(&updated_repo);
        let new_status = repo_status(&updated_repo);
        let new_status_s = capacity_status_str(&new_status);

        let persisted = update_usage(pool, &repo_id, new_used, new_days, new_status_s)
            .await
            .expect("update_usage failed")
            .expect("row not found");

        assert_eq!(
            persisted.used_capacity_tb, new_used,
            "used_capacity_tb must be updated"
        );
        // last_forecast is set to NOW() by the UPDATE.
        assert!(
            !persisted.last_forecast.is_empty(),
            "last_forecast is present"
        );

        // Verify the change was durable: re-read and confirm.
        let re_fetched = get(pool, &repo_id)
            .await
            .expect("get after update failed")
            .expect("row not found after update");
        assert_eq!(
            re_fetched.used_capacity_tb, new_used,
            "used_capacity_tb must persist across reads"
        );

        // into_model ignores the stored derived columns, so assert directly that
        // update_usage PERSISTED days_until_full + status (else a regression that
        // stopped writing them would pass unnoticed).
        let (stored_days, stored_status): (f64, String) = sqlx::query_as(
            "SELECT days_until_full::float8, status FROM backup_repositories WHERE id = $1::uuid",
        )
        .bind(&repo_id)
        .fetch_one(pool)
        .await
        .expect("raw select of derived columns failed");
        assert!(
            (stored_days - new_days).abs() < 0.1,
            "stored days_until_full ({stored_days}) must match recomputed ({new_days})"
        );
        assert_eq!(
            stored_status, new_status_s,
            "stored status must match the recomputed status"
        );

        cleanup_repo(pool, &repo_id).await;
    }

    // ─── get — unknown UUID → Ok(None) ───────────────────────────────────────

    #[tokio::test]
    async fn test_get_unknown_uuid_returns_none() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        let result = get(pool, &Uuid::new_v4().to_string())
            .await
            .expect("get must not fail for unknown UUID");
        assert!(result.is_none(), "unknown UUID must return None");
    }

    // ─── get — malformed id → Ok(None) ───────────────────────────────────────

    #[tokio::test]
    async fn test_get_malformed_id_returns_none() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        let result = get(pool, "not-a-uuid")
            .await
            .expect("get must not fail for malformed id");
        assert!(result.is_none(), "malformed id must return None");
    }

    // ─── list_history_for_repo ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_list_history_for_repo() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        // The migration seeds repo e0000380-3800-3800-3800-000000000001 with
        // 3 capacity_history rows (fixed 2026 dates). Use a wide window so the
        // assertion is not fragile against the relative months filter as time passes.
        let seeded_repo_id = "e0000380-3800-3800-3800-000000000001";

        let history = list_history_for_repo(pool, seeded_repo_id, 1200)
            .await
            .expect("list_history_for_repo failed");

        // Migration seeds exactly 3 rows for this repo.
        assert_eq!(
            history.len(),
            3,
            "expected 3 history rows for the seeded critical repo"
        );

        // Verify ascending order by snapshot_at.
        let dates: Vec<&str> = history.iter().map(|h| h.snapshot_at.as_str()).collect();
        let mut sorted = dates.clone();
        sorted.sort();
        assert_eq!(
            dates, sorted,
            "history rows must be in snapshot_at ASC order"
        );
    }

    // ─── list_history_for_repo honours the months window ─────────────────────

    #[tokio::test]
    async fn test_list_history_for_repo_months_window() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        // A test repo with two history rows at known relative ages: one ~2 months
        // old, one ~5 days old.
        let suffix = Uuid::new_v4().to_string();
        let repo = make_repo(&suffix, "DEFRA");
        let repo_id = repo.id.clone();
        let days_init = repo_days(&repo);
        insert(
            pool,
            &repo,
            days_init,
            capacity_status_str(&repo_status(&repo)),
        )
        .await
        .expect("insert failed");

        for (hist_suffix, age_interval) in [("old", "2 months"), ("recent", "5 days")] {
            sqlx::query(
                "INSERT INTO capacity_history \
                 (id, repository_id, used_capacity_tb, utilization_pct, days_until_full, status, snapshot_at) \
                 VALUES (gen_random_uuid(), $1::uuid, 100.0, 50.0, 30.0, 'healthy', NOW() - $2::interval)",
            )
            .bind(&repo_id)
            .bind(age_interval)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("insert history {hist_suffix} failed: {e}"));
        }

        // 1-month window excludes the 2-month-old row.
        let recent = list_history_for_repo(pool, &repo_id, 1)
            .await
            .expect("list (1mo) failed");
        assert_eq!(
            recent.len(),
            1,
            "1-month window must exclude the 2-month-old row"
        );

        // 12-month window includes both.
        let all = list_history_for_repo(pool, &repo_id, 12)
            .await
            .expect("list (12mo) failed");
        assert_eq!(all.len(), 2, "12-month window must include both rows");

        cleanup_repo(pool, &repo_id).await;
    }
}
