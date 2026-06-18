//! Repository functions for `baseline_checks` and `baseline_results`.
//!
//! All functions are pure over `&PgPool`; callers (handlers in `contracts.rs`)
//! are responsible for mapping `sqlx::Error` → 500 and `None` → 404.
//!
//! # ID type
//! Both `baseline_checks.id` (TEXT PK) and `baseline_results` composite PK
//! columns (`server_name`, `check_id`) are plain TEXT. Ids are bound and decoded
//! directly as `String` — no `Uuid::parse_str` and no early-return guard.
//!
//! # Enum encoding
//! `category` and `severity` are stored as their serde PascalCase variant names
//! (e.g. `"Security"`, `"Critical"`). A parse failure means the persisted row is
//! corrupt; we surface it as a decode error (caller → 500) rather than
//! substituting a default. DB CHECK constraints (migration 068) keep the values in
//! the legal set.
//!
//! # TIMESTAMPTZ ↔ String
//! `last_checked` is decoded as `chrono::DateTime<Utc>` then converted via
//! `.to_rfc3339()` in `into_model`. This avoids locale-sensitive `::text` casts
//! and round-trips cleanly through the DB.

use chrono::{DateTime, Utc};
use ryuki_engine::os_baseline::{
    BaselineCategory, BaselineCheck, BaselineResult, BaselineSeverity,
};
use sqlx::PgPool;

// ─── Column lists ─────────────────────────────────────────────────────────────

/// SELECT column list for `baseline_checks`.
pub const CHECK_COLUMNS: &str = "id, check_name, category, expected_value, severity";

/// SELECT column list for `baseline_results`.
pub const RESULT_COLUMNS: &str =
    "server_name, check_id, compliant, actual_value, last_checked, site";

// ─── Row structs ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct BaselineCheckRow {
    pub id: String,
    pub check_name: String,
    pub category: String,
    pub expected_value: String,
    pub severity: String,
}

impl BaselineCheckRow {
    /// Convert a DB row into the engine `BaselineCheck` model.
    ///
    /// Both enum columns are stored as their serde PascalCase names and decoded
    /// via `serde_json::from_value`. A parse failure is surfaced as a decode
    /// error (caller → 500) rather than substituting a default — the CHECK
    /// constraint in migration 068 is the backstop; a decode error here means
    /// the constraint was somehow bypassed and the row is corrupt.
    pub fn into_model(self) -> Result<BaselineCheck, sqlx::Error> {
        let category: BaselineCategory = serde_json::from_value(serde_json::Value::String(
            self.category.clone(),
        ))
        .map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "baseline_checks.category: corrupt persisted value '{}': {e}",
                    self.category
                )
                .into(),
            )
        })?;

        let severity: BaselineSeverity = serde_json::from_value(serde_json::Value::String(
            self.severity.clone(),
        ))
        .map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "baseline_checks.severity: corrupt persisted value '{}': {e}",
                    self.severity
                )
                .into(),
            )
        })?;

        Ok(BaselineCheck {
            id: self.id,
            check_name: self.check_name,
            category,
            expected_value: self.expected_value,
            severity,
        })
    }
}

#[derive(sqlx::FromRow)]
pub struct BaselineResultRow {
    pub server_name: String,
    pub check_id: String,
    pub compliant: bool,
    pub actual_value: String,
    pub last_checked: DateTime<Utc>,
    pub site: String,
}

impl BaselineResultRow {
    /// Convert a DB row into the engine `BaselineResult` model.
    pub fn into_model(self) -> BaselineResult {
        BaselineResult {
            server_name: self.server_name,
            check_id: self.check_id,
            compliant: self.compliant,
            actual_value: self.actual_value,
            last_checked: self.last_checked.to_rfc3339(),
            site: self.site,
        }
    }
}

// ─── Repository functions — baseline_checks ───────────────────────────────────

/// Return all baseline checks ordered by id.
pub async fn list_checks(pool: &PgPool) -> Result<Vec<BaselineCheck>, sqlx::Error> {
    let rows: Vec<BaselineCheckRow> = sqlx::query_as(&format!(
        "SELECT {CHECK_COLUMNS} FROM baseline_checks ORDER BY id"
    ))
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

// ─── Repository functions — baseline_results ──────────────────────────────────

/// Return all compliance results for a single server, ordered by check_id.
pub async fn list_results_for_server(
    pool: &PgPool,
    server_name: &str,
) -> Result<Vec<BaselineResult>, sqlx::Error> {
    let rows: Vec<BaselineResultRow> = sqlx::query_as(&format!(
        "SELECT {RESULT_COLUMNS} FROM baseline_results WHERE server_name = $1 ORDER BY check_id"
    ))
    .bind(server_name)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into_model()).collect())
}

/// Return all compliance results for a site, ordered by server_name, check_id.
pub async fn list_results_for_site(
    pool: &PgPool,
    site: &str,
) -> Result<Vec<BaselineResult>, sqlx::Error> {
    let rows: Vec<BaselineResultRow> = sqlx::query_as(&format!(
        "SELECT {RESULT_COLUMNS} FROM baseline_results \
         WHERE site = $1 ORDER BY server_name, check_id"
    ))
    .bind(site)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into_model()).collect())
}

/// Return all compliance results across all sites, ordered by server_name, check_id.
pub async fn list_all_results(pool: &PgPool) -> Result<Vec<BaselineResult>, sqlx::Error> {
    let rows: Vec<BaselineResultRow> = sqlx::query_as(&format!(
        "SELECT {RESULT_COLUMNS} FROM baseline_results ORDER BY server_name, check_id"
    ))
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into_model()).collect())
}

/// Atomically set a compliance result to compliant, using `FOR UPDATE` on the
/// composite PK row so concurrent remediations of the same (server, check) pair
/// are serialized.
///
/// Returns `Ok(None)` when the (server_name, check_id) pair is absent (caller →
/// 404). Returns `Ok(Some(result))` on success with the DB-authoritative row.
/// `Err` is reserved for genuine DB failures (caller → 500).
pub async fn remediate(
    pool: &PgPool,
    server_name: &str,
    check_id: &str,
) -> Result<Option<BaselineResult>, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Lock the result row AND fetch its check's authoritative expected_value in
    // one query, inside the tx, so the value written can't go stale between a
    // separate lookup and the UPDATE. If the result row (or its check) is absent
    // there is nothing valid to remediate → Ok(None) → 404. No fallback value.
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT c.expected_value \
         FROM baseline_results r \
         JOIN baseline_checks c ON c.id = r.check_id \
         WHERE r.server_name = $1 AND r.check_id = $2 \
         FOR UPDATE OF r",
    )
    .bind(server_name)
    .bind(check_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((expected_value,)) = row else {
        tx.rollback().await?;
        return Ok(None);
    };

    let updated: BaselineResultRow = sqlx::query_as(&format!(
        "UPDATE baseline_results \
         SET compliant = true, actual_value = $3, last_checked = NOW() \
         WHERE server_name = $1 AND check_id = $2 \
         RETURNING {RESULT_COLUMNS}"
    ))
    .bind(server_name)
    .bind(check_id)
    .bind(&expected_value)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(Some(updated.into_model()))
}

/// Return per-month compliance percentages for a site, sorted chronologically.
///
/// SQL: `to_char(date_trunc('month', last_checked), 'YYYY-MM')` groups results
/// into calendar months; `SUM(CASE WHEN compliant THEN 1 ELSE 0 END)/COUNT(*)`
/// gives the compliance ratio. With the current seed data there will be at most
/// one month; more months accumulate as real remediations land.
pub async fn compliance_trend_for_site(
    pool: &PgPool,
    site: &str,
) -> Result<Vec<(String, f64)>, sqlx::Error> {
    #[derive(sqlx::FromRow)]
    struct TrendRow {
        month: String,
        pct: f64,
    }

    let rows: Vec<TrendRow> = sqlx::query_as(
        "SELECT to_char(date_trunc('month', last_checked), 'YYYY-MM') AS month, \
                ROUND(100.0 * SUM(CASE WHEN compliant THEN 1 ELSE 0 END)::numeric \
                      / COUNT(*), 1)::float8 AS pct \
         FROM baseline_results \
         WHERE site = $1 \
         GROUP BY 1 \
         ORDER BY 1",
    )
    .bind(site)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| (r.month, r.pct)).collect())
}

// ─── DB integration tests ────────────────────────────────────────────────────
//
// Run with:
//   RYUKI_DATABASE_URL=postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform \
//     cargo test -p ryuki-api -- --test-threads=1 os_baseline_db_tests
//
// Tests SKIP when RYUKI_DATABASE_URL is unset; FAIL (panic) if the URL is set
// but connect or migrate fails.
#[cfg(test)]
mod os_baseline_db_tests {
    use super::*;
    use crate::database::DB_TEST_SERIAL;
    use ryuki_engine::os_baseline::{BaselineCategory, BaselineSeverity};

    /// Returns a FRESH owned pool per test invocation.
    /// Returns `None` only when `RYUKI_DATABASE_URL` is absent or empty —
    /// tests are skipped in that case. If the URL IS set but connect or
    /// migrate fails, this function panics.
    async fn global_pool() -> Option<PgPool> {
        let url = match std::env::var("RYUKI_DATABASE_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("os_baseline_db_tests: RYUKI_DATABASE_URL not set — skipping");
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

    // ─── list_checks ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_list_checks_returns_seeded_rows() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        let checks = list_checks(pool).await.expect("list_checks failed");
        assert!(
            checks.len() >= 4,
            "expected at least 4 seeded checks, got {}",
            checks.len()
        );

        // Verify PascalCase enum decode works for known seeded rows.
        let security = checks.iter().find(|c| c.id == "bc-001");
        assert!(security.is_some(), "bc-001 must be present");
        let security = security.unwrap();
        assert_eq!(
            security.category,
            BaselineCategory::Security,
            "bc-001 category must decode as Security"
        );
        assert_eq!(
            security.severity,
            BaselineSeverity::Critical,
            "bc-001 severity must decode as Critical"
        );

        let tools = checks.iter().find(|c| c.id == "bc-002");
        assert!(tools.is_some(), "bc-002 must be present");
        assert_eq!(
            tools.unwrap().severity,
            BaselineSeverity::High,
            "bc-002 severity must decode as High"
        );
    }

    // ─── list_results_for_site ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_list_results_for_site_returns_backfilled_rows() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        let results = list_results_for_site(pool, "DEFRA")
            .await
            .expect("list_results_for_site DEFRA failed");

        assert!(
            !results.is_empty(),
            "DEFRA must have at least one result row after migration 068 backfill"
        );
        assert!(
            results.iter().all(|r| r.site == "DEFRA"),
            "all returned rows must have site = DEFRA"
        );
        // Verify servers seeded in migration 024 appear.
        assert!(
            results.iter().any(|r| r.server_name == "srv-defra-dc01"),
            "srv-defra-dc01 must appear in DEFRA results"
        );

        // Strengthen: verify the migration-068 CASE backfill across ALL sites and
        // that no seed row fell through to 'UNKNOWN' (a typo in any CASE branch).
        let all = list_all_results(pool)
            .await
            .expect("list_all_results failed");
        assert_eq!(
            all.len(),
            20,
            "migration 024 seeds 20 baseline_results rows"
        );
        assert!(
            all.iter().all(|r| r.site != "UNKNOWN"),
            "no seed row should backfill to UNKNOWN — check the CASE branches"
        );
        let count_site = |s: &str| all.iter().filter(|r| r.site == s).count();
        assert_eq!(count_site("DEFRA"), 8, "DEFRA = 2 servers x 4 checks");
        assert_eq!(count_site("GBLON"), 4, "GBLON = 1 server x 4 checks");
        assert_eq!(count_site("FRPAR"), 4, "FRPAR = 1 server x 4 checks");
        assert_eq!(count_site("NLAMS"), 4, "NLAMS = 1 server x 4 checks");
    }

    // ─── list_results_for_server ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_list_results_for_server() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        let results = list_results_for_server(pool, "srv-gblon-db01")
            .await
            .expect("list_results_for_server failed");

        assert_eq!(
            results.len(),
            4,
            "srv-gblon-db01 must have 4 check results (one per seeded check)"
        );
        assert!(
            results.iter().all(|r| r.server_name == "srv-gblon-db01"),
            "all rows must belong to srv-gblon-db01"
        );
        assert!(
            results.iter().all(|r| r.site == "GBLON"),
            "all srv-gblon-db01 rows must have site = GBLON after backfill"
        );
        // bc-004 (Windows Firewall) should be non-compliant for the DB server.
        let fw = results.iter().find(|r| r.check_id == "bc-004");
        assert!(fw.is_some(), "bc-004 must be present");
        assert!(
            !fw.unwrap().compliant,
            "bc-004 must be non-compliant for srv-gblon-db01"
        );
    }

    // ─── remediate — happy path ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_remediate_sets_compliant() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        // Use the seeded non-compliant row (srv-gblon-db01, bc-004).
        let server = "srv-gblon-db01";
        let check = "bc-004";
        let expected = "enabled, domain profile";

        // Capture original state so we can restore it.
        let original = list_results_for_server(pool, server)
            .await
            .expect("pre-read failed")
            .into_iter()
            .find(|r| r.check_id == check)
            .expect("seeded row must exist");

        let result = remediate(pool, server, check)
            .await
            .expect("remediate failed");

        let result = result.expect("remediate must return Some for a known row");
        assert!(result.compliant, "remediated row must be compliant");
        assert_eq!(
            result.actual_value, expected,
            "actual_value must be set to expected_value"
        );
        assert_eq!(result.server_name, server, "server_name must be preserved");
        assert_eq!(result.check_id, check, "check_id must be preserved");

        // Restore original state.
        sqlx::query(
            "UPDATE baseline_results SET compliant = $3, actual_value = $4, last_checked = $5 \
             WHERE server_name = $1 AND check_id = $2",
        )
        .bind(server)
        .bind(check)
        .bind(original.compliant)
        .bind(&original.actual_value)
        .bind(
            chrono::DateTime::parse_from_rfc3339(&original.last_checked)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        )
        .execute(pool)
        .await
        .expect("cleanup restore failed");
    }

    // ─── remediate — unknown pair → Ok(None) ─────────────────────────────────

    #[tokio::test]
    async fn test_remediate_unknown_pair_returns_none() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        let result = remediate(pool, "nonexistent-server", "bc-001")
            .await
            .expect("remediate must not error for unknown pair");

        assert!(result.is_none(), "unknown (server, check) must return None");
    }

    // ─── compliance_trend_for_site ────────────────────────────────────────────

    #[tokio::test]
    async fn test_compliance_trend_for_site_returns_data() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        let trend = compliance_trend_for_site(pool, "DEFRA")
            .await
            .expect("compliance_trend_for_site failed");

        assert!(
            !trend.is_empty(),
            "DEFRA must have at least one trend month (seeded rows have last_checked = NOW())"
        );

        let (month, pct) = &trend[0];
        assert!(
            month.len() == 7 && month.contains('-'),
            "month must be YYYY-MM format, got {month}"
        );
        assert!(
            *pct >= 0.0 && *pct <= 100.0,
            "pct must be in [0,100], got {pct}"
        );

        // A site with no results (DEBER has no seed rows) trends to an empty vec,
        // not an error — the read degrades cleanly.
        let empty = compliance_trend_for_site(pool, "DEBER")
            .await
            .expect("trend for an empty site must not error");
        assert!(empty.is_empty(), "a site with no results must trend to []");
    }

    // ─── into_model — decode round-trip ──────────────────────────────────────

    #[tokio::test]
    async fn test_into_model_decode_known_category_severity() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        // bc-004 is Configuration / Critical — both non-default enum variants.
        let checks = list_checks(pool).await.expect("list_checks failed");
        let bc004 = checks.iter().find(|c| c.id == "bc-004");
        assert!(bc004.is_some(), "bc-004 must be present");
        let bc004 = bc004.unwrap();
        assert_eq!(bc004.category, BaselineCategory::Configuration);
        assert_eq!(bc004.severity, BaselineSeverity::Critical);
    }
}
