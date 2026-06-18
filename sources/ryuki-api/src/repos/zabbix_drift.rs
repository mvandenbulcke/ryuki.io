//! Repository functions for `drift_reports`.
//!
//! All functions are pure over `&PgPool`; callers (handlers in `contracts.rs`)
//! are responsible for mapping `sqlx::Error` → 500, `None` → 404, and CAS
//! misses (`Ok(None)` from `transition`) → 409.
//!
//! # ID type
//! `drift_reports.id` is a UUID PK. SELECT casts: `id::text AS id`.
//! On bind: `Uuid::parse_str(id)` — malformed id → `Ok(None)` (caller → 404),
//! NOT an error.
//!
//! # Enum encoding
//! `drift_severity` and `status` are stored as PascalCase variant names
//! (e.g. `"High"`, `"Detected"`). Decoded via `serde_json::from_value`.
//! A parse failure means the persisted row is corrupt; surfaced as a decode
//! error (caller → 500) rather than defaulting.
//!
//! # Arrays and JSONB
//! `remediation_steps` is a native `TEXT[]` column decoded as `Vec<String>`.
//! `metadata` is `JSONB` decoded as `HashMap<String, String>`.
//!
//! # Timestamps
//! `created_at` / `updated_at` are `TIMESTAMPTZ`, decoded as
//! `chrono::DateTime<Utc>`, then converted via `.to_rfc3339()` in `into_model`.

use chrono::{DateTime, Utc};
use ryuki_engine::zabbix_drift::{DriftReport, DriftSeverity, DriftStatus};
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

// ─── Column list ─────────────────────────────────────────────────────────────

/// SELECT column list. UUID → text; JSONB decoded via sqlx directly.
pub const COLUMNS: &str = "id::text AS id, \
     host_id, \
     hostname, \
     site, \
     expected_group, \
     actual_group, \
     expected_template, \
     actual_template, \
     expected_proxy, \
     actual_proxy, \
     drift_severity, \
     status, \
     remediation_steps, \
     metadata, \
     created_at, \
     updated_at";

// ─── Row struct ───────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct DriftReportRow {
    pub id: String,
    pub host_id: String,
    pub hostname: String,
    pub site: String,
    pub expected_group: String,
    pub actual_group: String,
    pub expected_template: String,
    pub actual_template: String,
    pub expected_proxy: String,
    pub actual_proxy: String,
    pub drift_severity: String,
    pub status: String,
    pub remediation_steps: Vec<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl DriftReportRow {
    /// Convert a DB row into the engine model. Fallible — a corrupt persisted
    /// enum value is surfaced as a decode error (caller → 500) rather than
    /// substituting a default.
    pub fn into_model(self) -> Result<DriftReport, sqlx::Error> {
        let drift_severity: DriftSeverity =
            serde_json::from_value(serde_json::Value::String(self.drift_severity.clone()))
                .map_err(|e| {
                    sqlx::Error::Decode(
                        format!(
                            "drift_reports.drift_severity: corrupt persisted value '{}': {e}",
                            self.drift_severity
                        )
                        .into(),
                    )
                })?;

        let status: DriftStatus = serde_json::from_value(serde_json::Value::String(
            self.status.clone(),
        ))
        .map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "drift_reports.status: corrupt persisted value '{}': {e}",
                    self.status
                )
                .into(),
            )
        })?;

        let metadata: HashMap<String, String> = serde_json::from_value(self.metadata.clone())
            .map_err(|e| {
                sqlx::Error::Decode(
                    format!("drift_reports.metadata: corrupt JSONB value: {e}").into(),
                )
            })?;

        Ok(DriftReport {
            id: self.id,
            host_id: self.host_id,
            hostname: self.hostname,
            site: self.site,
            expected_group: self.expected_group,
            actual_group: self.actual_group,
            expected_template: self.expected_template,
            actual_template: self.actual_template,
            expected_proxy: self.expected_proxy,
            actual_proxy: self.actual_proxy,
            drift_severity,
            status,
            remediation_steps: self.remediation_steps,
            created_at: self.created_at.to_rfc3339(),
            updated_at: self.updated_at.to_rfc3339(),
            metadata,
        })
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

/// Canonical PascalCase variant name for a `DriftSeverity` as stored in the DB.
pub fn severity_str(s: &DriftSeverity) -> &'static str {
    s.as_str()
}

/// Canonical PascalCase variant name for a `DriftStatus` as stored in the DB.
pub fn status_str(s: &DriftStatus) -> &'static str {
    s.as_str()
}

// ─── Repository functions ─────────────────────────────────────────────────────

/// Upsert a batch of fabricated drift reports.
///
/// For each report in `reports`:
/// - INSERT with `ON CONFLICT (site, host_id) DO NOTHING`.
/// - On conflict (row already exists for that site+host_id) the INSERT is
///   skipped and the row is NOT returned.
/// - Returns only the newly-inserted rows (RETURNING).
///
/// `id` in each input `DriftReport` is ignored — Postgres assigns a UUID via
/// `gen_random_uuid()` and RETURNING returns `id::text`.
pub async fn upsert_detected(
    pool: &PgPool,
    reports: &[DriftReport],
) -> Result<Vec<DriftReport>, sqlx::Error> {
    let mut inserted: Vec<DriftReport> = Vec::new();

    for r in reports {
        let metadata_val = serde_json::to_value(&r.metadata)
            .unwrap_or(serde_json::Value::Object(Default::default()));

        let row: Option<DriftReportRow> = sqlx::query_as(&format!(
            "INSERT INTO drift_reports \
             (host_id, hostname, site, expected_group, actual_group, \
              expected_template, actual_template, expected_proxy, actual_proxy, \
              drift_severity, status, remediation_steps, metadata) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
             ON CONFLICT (site, host_id) DO NOTHING \
             RETURNING {COLUMNS}"
        ))
        .bind(&r.host_id)
        .bind(&r.hostname)
        .bind(&r.site)
        .bind(&r.expected_group)
        .bind(&r.actual_group)
        .bind(&r.expected_template)
        .bind(&r.actual_template)
        .bind(&r.expected_proxy)
        .bind(&r.actual_proxy)
        .bind(severity_str(&r.drift_severity))
        .bind(status_str(&r.status))
        .bind(&r.remediation_steps)
        .bind(metadata_val)
        .fetch_optional(pool)
        .await?;

        if let Some(row) = row {
            inserted.push(row.into_model()?);
        }
    }

    Ok(inserted)
}

/// Return all drift reports for a given site, ordered by id.
pub async fn list_by_site(pool: &PgPool, site: &str) -> Result<Vec<DriftReport>, sqlx::Error> {
    let rows: Vec<DriftReportRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM drift_reports WHERE site = $1 ORDER BY id"
    ))
    .bind(site)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Return all drift reports, ordered by id.
#[allow(dead_code)]
pub async fn list_all(pool: &PgPool) -> Result<Vec<DriftReport>, sqlx::Error> {
    let rows: Vec<DriftReportRow> =
        sqlx::query_as(&format!("SELECT {COLUMNS} FROM drift_reports ORDER BY id"))
            .fetch_all(pool)
            .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Fetch one drift report by id. A malformed (non-UUID) id is treated as
/// `Ok(None)` (caller → 404) rather than an error. `Err` is reserved for
/// genuine DB failures (caller → 500).
pub async fn get(pool: &PgPool, id: &str) -> Result<Option<DriftReport>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<DriftReportRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM drift_reports WHERE id = $1"
    ))
    .bind(uid)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Atomically transition a drift report to a new status IFF the DB row still
/// has `expected_status`. Returns `Ok(None)` when the row is absent or was
/// concurrently modified (caller → 409); `Ok(Some(persisted))` on success.
///
/// When `remediation_steps` is `Some`, the column is updated in the same
/// statement (used by the plan transition to persist computed steps).
pub async fn transition(
    pool: &PgPool,
    id: &str,
    expected_status: &str,
    new_status: &str,
    remediation_steps: Option<&[String]>,
) -> Result<Option<DriftReport>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<DriftReportRow> = if let Some(steps) = remediation_steps {
        sqlx::query_as(&format!(
            "UPDATE drift_reports \
             SET status = $3, remediation_steps = $4, updated_at = NOW() \
             WHERE id = $1 AND status = $2 \
             RETURNING {COLUMNS}"
        ))
        .bind(uid)
        .bind(expected_status)
        .bind(new_status)
        .bind(steps)
        .fetch_optional(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "UPDATE drift_reports \
             SET status = $3, updated_at = NOW() \
             WHERE id = $1 AND status = $2 \
             RETURNING {COLUMNS}"
        ))
        .bind(uid)
        .bind(expected_status)
        .bind(new_status)
        .fetch_optional(pool)
        .await?
    };

    row.map(|r| r.into_model()).transpose()
}

// ─── DB integration tests ─────────────────────────────────────────────────────
//
// Run with:
//   RYUKI_DATABASE_URL=postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform \
//     cargo test -p ryuki-api -- --test-threads=1 zabbix_drift_db_tests
//
// Tests SKIP when RYUKI_DATABASE_URL is unset; FAIL (panic) if the URL is set
// but connect or migrate fails — a migration error must not be silently skipped.
#[cfg(test)]
mod zabbix_drift_db_tests {
    use super::*;
    use crate::database::DB_TEST_SERIAL;
    use ryuki_engine::zabbix_drift::detect_drift;
    use uuid::Uuid;

    /// Returns a fresh owned pool per test invocation.
    /// Returns `None` only when `RYUKI_DATABASE_URL` is absent or empty.
    /// Panics when the URL is set but the connection or migrations fail.
    async fn global_pool() -> Option<PgPool> {
        let url = match std::env::var("RYUKI_DATABASE_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("zabbix_drift_db_tests: RYUKI_DATABASE_URL not set — skipping");
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

    async fn cleanup(pool: &PgPool, id: &str) {
        if let Ok(uid) = Uuid::parse_str(id) {
            sqlx::query("DELETE FROM drift_reports WHERE id = $1")
                .bind(uid)
                .execute(pool)
                .await
                .ok();
        }
    }

    /// Insert a single fabricated report and return it.
    async fn insert_one(
        pool: &PgPool,
        site: &str,
        host_suffix: &str,
        drift_type: &str,
    ) -> DriftReport {
        let metadata_val = serde_json::json!({
            "drift_type": drift_type,
            "dry_run": "true"
        });
        let row: DriftReportRow = sqlx::query_as(&format!(
            "INSERT INTO drift_reports \
             (host_id, hostname, site, expected_group, actual_group, \
              expected_template, actual_template, expected_proxy, actual_proxy, \
              drift_severity, status, remediation_steps, metadata) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
             RETURNING {COLUMNS}"
        ))
        // UUID-suffix the host_id so tests stay repeat-safe under the new
        // UNIQUE(site, host_id) constraint (an interrupted run can't leave a
        // colliding residue row).
        .bind(format!(
            "host-{}-{}-{}",
            site.to_lowercase(),
            host_suffix,
            uuid::Uuid::new_v4()
        ))
        .bind(format!(
            "{}-{}.contoso.com",
            site.to_lowercase(),
            host_suffix
        ))
        .bind(site)
        .bind(format!("{}-Production-Servers", site))
        .bind(format!("{}-Discovered-Hosts", site))
        .bind("Template-OS-Windows-Server-2022")
        .bind("Template-OS-Windows-Server-2019")
        .bind(format!("zabbix-proxy-{}", site.to_lowercase()))
        .bind(format!("zabbix-proxy-{}", site.to_lowercase()))
        .bind("High")
        .bind("Detected")
        .bind(Vec::<String>::new())
        .bind(metadata_val)
        .fetch_one(pool)
        .await
        .expect("insert_one failed");

        row.into_model().expect("into_model failed")
    }

    // ── seeded_rows_pascal_case ───────────────────────────────────────────────
    //
    // Migration 013 seeds 4 rows; migration 069 normalizes them to PascalCase
    // and adds the UNIQUE constraint. Verify the repo decodes them correctly.

    #[tokio::test]
    async fn seeded_rows_pascal_case_decode() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        // The DEFRA seeded row: drift_severity=High, status=Detected.
        let rows = list_by_site(&pool, "DEFRA")
            .await
            .expect("list_by_site DEFRA failed");

        // At minimum the seeded row exists.
        assert!(
            !rows.is_empty(),
            "expected at least one seeded DEFRA drift row"
        );

        let seeded = rows
            .iter()
            .find(|r| r.host_id == "host-defra-srv-01")
            .expect("seeded host-defra-srv-01 must exist");

        assert_eq!(seeded.drift_severity, DriftSeverity::High);
        assert_eq!(seeded.status, DriftStatus::Detected);
        assert_eq!(seeded.site, "DEFRA");
        // remediation_steps defaults to empty array — TEXT[] round-trip.
        assert!(seeded.remediation_steps.is_empty());
        // metadata defaults to {} — JSONB round-trip.
        assert!(seeded.metadata.is_empty());
    }

    // ── get_by_uuid ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_by_uuid() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let inserted = insert_one(&pool, "GBLON", "test-get", "template-only").await;
        let id = inserted.id.clone();

        let fetched = get(&pool, &id)
            .await
            .expect("get must not fail")
            .expect("row must exist after insert");

        assert_eq!(fetched.id, id);
        assert_eq!(fetched.site, "GBLON");
        assert_eq!(fetched.drift_severity, DriftSeverity::High);
        assert_eq!(fetched.status, DriftStatus::Detected);

        cleanup(&pool, &id).await;
    }

    // ── malformed_uuid_returns_none ───────────────────────────────────────────

    #[tokio::test]
    async fn malformed_uuid_returns_none() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let result = get(&pool, "not-a-uuid")
            .await
            .expect("get must not fail for malformed id");
        assert!(result.is_none(), "malformed id must return None");
    }

    // ── upsert_idempotent ─────────────────────────────────────────────────────
    //
    // upsert_detected inserts a new (site, host_id) pair and on a second call
    // for the same pair returns empty (DO NOTHING) without creating a duplicate.

    #[tokio::test]
    async fn upsert_detected_inserts_and_is_idempotent() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        // Use a unique site prefix so we don't collide with seeded rows.
        let unique_site = "NLAMS";
        let unique_host = format!("host-test-upsert-{}", Uuid::new_v4());

        // Build a fabricated report with our unique host_id.
        let ts = chrono::Utc::now().to_rfc3339();
        let report = DriftReport {
            id: String::new(),
            host_id: unique_host.clone(),
            hostname: format!("{}.test.local", unique_host),
            site: unique_site.to_string(),
            expected_group: format!("{}-Production-Servers", unique_site),
            actual_group: format!("{}-Discovered-Hosts", unique_site),
            expected_template: "Template-OS-Windows-Server-2022".into(),
            actual_template: "Template-OS-Windows-Server-2019".into(),
            expected_proxy: format!("zabbix-proxy-{}", unique_site.to_lowercase()),
            actual_proxy: format!("zabbix-proxy-{}", unique_site.to_lowercase()),
            drift_severity: DriftSeverity::High,
            status: DriftStatus::Detected,
            remediation_steps: Vec::new(),
            created_at: ts.clone(),
            updated_at: ts,
            metadata: std::collections::HashMap::from([
                ("drift_type".into(), "template-only".into()),
                ("dry_run".into(), "true".into()),
            ]),
        };

        // First call — should insert and return the new row.
        let first = upsert_detected(&pool, std::slice::from_ref(&report))
            .await
            .expect("first upsert failed");
        assert_eq!(first.len(), 1, "first upsert must insert one row");
        let inserted_id = first[0].id.clone();
        assert!(!inserted_id.is_empty(), "inserted id must be a real UUID");

        // Count rows for this host_id before second call.
        let count_before: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM drift_reports WHERE host_id = $1")
                .bind(&unique_host)
                .fetch_one(&pool)
                .await
                .expect("count before failed");

        // Second call — DO NOTHING; must return empty.
        let second = upsert_detected(&pool, std::slice::from_ref(&report))
            .await
            .expect("second upsert failed");
        assert!(
            second.is_empty(),
            "second upsert must return empty on conflict"
        );

        // Count must still be 1 — no duplicate.
        let count_after: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM drift_reports WHERE host_id = $1")
                .bind(&unique_host)
                .fetch_one(&pool)
                .await
                .expect("count after failed");

        assert_eq!(
            count_before.0, count_after.0,
            "upsert DO NOTHING must not create a duplicate"
        );
        assert_eq!(count_before.0, 1, "exactly one row must exist");

        cleanup(&pool, &inserted_id).await;
    }

    // ── transition_plan_cas ───────────────────────────────────────────────────

    #[tokio::test]
    async fn transition_plan_cas_success_and_miss() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let inserted = insert_one(&pool, "FRPAR", "cas-test", "host-group-template").await;
        let id = inserted.id.clone();

        let steps = vec!["step 1".to_string(), "step 2".to_string()];

        // CAS: Detected → Planned with steps — must succeed.
        let planned = transition(&pool, &id, "Detected", "Planned", Some(&steps))
            .await
            .expect("transition must not fail")
            .expect("CAS must succeed on first call");

        assert_eq!(planned.status, DriftStatus::Planned);
        assert_eq!(planned.remediation_steps, steps);
        assert!(!planned.updated_at.is_empty());

        // CAS miss: row is now Planned; expected Detected → must return Ok(None).
        let miss = transition(&pool, &id, "Detected", "Planned", Some(&steps))
            .await
            .expect("transition must not fail");
        assert!(
            miss.is_none(),
            "CAS with wrong expected_status must return None"
        );

        cleanup(&pool, &id).await;
    }

    // ── full_lifecycle ────────────────────────────────────────────────────────
    //
    // Walk a single report through the full lifecycle:
    // Detected → Planned → Validated → Remediated → Verified.

    #[tokio::test]
    async fn full_lifecycle_detected_to_verified() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        // Insert via fabricated engine reports to also test upsert_detected path.
        let site = "DEBER";
        let unique_host = format!("host-test-lifecycle-{}", Uuid::new_v4());
        let ts = chrono::Utc::now().to_rfc3339();
        let report = DriftReport {
            id: String::new(),
            host_id: unique_host.clone(),
            hostname: format!("{}.test.local", unique_host),
            site: site.to_string(),
            expected_group: format!("{}-Production-Servers", site),
            actual_group: format!("{}-Discovered-Hosts", site),
            expected_template: "Template-OS-Windows-Server-2022".into(),
            actual_template: "Template-OS-Windows-Server-2019".into(),
            expected_proxy: format!("zabbix-proxy-{}", site.to_lowercase()),
            actual_proxy: format!("zabbix-proxy-{}", site.to_lowercase()),
            drift_severity: DriftSeverity::High,
            status: DriftStatus::Detected,
            remediation_steps: Vec::new(),
            created_at: ts.clone(),
            updated_at: ts,
            metadata: std::collections::HashMap::from([
                ("drift_type".into(), "group-proxy".into()),
                ("dry_run".into(), "true".into()),
            ]),
        };

        let upserted = upsert_detected(&pool, &[report])
            .await
            .expect("upsert_detected failed");
        assert_eq!(upserted.len(), 1);
        let id = upserted[0].id.clone();

        // Detected → Planned (with steps).
        let steps = vec![
            "DRY-RUN: reassign group".into(),
            "DRY-RUN: reassign proxy".into(),
        ];
        let planned = transition(&pool, &id, "Detected", "Planned", Some(&steps))
            .await
            .expect("plan transition failed")
            .expect("plan CAS must succeed");
        assert_eq!(planned.status, DriftStatus::Planned);
        assert_eq!(planned.remediation_steps.len(), 2);

        // Planned → Validated.
        let validated = transition(&pool, &id, "Planned", "Validated", None)
            .await
            .expect("validate transition failed")
            .expect("validate CAS must succeed");
        assert_eq!(validated.status, DriftStatus::Validated);

        // Validated → Remediated.
        let remediated = transition(&pool, &id, "Validated", "Remediated", None)
            .await
            .expect("execute transition failed")
            .expect("execute CAS must succeed");
        assert_eq!(remediated.status, DriftStatus::Remediated);

        // Remediated → Verified.
        let verified = transition(&pool, &id, "Remediated", "Verified", None)
            .await
            .expect("verify transition failed")
            .expect("verify CAS must succeed");
        assert_eq!(verified.status, DriftStatus::Verified);

        // JSONB metadata + TEXT[] steps survive the full lifecycle.
        assert_eq!(verified.remediation_steps.len(), 2);

        cleanup(&pool, &id).await;
    }

    // ── upsert_detected_fabricated_batch ─────────────────────────────────────
    //
    // Verify that engine detect_drift + repo upsert round-trips correctly:
    // the batch is inserted, and a second call skips all of them.

    #[tokio::test]
    async fn upsert_detected_fabricated_batch_idempotent() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        // We use a unique host_id suffix so the test rows are isolated from
        // the seeded DEFRA rows. We fabricate reports with a different site
        // that has no seeded rows.
        let site = "GBLON";
        let reports = detect_drift(site).expect("detect_drift failed");

        // Override host_ids to be unique for this test run to avoid conflicts
        // with any earlier runs or seeded data.
        let suffix = Uuid::new_v4().to_string()[..8].to_string();
        let unique_reports: Vec<DriftReport> = reports
            .iter()
            .enumerate()
            .map(|(i, r)| DriftReport {
                id: String::new(),
                host_id: format!("test-{}-srv-{:02}-{}", site.to_lowercase(), i + 1, suffix),
                hostname: format!(
                    "test-{}-srv-{:02}-{}.contoso.com",
                    site.to_lowercase(),
                    i + 1,
                    suffix
                ),
                ..r.clone()
            })
            .collect();

        let inserted = upsert_detected(&pool, &unique_reports)
            .await
            .expect("first upsert_detected failed");
        assert_eq!(
            inserted.len(),
            unique_reports.len(),
            "all unique reports must be inserted on first call"
        );

        let ids: Vec<String> = inserted.iter().map(|r| r.id.clone()).collect();

        // Second call with same host_ids — all DO NOTHING.
        let second = upsert_detected(&pool, &unique_reports)
            .await
            .expect("second upsert_detected failed");
        assert!(
            second.is_empty(),
            "second upsert must be fully idempotent (all conflict)"
        );

        // Cleanup.
        for id in &ids {
            cleanup(&pool, id).await;
        }
    }
}
