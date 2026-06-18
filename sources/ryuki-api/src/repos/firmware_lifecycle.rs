//! Repository functions for `firmware_records` and `firmware_exceptions`.
//!
//! # ID type
//! Both tables use plain TEXT primary keys (e.g. "fw-defra-srv-001", "fwex-...").
//! Ids are bound and decoded directly as `String` — no `Uuid::parse_str`.
//!
//! # Enum encoding
//! `device_type` and `compliance_status` are stored as their serde PascalCase
//! variant names (e.g. "Server", "Compliant"). Both enums derive
//! `Serialize/Deserialize` with no rename, so the serde name equals the variant
//! name equals the DB CHECK form. We decode via `serde_json::from_value` —
//! a parse failure means the persisted row is corrupt (decode error → 500).
//!
//! # Engine struct fields
//! `FirmwareRecord` and `FirmwareException` have no `created_at`/`updated_at`
//! fields. We select only the columns the engine model has.
//!
//! # Multi-table transactions
//! `request_exception`: UPDATE firmware_records + INSERT firmware_exceptions in
//!   one transaction. Both writes commit atomically.
//! `revoke_exception`: SELECT exception + DELETE firmware_exceptions + UPDATE
//!   firmware_records in one transaction.
//!
//! # list_exceptions active filter
//! Filtered in SQL: `WHERE expiry_date >= $1`, where `$1` is the UTC date
//! (`Utc::now().date_naive()`) bound from Rust — NOT SQL `CURRENT_DATE`, whose
//! timezone could differ from the engine's UTC `active_exception` predicate.
//! Since expiry_date is TEXT in 'YYYY-MM-DD' format, lexicographic comparison
//! works correctly for ISO date strings.

use chrono::{Duration, Utc};
use ryuki_engine::firmware_lifecycle::{
    ComplianceStatus, DeviceType, FirmwareException, FirmwareRecord,
};
use sqlx::PgPool;
use uuid::Uuid;

// ─── Column lists ─────────────────────────────────────────────────────────────

pub const RECORD_COLUMNS: &str =
    "id, device_type, vendor, model, current_version, minimum_version, latest_version, eol_date, site, compliance_status";

pub const EXCEPTION_COLUMNS: &str = "id, device_id, reason, approved_by, expiry_date";

// ─── Row structs ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct FirmwareRecordRow {
    pub id: String,
    pub device_type: String,
    pub vendor: String,
    pub model: String,
    pub current_version: String,
    pub minimum_version: String,
    pub latest_version: String,
    pub eol_date: String,
    pub site: String,
    pub compliance_status: String,
}

impl FirmwareRecordRow {
    pub fn into_model(self) -> Result<FirmwareRecord, sqlx::Error> {
        let device_type: DeviceType = serde_json::from_value(serde_json::Value::String(
            self.device_type.clone(),
        ))
        .map_err(|e| {
            sqlx::Error::Decode(
                format!(
                    "firmware_records.device_type: corrupt value '{}': {e}",
                    self.device_type
                )
                .into(),
            )
        })?;
        let compliance_status: ComplianceStatus =
            serde_json::from_value(serde_json::Value::String(self.compliance_status.clone()))
                .map_err(|e| {
                    sqlx::Error::Decode(
                        format!(
                            "firmware_records.compliance_status: corrupt value '{}': {e}",
                            self.compliance_status
                        )
                        .into(),
                    )
                })?;
        Ok(FirmwareRecord {
            id: self.id,
            device_type,
            vendor: self.vendor,
            model: self.model,
            current_version: self.current_version,
            minimum_version: self.minimum_version,
            latest_version: self.latest_version,
            eol_date: self.eol_date,
            site: self.site,
            compliance_status,
        })
    }
}

#[derive(sqlx::FromRow)]
pub struct FirmwareExceptionRow {
    pub id: String,
    pub device_id: String,
    pub reason: String,
    pub approved_by: String,
    pub expiry_date: String,
}

impl FirmwareExceptionRow {
    pub fn into_model(self) -> FirmwareException {
        FirmwareException {
            id: self.id,
            device_id: self.device_id,
            reason: self.reason,
            approved_by: self.approved_by,
            expiry_date: self.expiry_date,
        }
    }
}

// ─── Read functions ───────────────────────────────────────────────────────────

/// List all firmware records, optionally filtered by site.
pub async fn list_devices(pool: &PgPool, site: &str) -> Result<Vec<FirmwareRecord>, sqlx::Error> {
    let rows: Vec<FirmwareRecordRow> = if site.is_empty() {
        sqlx::query_as(&format!(
            "SELECT {RECORD_COLUMNS} FROM firmware_records ORDER BY id"
        ))
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {RECORD_COLUMNS} FROM firmware_records WHERE site = $1 ORDER BY id"
        ))
        .bind(site)
        .fetch_all(pool)
        .await?
    };
    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Get a single firmware record by TEXT id. Returns `Ok(None)` when absent.
pub async fn get_device(pool: &PgPool, id: &str) -> Result<Option<FirmwareRecord>, sqlx::Error> {
    let row: Option<FirmwareRecordRow> = sqlx::query_as(&format!(
        "SELECT {RECORD_COLUMNS} FROM firmware_records WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.map(|r| r.into_model()).transpose()
}

/// Return all non-compliant (NonCompliant or EOL) firmware records.
pub async fn list_noncompliant(pool: &PgPool) -> Result<Vec<FirmwareRecord>, sqlx::Error> {
    let rows: Vec<FirmwareRecordRow> = sqlx::query_as(&format!(
        "SELECT {RECORD_COLUMNS} FROM firmware_records \
         WHERE compliance_status IN ('NonCompliant', 'EOL') ORDER BY id"
    ))
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Return all firmware records whose eol_date < today (lexicographic ISO date).
/// The cutoff is the UTC date computed in Rust (NOT SQL CURRENT_DATE, whose
/// timezone could differ), so this matches the engine's `is_eol` which uses
/// `Utc::now().date_naive()`.
pub async fn list_eol(pool: &PgPool) -> Result<Vec<FirmwareRecord>, sqlx::Error> {
    let today_utc = Utc::now().date_naive().to_string();
    let rows: Vec<FirmwareRecordRow> = sqlx::query_as(&format!(
        "SELECT {RECORD_COLUMNS} FROM firmware_records \
         WHERE eol_date < $1 ORDER BY id"
    ))
    .bind(today_utc)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Return all firmware records for the compliance report.
pub async fn list_all_for_report(pool: &PgPool) -> Result<Vec<FirmwareRecord>, sqlx::Error> {
    let rows: Vec<FirmwareRecordRow> = sqlx::query_as(&format!(
        "SELECT {RECORD_COLUMNS} FROM firmware_records ORDER BY id"
    ))
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Return active exceptions (expiry_date >= today, ISO date TEXT lexicographic
/// comparison). The cutoff is the UTC date from Rust (NOT SQL CURRENT_DATE), so
/// it matches the engine's `active_exception` which uses `Utc::now().date_naive()`.
pub async fn list_active_exceptions(pool: &PgPool) -> Result<Vec<FirmwareException>, sqlx::Error> {
    let today_utc = Utc::now().date_naive().to_string();
    let rows: Vec<FirmwareExceptionRow> = sqlx::query_as(&format!(
        "SELECT {EXCEPTION_COLUMNS} FROM firmware_exceptions \
         WHERE expiry_date >= $1 ORDER BY id"
    ))
    .bind(today_utc)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.into_model()).collect())
}

// ─── Write functions ──────────────────────────────────────────────────────────

/// Recalculate and persist a device's compliance_status in ONE transaction.
/// The device row is locked with `SELECT ... FOR UPDATE`, the new status is
/// computed from the LOCKED row via the pure engine, and written back — so a
/// concurrent `request_exception` (which sets the device to 'Exception') cannot
/// be clobbered by a stale recompute. Returns the updated record, or `Ok(None)`
/// when the id is absent. (calculated_status preserves an 'Exception' status, so
/// a serialized recompute after an exception lands re-writes 'Exception'.)
pub async fn recalculate_compliance(
    pool: &PgPool,
    id: &str,
) -> Result<Option<FirmwareRecord>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let row: Option<FirmwareRecordRow> = sqlx::query_as(&format!(
        "SELECT {RECORD_COLUMNS} FROM firmware_records WHERE id = $1 FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        tx.rollback().await?;
        return Ok(None);
    };
    let mut record = row.into_model()?;
    let new_status = ryuki_engine::firmware_lifecycle::calculated_status(&record);
    sqlx::query(
        "UPDATE firmware_records SET compliance_status = $2, updated_at = NOW() WHERE id = $1",
    )
    .bind(id)
    .bind(new_status.to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    record.compliance_status = new_status;
    Ok(Some(record))
}

/// Request an exception for a device: atomically set device status to 'Exception'
/// and insert a new firmware_exceptions row.
///
/// Transaction:
///   1. UPDATE firmware_records SET compliance_status='Exception' WHERE id=$device_id
///      → returns None if device absent (caller → 404)
///   2. INSERT INTO firmware_exceptions (id, device_id, reason, approved_by, expiry_date)
///
/// The exception id is generated as "fwex-{full-uuid}" — the FULL v4 UUID (122
/// bits), not just the first 8-hex segment, so a growing exceptions table does
/// not hit a birthday collision that would fail the PK insert with a 500.
/// expiry_date is computed as (today + expiry_days) in YYYY-MM-DD format.
pub async fn request_exception(
    pool: &PgPool,
    device_id: &str,
    reason: &str,
    approved_by: &str,
    expiry_days: i64,
) -> Result<Option<FirmwareException>, sqlx::Error> {
    let exception_id = format!("fwex-{}", Uuid::new_v4());
    let expiry_date = (Utc::now() + Duration::days(expiry_days))
        .date_naive()
        .to_string();

    let mut tx = pool.begin().await?;

    // Update device status; if device absent, UPDATE returns 0 rows.
    let affected = sqlx::query(
        "UPDATE firmware_records \
         SET compliance_status = 'Exception', updated_at = NOW() \
         WHERE id = $1",
    )
    .bind(device_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if affected == 0 {
        tx.rollback().await?;
        return Ok(None);
    }

    // Insert exception row.
    sqlx::query(
        "INSERT INTO firmware_exceptions (id, device_id, reason, approved_by, expiry_date) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&exception_id)
    .bind(device_id)
    .bind(reason)
    .bind(approved_by)
    .bind(&expiry_date)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Some(FirmwareException {
        id: exception_id,
        device_id: device_id.to_string(),
        reason: reason.to_string(),
        approved_by: approved_by.to_string(),
        expiry_date,
    }))
}

/// Revoke an exception: atomically delete the exception row and set device to NonCompliant.
///
/// Transaction:
///   1. SELECT exception (→ None if absent, caller → 404)
///   2. DELETE firmware_exceptions WHERE id=$exception_id
///   3. UPDATE firmware_records SET compliance_status='NonCompliant' WHERE id=$device_id
pub async fn revoke_exception(
    pool: &PgPool,
    exception_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Fetch the exception to get device_id (None = absent).
    let row: Option<FirmwareExceptionRow> = sqlx::query_as(&format!(
        "SELECT {EXCEPTION_COLUMNS} FROM firmware_exceptions WHERE id = $1 FOR UPDATE"
    ))
    .bind(exception_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(exc) = row else {
        tx.rollback().await?;
        return Ok(None);
    };

    let device_id = exc.device_id.clone();

    // Delete the exception.
    sqlx::query("DELETE FROM firmware_exceptions WHERE id = $1")
        .bind(exception_id)
        .execute(&mut *tx)
        .await?;

    // Set device to NonCompliant.
    sqlx::query(
        "UPDATE firmware_records \
         SET compliance_status = 'NonCompliant', updated_at = NOW() \
         WHERE id = $1",
    )
    .bind(&device_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Some(device_id))
}

// ─── DB integration tests ─────────────────────────────────────────────────────
//
// Run with:
//   RYUKI_DATABASE_URL=postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform \
//     cargo test -p ryuki-api --lib -- --test-threads=1 firmware_lifecycle_db_tests
//
// Tests SKIP when RYUKI_DATABASE_URL is unset.
#[cfg(test)]
mod firmware_lifecycle_db_tests {
    use super::*;
    use ryuki_engine::firmware_lifecycle::ComplianceStatus;

    async fn test_pool() -> Option<PgPool> {
        let url = match std::env::var("RYUKI_DATABASE_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("firmware_lifecycle_db_tests: RYUKI_DATABASE_URL not set — skipping");
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

    #[tokio::test]
    async fn test_list_devices_returns_9_seeded_rows() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let devices = list_devices(&pool, "").await.expect("list_devices failed");
        assert_eq!(devices.len(), 9, "migration 071 seeds 9 firmware records");
    }

    #[tokio::test]
    async fn test_get_device_by_id_and_absent() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let found = get_device(&pool, "fw-defra-srv-001")
            .await
            .expect("get_device failed");
        assert!(found.is_some(), "fw-defra-srv-001 must be present");
        let rec = found.unwrap();
        assert_eq!(rec.site, "DEFRA");
        assert_eq!(rec.vendor, "HPE");

        let absent = get_device(&pool, "fw-nonexistent")
            .await
            .expect("get_device must not error for absent id");
        assert!(absent.is_none(), "absent id must return None");
    }

    #[tokio::test]
    async fn test_recalculate_compliance_corrects_status() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // fw-defra-srv-001 is seeded Compliant (current 2.94 >= min 2.90, future EOL).
        // Force a WRONG stored status, then recalculate_compliance must compute the
        // correct status FROM the device's versions/EOL and persist it — proving it
        // actually exercises calculated_status, not a write-back of a hardcoded value.
        sqlx::query(
            "UPDATE firmware_records SET compliance_status = 'EOL' WHERE id = 'fw-defra-srv-001'",
        )
        .execute(&pool)
        .await
        .expect("force wrong status");

        let updated = recalculate_compliance(&pool, "fw-defra-srv-001")
            .await
            .expect("recalculate_compliance failed")
            .expect("fw-defra-srv-001 must exist");
        assert_eq!(
            updated.compliance_status,
            ComplianceStatus::Compliant,
            "recalc must correct the forced-wrong status from the device's versions"
        );

        // The corrected status is persisted.
        let (stored,): (String,) = sqlx::query_as(
            "SELECT compliance_status FROM firmware_records WHERE id = 'fw-defra-srv-001'",
        )
        .fetch_one(&pool)
        .await
        .expect("read back");
        assert_eq!(stored, "Compliant");

        // Absent id returns None (not an error).
        let absent = recalculate_compliance(&pool, "fw-nonexistent")
            .await
            .expect("recalculate for absent id must not error");
        assert!(absent.is_none(), "absent id must return None");
    }

    #[tokio::test]
    async fn test_request_exception_sets_exception_and_inserts_row() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // Use a NonCompliant device for a clean exception request.
        let result = request_exception(
            &pool,
            "fw-gblon-srv-001",
            "Vendor image pending staged validation",
            "netops.lead",
            14,
        )
        .await
        .expect("request_exception failed");

        assert!(
            result.is_some(),
            "request_exception must return Some for known device"
        );
        let exc = result.unwrap();
        assert_eq!(exc.device_id, "fw-gblon-srv-001");
        assert!(
            exc.id.starts_with("fwex-"),
            "exception id must start with fwex-"
        );

        // Device must now be Exception.
        let device = get_device(&pool, "fw-gblon-srv-001")
            .await
            .expect("get_device failed")
            .expect("device must exist");
        assert_eq!(device.compliance_status, ComplianceStatus::Exception);

        // Cleanup: revoke the exception to restore state.
        let revoked = revoke_exception(&pool, &exc.id)
            .await
            .expect("revoke_exception failed");
        assert!(revoked.is_some(), "revoke must succeed");

        // Device restored to NonCompliant.
        let restored = get_device(&pool, "fw-gblon-srv-001")
            .await
            .expect("get_device failed")
            .expect("device must exist after revoke");
        assert_eq!(restored.compliance_status, ComplianceStatus::NonCompliant);
    }

    #[tokio::test]
    async fn test_revoke_exception_deletes_and_sets_noncompliant() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // First request an exception on a fresh device.
        let exc = request_exception(
            &pool,
            "fw-deber-fw-001",
            "Rollback validation required",
            "platform.owner",
            7,
        )
        .await
        .expect("request_exception failed")
        .expect("must return exception");

        // Revoke it.
        let device_id = revoke_exception(&pool, &exc.id)
            .await
            .expect("revoke_exception failed");
        assert_eq!(device_id, Some("fw-deber-fw-001".to_string()));

        // Device must be NonCompliant.
        let device = get_device(&pool, "fw-deber-fw-001")
            .await
            .expect("get_device failed")
            .expect("device must exist");
        assert_eq!(device.compliance_status, ComplianceStatus::NonCompliant);

        // Absent exception returns None.
        let absent = revoke_exception(&pool, "fwex-nonexistent")
            .await
            .expect("revoke for absent id must not error");
        assert!(absent.is_none(), "absent exception id must return None");
    }

    #[tokio::test]
    async fn test_list_active_exceptions_returns_seeded() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let exceptions = list_active_exceptions(&pool)
            .await
            .expect("list_active_exceptions failed");
        // Seeded exception fwex-gblon-crac-001 has expiry = today+21 days, so it's active.
        assert!(
            !exceptions.is_empty(),
            "must have at least the seeded active exception"
        );
        assert!(
            exceptions.iter().any(|e| e.id == "fwex-gblon-crac-001"),
            "seeded exception fwex-gblon-crac-001 must be active"
        );
    }
}
