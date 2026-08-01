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
//! Exception lifecycle writes accept a caller-owned transaction so the API can
//! commit the state transition and its security audit record atomically.
//!
//! # Exception authority clock
//! PostgreSQL `CURRENT_DATE` is the only authority for creation, approval, and
//! expiry. Rust receives that same date for pure compliance evaluation; a
//! stored `Exception` status is only a cache and never grants authority alone.

use chrono::NaiveDate;
use ryuki_engine::firmware_lifecycle::{
    ComplianceStatus, DeviceType, FirmwareException, FirmwareExceptionStatus, FirmwareRecord,
};
use sqlx::{PgConnection, PgPool};
use std::collections::HashMap;
use uuid::Uuid;

// ─── Column lists ─────────────────────────────────────────────────────────────

pub const RECORD_COLUMNS: &str =
    "id, device_type, vendor, model, current_version, minimum_version, latest_version, eol_date, site, compliance_status";

pub const EXCEPTION_COLUMNS: &str =
    "id, device_id, reason, requested_by, approved_by, expiry_date, status, version";

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
    pub requested_by: String,
    pub approved_by: Option<String>,
    pub expiry_date: NaiveDate,
    pub status: String,
    pub version: i64,
}

impl FirmwareExceptionRow {
    pub fn into_model(self) -> Result<FirmwareException, sqlx::Error> {
        let status = FirmwareExceptionStatus::try_from(self.status.as_str()).map_err(|error| {
            sqlx::Error::Decode(
                format!(
                    "firmware_exceptions.status: corrupt value '{}': {error}",
                    self.status
                )
                .into(),
            )
        })?;
        Ok(FirmwareException {
            id: self.id,
            device_id: self.device_id,
            reason: self.reason,
            requested_by: self.requested_by,
            approved_by: self.approved_by,
            expiry_date: self.expiry_date.to_string(),
            status,
            version: self.version,
        })
    }
}

fn engine_error(error: String) -> sqlx::Error {
    sqlx::Error::Decode(error.into())
}

async fn apply_effective_statuses(
    pool: &PgPool,
    records: &mut [FirmwareRecord],
) -> Result<(), sqlx::Error> {
    if records.is_empty() {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    let today: NaiveDate = sqlx::query_scalar("SELECT CURRENT_DATE")
        .fetch_one(&mut *tx)
        .await?;
    let device_ids: Vec<String> = records.iter().map(|record| record.id.clone()).collect();
    let rows: Vec<FirmwareExceptionRow> = sqlx::query_as(&format!(
        "SELECT {EXCEPTION_COLUMNS} FROM firmware_exceptions \
         WHERE device_id = ANY($1) AND status = 'Approved' ORDER BY device_id, id"
    ))
    .bind(&device_ids)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let mut authority = HashMap::with_capacity(rows.len());
    for row in rows {
        let exception = row.into_model()?;
        if authority
            .insert(exception.device_id.clone(), exception)
            .is_some()
        {
            return Err(engine_error(
                "multiple Approved firmware exceptions exist for one device".into(),
            ));
        }
    }
    for record in records {
        record.compliance_status =
            ryuki_engine::firmware_lifecycle::calculated_status_with_exception_at(
                record,
                authority.get(&record.id),
                today,
            )
            .map_err(engine_error)?;
    }
    Ok(())
}

// ─── Read functions ───────────────────────────────────────────────────────────

/// List firmware records (optionally site-filtered), bounded to one
/// `LIMIT`/`OFFSET` page (#14). `ORDER BY id` is a unique key, so the page is a
/// stable cut.
pub async fn list_devices(
    pool: &PgPool,
    site: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<FirmwareRecord>, sqlx::Error> {
    let rows: Vec<FirmwareRecordRow> = if site.is_empty() {
        sqlx::query_as(&format!(
            "SELECT {RECORD_COLUMNS} FROM firmware_records ORDER BY id LIMIT $1 OFFSET $2"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {RECORD_COLUMNS} FROM firmware_records \
             WHERE site = $1 ORDER BY id LIMIT $2 OFFSET $3"
        ))
        .bind(site)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?
    };
    let mut records: Vec<FirmwareRecord> = rows
        .into_iter()
        .map(|row| row.into_model())
        .collect::<Result<_, _>>()?;
    apply_effective_statuses(pool, &mut records).await?;
    Ok(records)
}

/// Count firmware records (optionally site-filtered) — the pagination total for
/// [`list_devices`], using the SAME `WHERE` so the count matches the paged set.
pub async fn count_devices(pool: &PgPool, site: &str) -> Result<i64, sqlx::Error> {
    if site.is_empty() {
        sqlx::query_scalar("SELECT COUNT(*) FROM firmware_records")
            .fetch_one(pool)
            .await
    } else {
        sqlx::query_scalar("SELECT COUNT(*) FROM firmware_records WHERE site = $1")
            .bind(site)
            .fetch_one(pool)
            .await
    }
}

/// Get a single firmware record by TEXT id. Returns `Ok(None)` when absent.
pub async fn get_device(pool: &PgPool, id: &str) -> Result<Option<FirmwareRecord>, sqlx::Error> {
    let row: Option<FirmwareRecordRow> = sqlx::query_as(&format!(
        "SELECT {RECORD_COLUMNS} FROM firmware_records WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let mut records = vec![row.into_model()?];
    apply_effective_statuses(pool, &mut records).await?;
    Ok(records.pop())
}

/// Return all effectively non-compliant (NonCompliant or EOL) firmware records.
/// Persisted Exception rows are included in the candidate set and re-evaluated
/// against database-date exception authority before filtering, so an expired
/// exception becomes visible immediately even before a cache recalculation.
pub async fn list_noncompliant(pool: &PgPool) -> Result<Vec<FirmwareRecord>, sqlx::Error> {
    let rows: Vec<FirmwareRecordRow> = sqlx::query_as(&format!(
        "SELECT {RECORD_COLUMNS} FROM firmware_records \
         WHERE compliance_status IN ('NonCompliant', 'EOL', 'Exception') ORDER BY id"
    ))
    .fetch_all(pool)
    .await?;
    let mut records: Vec<FirmwareRecord> = rows
        .into_iter()
        .map(|row| row.into_model())
        .collect::<Result<_, _>>()?;
    apply_effective_statuses(pool, &mut records).await?;
    records.retain(|record| {
        matches!(
            record.compliance_status,
            ComplianceStatus::NonCompliant | ComplianceStatus::EOL
        )
    });
    Ok(records)
}

/// Return all firmware records whose canonical ISO EOL date has passed under
/// the same authoritative database date used by exception evaluation.
pub async fn list_eol(pool: &PgPool) -> Result<Vec<FirmwareRecord>, sqlx::Error> {
    let rows: Vec<FirmwareRecordRow> = sqlx::query_as(&format!(
        "SELECT {RECORD_COLUMNS} FROM firmware_records \
         WHERE eol_date::date < CURRENT_DATE ORDER BY id"
    ))
    .fetch_all(pool)
    .await?;
    let mut records: Vec<FirmwareRecord> = rows
        .into_iter()
        .map(|row| row.into_model())
        .collect::<Result<_, _>>()?;
    apply_effective_statuses(pool, &mut records).await?;
    Ok(records)
}

/// Return all firmware records for the compliance report.
pub async fn list_all_for_report(pool: &PgPool) -> Result<Vec<FirmwareRecord>, sqlx::Error> {
    let rows: Vec<FirmwareRecordRow> = sqlx::query_as(&format!(
        "SELECT {RECORD_COLUMNS} FROM firmware_records ORDER BY id"
    ))
    .fetch_all(pool)
    .await?;
    let mut records: Vec<FirmwareRecord> = rows
        .into_iter()
        .map(|row| row.into_model())
        .collect::<Result<_, _>>()?;
    apply_effective_statuses(pool, &mut records).await?;
    Ok(records)
}

/// Return only approved exceptions whose inclusive expiry has not passed under
/// the authoritative PostgreSQL date. Pending, legacy, revoked, and expired
/// rows are never surfaced as active authority.
pub async fn list_active_exceptions(pool: &PgPool) -> Result<Vec<FirmwareException>, sqlx::Error> {
    let rows: Vec<FirmwareExceptionRow> = sqlx::query_as(&format!(
        "SELECT {EXCEPTION_COLUMNS} FROM firmware_exceptions \
         WHERE status = 'Approved' AND expiry_date >= CURRENT_DATE ORDER BY id"
    ))
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(|row| row.into_model()).collect()
}

// ─── Write functions ──────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum RequestExceptionOutcome {
    Created(FirmwareException),
    MissingDevice,
    Conflict,
}

#[derive(Debug)]
pub enum ApproveExceptionOutcome {
    Approved(FirmwareException),
    NotFound,
    Conflict,
    SelfApproval,
}

#[derive(Debug)]
pub enum RevokeExceptionOutcome {
    Revoked {
        exception: FirmwareException,
        device: Box<FirmwareRecord>,
    },
    NotFound,
    Conflict,
}

/// Lock the resource authority row before any firmware exception row. Every
/// lifecycle writer follows this lock order so concurrent request, approval,
/// expiry reconciliation, recalc, and revocation cannot deadlock or race scope.
pub async fn get_device_for_update(
    conn: &mut PgConnection,
    id: &str,
) -> Result<Option<FirmwareRecord>, sqlx::Error> {
    let row: Option<FirmwareRecordRow> = sqlx::query_as(&format!(
        "SELECT {RECORD_COLUMNS} FROM firmware_records WHERE id = $1 FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    row.map(FirmwareRecordRow::into_model).transpose()
}

/// Resolve an exception's immutable parent before taking locks. Callers then
/// lock the device first and the exception second.
pub async fn exception_device_id(
    pool: &PgPool,
    exception_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT device_id FROM firmware_exceptions WHERE id = $1")
        .bind(exception_id)
        .fetch_optional(pool)
        .await
}

async fn expire_open_exception(
    conn: &mut PgConnection,
    device_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE firmware_exceptions \
         SET status = 'Expired', version = version + 1 \
         WHERE device_id = $1 AND status IN ('Pending', 'Approved') \
           AND expiry_date < CURRENT_DATE",
    )
    .bind(device_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Recalculate inside the caller's transaction. Expiry is first reconciled
/// under the device lock, then the approved exception fact and database date
/// drive the pure engine calculation. Stored `Exception` is never trusted.
pub async fn recalculate_compliance(
    conn: &mut PgConnection,
    id: &str,
) -> Result<Option<FirmwareRecord>, sqlx::Error> {
    let Some(mut record) = get_device_for_update(conn, id).await? else {
        return Ok(None);
    };
    expire_open_exception(conn, id).await?;
    let row: Option<FirmwareExceptionRow> = sqlx::query_as(&format!(
        "SELECT {EXCEPTION_COLUMNS} FROM firmware_exceptions \
         WHERE device_id = $1 AND status = 'Approved' FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    let exception = row.map(FirmwareExceptionRow::into_model).transpose()?;
    let today: NaiveDate = sqlx::query_scalar("SELECT CURRENT_DATE")
        .fetch_one(&mut *conn)
        .await?;
    let new_status = ryuki_engine::firmware_lifecycle::calculated_status_with_exception_at(
        &record,
        exception.as_ref(),
        today,
    )
    .map_err(engine_error)?;
    sqlx::query(
        "UPDATE firmware_records SET compliance_status = $2, updated_at = NOW() WHERE id = $1",
    )
    .bind(id)
    .bind(new_status.to_string())
    .execute(&mut *conn)
    .await?;
    record.compliance_status = new_status;
    Ok(Some(record))
}

/// Create a Pending request. The maker is a server-derived identity and creation
/// does not grant authority or change the device status. The expiry is computed
/// by PostgreSQL, never by a caller or process-local clock.
pub async fn request_exception(
    conn: &mut PgConnection,
    device_id: &str,
    reason: &str,
    requested_by: &str,
    expiry_days: i32,
) -> Result<RequestExceptionOutcome, sqlx::Error> {
    if get_device_for_update(conn, device_id).await?.is_none() {
        return Ok(RequestExceptionOutcome::MissingDevice);
    }
    expire_open_exception(conn, device_id).await?;
    let open_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM firmware_exceptions \
         WHERE device_id = $1 AND status IN ('Pending', 'Approved'))",
    )
    .bind(device_id)
    .fetch_one(&mut *conn)
    .await?;
    if open_exists {
        return Ok(RequestExceptionOutcome::Conflict);
    }
    let exception_id = format!("fwex-{}", Uuid::new_v4());
    let row: FirmwareExceptionRow = sqlx::query_as(&format!(
        "INSERT INTO firmware_exceptions \
            (id, device_id, reason, requested_by, approved_by, expiry_date, status, version) \
         VALUES ($1, $2, $3, $4, NULL, CURRENT_DATE + $5::int, 'Pending', 1) \
         RETURNING {EXCEPTION_COLUMNS}"
    ))
    .bind(&exception_id)
    .bind(device_id)
    .bind(reason)
    .bind(requested_by.trim())
    .bind(expiry_days)
    .fetch_one(&mut *conn)
    .await?;
    Ok(RequestExceptionOutcome::Created(row.into_model()?))
}

/// Transition one unexpired Pending request to Approved with a distinct checker.
/// The expected version, state, expiry, and actor separation are repeated in the
/// UPDATE predicate and database trigger; the device cache changes in the same
/// caller-owned transaction.
pub async fn approve_exception(
    conn: &mut PgConnection,
    exception_id: &str,
    expected_version: i64,
    approved_by: &str,
) -> Result<ApproveExceptionOutcome, sqlx::Error> {
    let device_id: Option<String> =
        sqlx::query_scalar("SELECT device_id FROM firmware_exceptions WHERE id = $1")
            .bind(exception_id)
            .fetch_optional(&mut *conn)
            .await?;
    let Some(device_id) = device_id else {
        return Ok(ApproveExceptionOutcome::NotFound);
    };
    if get_device_for_update(conn, &device_id).await?.is_none() {
        return Err(engine_error(
            "firmware exception parent device is missing".into(),
        ));
    }
    let row: Option<FirmwareExceptionRow> = sqlx::query_as(&format!(
        "SELECT {EXCEPTION_COLUMNS} FROM firmware_exceptions WHERE id = $1 FOR UPDATE"
    ))
    .bind(exception_id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else {
        return Ok(ApproveExceptionOutcome::NotFound);
    };
    let today: NaiveDate = sqlx::query_scalar("SELECT CURRENT_DATE")
        .fetch_one(&mut *conn)
        .await?;
    if row.status == "Pending" && row.expiry_date < today {
        sqlx::query(
            "UPDATE firmware_exceptions \
             SET status = 'Expired', version = version + 1 \
             WHERE id = $1 AND status = 'Pending' AND version = $2 \
               AND expiry_date < CURRENT_DATE",
        )
        .bind(exception_id)
        .bind(row.version)
        .execute(&mut *conn)
        .await?;
        return Ok(ApproveExceptionOutcome::Conflict);
    }
    if row.requested_by.trim() == approved_by.trim() {
        return Ok(ApproveExceptionOutcome::SelfApproval);
    }
    if row.status != "Pending" || row.version != expected_version {
        return Ok(ApproveExceptionOutcome::Conflict);
    }
    let approved: Option<FirmwareExceptionRow> = sqlx::query_as(&format!(
        "UPDATE firmware_exceptions \
         SET status = 'Approved', approved_by = $3, version = version + 1 \
         WHERE id = $1 AND status = 'Pending' AND version = $2 \
           AND expiry_date >= CURRENT_DATE AND BTRIM(requested_by) <> BTRIM($3) \
         RETURNING {EXCEPTION_COLUMNS}"
    ))
    .bind(exception_id)
    .bind(expected_version)
    .bind(approved_by.trim())
    .fetch_optional(&mut *conn)
    .await?;
    let Some(approved) = approved else {
        return Ok(ApproveExceptionOutcome::Conflict);
    };
    sqlx::query(
        "UPDATE firmware_records SET compliance_status = 'Exception', updated_at = NOW() \
         WHERE id = $1",
    )
    .bind(&approved.device_id)
    .execute(&mut *conn)
    .await?;
    Ok(ApproveExceptionOutcome::Approved(approved.into_model()?))
}

/// Revoke one currently Approved exception without deleting its evidence. The
/// underlying device status is recomputed under the same DB date and transaction.
pub async fn revoke_exception(
    conn: &mut PgConnection,
    exception_id: &str,
) -> Result<RevokeExceptionOutcome, sqlx::Error> {
    let device_id: Option<String> =
        sqlx::query_scalar("SELECT device_id FROM firmware_exceptions WHERE id = $1")
            .bind(exception_id)
            .fetch_optional(&mut *conn)
            .await?;
    let Some(device_id) = device_id else {
        return Ok(RevokeExceptionOutcome::NotFound);
    };
    let Some(mut device) = get_device_for_update(conn, &device_id).await? else {
        return Err(engine_error(
            "firmware exception parent device is missing".into(),
        ));
    };
    let row: Option<FirmwareExceptionRow> = sqlx::query_as(&format!(
        "SELECT {EXCEPTION_COLUMNS} FROM firmware_exceptions WHERE id = $1 FOR UPDATE"
    ))
    .bind(exception_id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else {
        return Ok(RevokeExceptionOutcome::NotFound);
    };
    if row.status != "Approved" {
        return Ok(RevokeExceptionOutcome::Conflict);
    }
    let revoked: FirmwareExceptionRow = sqlx::query_as(&format!(
        "UPDATE firmware_exceptions \
         SET status = 'Revoked', version = version + 1 \
         WHERE id = $1 AND status = 'Approved' AND version = $2 \
         RETURNING {EXCEPTION_COLUMNS}"
    ))
    .bind(exception_id)
    .bind(row.version)
    .fetch_one(&mut *conn)
    .await?;
    let today: NaiveDate = sqlx::query_scalar("SELECT CURRENT_DATE")
        .fetch_one(&mut *conn)
        .await?;
    device.compliance_status =
        ryuki_engine::firmware_lifecycle::calculated_status_with_exception_at(&device, None, today)
            .map_err(engine_error)?;
    sqlx::query(
        "UPDATE firmware_records \
         SET compliance_status = $2, updated_at = NOW() WHERE id = $1",
    )
    .bind(&device.id)
    .bind(device.compliance_status.to_string())
    .execute(&mut *conn)
    .await?;
    Ok(RevokeExceptionOutcome::Revoked {
        exception: revoked.into_model()?,
        device: Box::new(device),
    })
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
    use crate::database::DB_TEST_SERIAL;
    use ryuki_engine::firmware_lifecycle::{ComplianceStatus, FirmwareExceptionStatus};

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
    async fn test_list_devices_contains_seeded_fixture_and_paginates_snapshot() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        // Keep the count/list/page reads stable without creating any fixture
        // rows that would need cleanup. PostgreSQL releases this lock when the
        // transaction is explicitly rolled back or dropped during a panic.
        let mut snapshot_guard = pool.begin().await.expect("begin firmware snapshot guard");
        sqlx::query("LOCK TABLE firmware_records IN SHARE MODE")
            .execute(&mut *snapshot_guard)
            .await
            .expect("lock firmware records against concurrent fixture writes");

        const MIGRATION_071_DEVICE_IDS: [&str; 9] = [
            "fw-defra-srv-001",
            "fw-defra-sw-001",
            "fw-defra-pdu-001",
            "fw-gblon-srv-001",
            "fw-gblon-sw-001",
            "fw-gblon-crac-001",
            "fw-deber-fw-001",
            "fw-deber-srv-001",
            "fw-deber-pdu-001",
        ];

        // The shared integration database may legitimately contain records
        // created by another test or retained after a prior panic. Derive the
        // global list/count assertions from one serialized snapshot, and scope
        // the migration assertion to the fixture's stable primary keys.
        let total = count_devices(&pool, "").await.expect("count_devices");
        assert!(
            total >= MIGRATION_071_DEVICE_IDS.len() as i64,
            "the database must contain every migration 071 fixture record"
        );
        let devices = list_devices(&pool, "", total, 0)
            .await
            .expect("list_devices failed");
        assert_eq!(
            i64::try_from(devices.len()).expect("firmware record count fits i64"),
            total,
            "#14: count_devices matches the full unpaged set"
        );

        let expected_seed_ids: std::collections::BTreeSet<&str> =
            MIGRATION_071_DEVICE_IDS.into_iter().collect();
        let observed_seed_ids: std::collections::BTreeSet<&str> = devices
            .iter()
            .map(|device| device.id.as_str())
            .filter(|id| expected_seed_ids.contains(*id))
            .collect();
        assert_eq!(
            observed_seed_ids, expected_seed_ids,
            "migration 071 firmware fixture is incomplete"
        );

        // #14 pagination: LIMIT bounds the page and OFFSET advances it; the
        // `ORDER BY id` tie-breaker must reproduce the corresponding slices of
        // the same complete snapshot even when unrelated records are present.
        let page1 = list_devices(&pool, "", 4, 0).await.expect("page1");
        let page2 = list_devices(&pool, "", 4, 4).await.expect("page2");
        let expected_page1: Vec<&str> = devices
            .iter()
            .take(4)
            .map(|device| device.id.as_str())
            .collect();
        let expected_page2: Vec<&str> = devices
            .iter()
            .skip(4)
            .take(4)
            .map(|device| device.id.as_str())
            .collect();
        assert_eq!(
            page1
                .iter()
                .map(|device| device.id.as_str())
                .collect::<Vec<_>>(),
            expected_page1,
            "LIMIT 4 returns the first stable id-ordered page"
        );
        assert_eq!(
            page2
                .iter()
                .map(|device| device.id.as_str())
                .collect::<Vec<_>>(),
            expected_page2,
            "OFFSET 4 returns the next stable id-ordered page"
        );

        snapshot_guard
            .rollback()
            .await
            .expect("release firmware snapshot guard");
    }

    #[tokio::test]
    async fn test_get_device_by_id_and_absent() {
        let _serial = DB_TEST_SERIAL.lock().await;
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
        let _serial = DB_TEST_SERIAL.lock().await;
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

        let mut tx = pool.begin().await.expect("begin recalc transaction");
        let updated = recalculate_compliance(&mut tx, "fw-defra-srv-001")
            .await
            .expect("recalculate_compliance failed")
            .expect("fw-defra-srv-001 must exist");
        tx.commit().await.expect("commit recalc transaction");
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
        let mut tx = pool.begin().await.expect("begin absent transaction");
        let absent = recalculate_compliance(&mut tx, "fw-nonexistent")
            .await
            .expect("recalculate for absent id must not error");
        tx.rollback().await.expect("rollback absent transaction");
        assert!(absent.is_none(), "absent id must return None");
    }

    #[tokio::test]
    async fn test_request_requires_distinct_checker_before_authority() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // Use a NonCompliant device for a clean exception request.
        let mut tx = pool.begin().await.expect("begin request transaction");
        let result = request_exception(
            &mut tx,
            "fw-gblon-srv-001",
            "Vendor image pending staged validation",
            "firmware-maker",
            14,
        )
        .await
        .expect("request_exception failed");
        let RequestExceptionOutcome::Created(exc) = result else {
            panic!("known device must create a pending request: {result:?}");
        };
        tx.commit().await.expect("commit pending request");
        assert_eq!(exc.device_id, "fw-gblon-srv-001");
        assert_eq!(exc.requested_by, "firmware-maker");
        assert_eq!(exc.approved_by, None);
        assert_eq!(exc.status, FirmwareExceptionStatus::Pending);
        assert_eq!(exc.version, 1);

        // A request alone never grants authority or changes the device cache.
        let device = get_device(&pool, "fw-gblon-srv-001")
            .await
            .expect("get_device failed")
            .expect("device must exist");
        assert_eq!(device.compliance_status, ComplianceStatus::NonCompliant);

        // The maker cannot approve their own request.
        let mut tx = pool.begin().await.expect("begin self-approval transaction");
        let self_approval = approve_exception(&mut tx, &exc.id, 1, "firmware-maker")
            .await
            .expect("self approval result");
        assert!(matches!(
            self_approval,
            ApproveExceptionOutcome::SelfApproval
        ));
        tx.rollback().await.expect("roll back denied self approval");

        // A distinct checker can approve at the current CAS version.
        let mut tx = pool.begin().await.expect("begin approval transaction");
        let approved = approve_exception(&mut tx, &exc.id, 1, "firmware-checker")
            .await
            .expect("cross-principal approval result");
        let ApproveExceptionOutcome::Approved(approved) = approved else {
            panic!("distinct checker must approve: {approved:?}");
        };
        tx.commit().await.expect("commit approval");
        assert_eq!(approved.status, FirmwareExceptionStatus::Approved);
        assert_eq!(approved.approved_by.as_deref(), Some("firmware-checker"));
        assert_eq!(approved.version, 2);
        let active = get_device(&pool, "fw-gblon-srv-001")
            .await
            .expect("read active device")
            .expect("device exists");
        assert_eq!(active.compliance_status, ComplianceStatus::Exception);

        let mut tx = pool.begin().await.expect("begin cleanup revoke");
        let revoked = revoke_exception(&mut tx, &exc.id)
            .await
            .expect("revoke approved exception");
        assert!(matches!(revoked, RevokeExceptionOutcome::Revoked { .. }));
        tx.commit().await.expect("commit cleanup revoke");
        sqlx::query("SELECT purge_firmware_exceptions_for_maintenance($1)")
            .bind(&exc.device_id)
            .execute(&pool)
            .await
            .expect("purge test exception history as schema owner");
    }

    #[tokio::test]
    async fn test_approval_is_cas_safe_under_concurrency() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let mut tx = pool.begin().await.expect("begin concurrent fixture");
        let outcome = request_exception(
            &mut tx,
            "fw-deber-fw-001",
            "Concurrent decision validation",
            "concurrent-maker",
            7,
        )
        .await
        .expect("request fixture");
        let RequestExceptionOutcome::Created(exc) = outcome else {
            panic!("fixture request must be created: {outcome:?}");
        };
        tx.commit().await.expect("commit concurrent fixture");

        let approve_once = |pool: PgPool, id: String, checker: &'static str| async move {
            let mut tx = pool.begin().await.expect("begin competing approval");
            let outcome = approve_exception(&mut tx, &id, 1, checker)
                .await
                .expect("competing approval result");
            tx.commit().await.expect("commit competing approval");
            outcome
        };
        let (first, second) = tokio::join!(
            approve_once(pool.clone(), exc.id.clone(), "checker-a"),
            approve_once(pool.clone(), exc.id.clone(), "checker-b")
        );
        let approved_count = [&first, &second]
            .into_iter()
            .filter(|outcome| matches!(outcome, ApproveExceptionOutcome::Approved(_)))
            .count();
        let conflict_count = [&first, &second]
            .into_iter()
            .filter(|outcome| matches!(outcome, ApproveExceptionOutcome::Conflict))
            .count();
        assert_eq!(approved_count, 1, "exactly one checker wins the CAS");
        assert_eq!(conflict_count, 1, "the stale checker is rejected");

        let mut tx = pool.begin().await.expect("begin concurrent cleanup");
        let _ = revoke_exception(&mut tx, &exc.id).await;
        tx.commit().await.expect("commit concurrent cleanup");
        sqlx::query("SELECT purge_firmware_exceptions_for_maintenance($1)")
            .bind(&exc.device_id)
            .execute(&pool)
            .await
            .expect("purge concurrent fixture as schema owner");
    }

    #[tokio::test]
    async fn test_database_expiry_boundary_is_inclusive() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let device_id = format!("fw-expiry-boundary-{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO firmware_records \
                (id, device_type, vendor, model, current_version, minimum_version, \
                 latest_version, eol_date, site, compliance_status) \
             VALUES ($1, 'Server', 'TestVendor', 'TestModel', '1.0', '2.0', '2.0', \
                     to_char(CURRENT_DATE + 365, 'YYYY-MM-DD'), 'TEST', 'NonCompliant')",
        )
        .bind(&device_id)
        .execute(&pool)
        .await
        .expect("seed boundary device");

        // The public validator requires at least one day. This repository-level
        // fixture deliberately uses zero so expiry_date == CURRENT_DATE and
        // proves the database predicate treats the final date as inclusive.
        let mut tx = pool.begin().await.expect("begin boundary request");
        let requested = request_exception(
            &mut tx,
            &device_id,
            "Inclusive expiry boundary",
            "boundary-maker",
            0,
        )
        .await
        .expect("create boundary request");
        let RequestExceptionOutcome::Created(exception) = requested else {
            panic!("boundary request must be created: {requested:?}");
        };
        let approved = approve_exception(&mut tx, &exception.id, 1, "boundary-checker")
            .await
            .expect("approve at inclusive boundary");
        assert!(matches!(approved, ApproveExceptionOutcome::Approved(_)));
        tx.commit().await.expect("commit boundary approval");

        let active = list_active_exceptions(&pool)
            .await
            .expect("list boundary authority");
        assert!(active.iter().any(|row| row.id == exception.id));

        let mut tx = pool.begin().await.expect("begin boundary cleanup");
        let _ = revoke_exception(&mut tx, &exception.id).await;
        tx.commit().await.expect("commit boundary cleanup");
        sqlx::query("SELECT purge_firmware_exceptions_for_maintenance($1)")
            .bind(&device_id)
            .execute(&pool)
            .await
            .expect("purge boundary exception history as schema owner");
        sqlx::query("DELETE FROM firmware_records WHERE id = $1")
            .bind(&device_id)
            .execute(&pool)
            .await
            .expect("delete boundary fixture");
    }

    #[tokio::test]
    async fn test_legacy_rows_are_never_active_authority() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let exceptions = list_active_exceptions(&pool)
            .await
            .expect("list_active_exceptions failed");
        assert!(
            exceptions
                .iter()
                .all(|exception| exception.status == FirmwareExceptionStatus::Approved),
            "only explicitly approved rows can be active"
        );
        assert!(!exceptions
            .iter()
            .any(|exception| exception.id == "fwex-gblon-crac-001"));

        let legacy_status: String = sqlx::query_scalar(
            "SELECT status FROM firmware_exceptions WHERE id = 'fwex-gblon-crac-001'",
        )
        .fetch_one(&pool)
        .await
        .expect("read migrated legacy status");
        assert_eq!(legacy_status, "Legacy");
        let device = get_device(&pool, "fw-gblon-crac-001")
            .await
            .expect("read legacy device")
            .expect("legacy device exists");
        assert_ne!(device.compliance_status, ComplianceStatus::Exception);
    }
}
