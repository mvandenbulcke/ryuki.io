//! Repository functions for `ad_computers`.
//!
//! Ordinary reads use `&PgPool`; mutations and reviewed recovery also accept a
//! caller-owned transaction connection where atomic locking and audit are
//! required. Operational paths expose only Verified rows whose exact persisted
//! owner site is currently active.
//!
//! # CAS design
//! `transition` uses a compare-and-set conditioned on BOTH `expected_status`
//! AND `expected_updated_at` (the `updated_at` timestamp the caller loaded).
//! This prevents a stale write from winning even when status matches: a
//! concurrent move that changes `ou_path` advances `updated_at`, so a stale
//! disable/delete loaded before the move cannot overwrite the moved row.
//!
//! The UPDATE sets `updated_at = NOW()` so the next reader always sees a
//! fresh version token.

use chrono::{DateTime, Utc};
use ryuki_engine::ad_computer_lifecycle::{ADComputer, ComputerStatus};
use ryuki_engine::site_registry::DIRECTORY_NAMESPACE_POLICY_VERSION;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

// ─── Column list ─────────────────────────────────────────────────────────────

/// SELECT column list. UUID → text so sqlx decodes into `String`.
/// `metadata` is cast to text so sqlx decodes it as a raw JSON string;
/// `into_model` deserializes it into `HashMap<String, String>`.
/// `updated_at` is included as the optimistic-version CAS token.
pub const COLUMNS: &str = "id::text AS id, \
     name, \
     site, \
     ou_path, \
     status, \
     last_logon, \
     os, \
     created_at, \
     updated_at, \
     namespace_owner_site, \
     namespace_policy_version, \
     namespace_state, \
     metadata::text AS metadata";

// ─── Row struct ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct AdComputerRow {
    pub id: String,
    pub name: String,
    pub site: String,
    pub ou_path: String,
    pub status: String,
    pub last_logon: DateTime<Utc>,
    pub os: String,
    pub created_at: DateTime<Utc>,
    /// Optimistic-version CAS token — carried by callers into `transition`.
    pub updated_at: DateTime<Utc>,
    pub namespace_owner_site: Option<String>,
    pub namespace_policy_version: Option<String>,
    pub namespace_state: String,
    /// Raw JSON text from `metadata::text` cast.
    pub metadata: String,
}

impl AdComputerRow {
    /// Convert a DB row into the engine model.
    ///
    /// `status` is decoded via serde_json (PascalCase enum names). A parse
    /// failure means the persisted row is corrupt and is surfaced as a decode
    /// error (caller → 500) rather than substituting a default — a CAS
    /// transition against the wrong status string would silently miss.
    ///
    /// `metadata` JSONB is decoded fallibly: a corrupt or non-object JSONB
    /// value is mapped to a decode error (caller → 500) rather than silently
    /// becoming an empty `{}` that a later CAS would overwrite.
    pub fn into_model(self) -> Result<(ADComputer, DateTime<Utc>), sqlx::Error> {
        fn decode_status(raw: &str) -> Result<ComputerStatus, sqlx::Error> {
            serde_json::from_str(&format!("\"{}\"", raw)).map_err(|e| {
                sqlx::Error::Decode(
                    format!("ad_computers.status: corrupt persisted value: {e}").into(),
                )
            })
        }

        let status = decode_status(&self.status)?;
        if self.namespace_state != "Verified" {
            return Err(sqlx::Error::Decode(
                "ad_computers: unverified namespace rows are not operational models".into(),
            ));
        }
        if self.namespace_owner_site.as_deref() != Some(self.site.as_str())
            || self.namespace_policy_version.as_deref() != Some(DIRECTORY_NAMESPACE_POLICY_VERSION)
        {
            return Err(sqlx::Error::Decode(
                "ad_computers: verified namespace provenance is internally inconsistent".into(),
            ));
        }

        let metadata: std::collections::HashMap<String, String> =
            serde_json::from_str(&self.metadata).map_err(|e| {
                sqlx::Error::Decode(
                    format!("ad_computers.metadata: corrupt JSONB value: {e}").into(),
                )
            })?;

        let model = ADComputer {
            id: self.id,
            name: self.name,
            site: self.site,
            ou_path: self.ou_path,
            status,
            last_logon: self.last_logon.to_rfc3339(),
            os: self.os,
            created_at: self.created_at.to_rfc3339(),
            metadata,
        };

        Ok((model, self.updated_at))
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

/// Canonical serde variant name for a `ComputerStatus` as stored in the DB.
/// `pub` so handlers can supply the `expected_status` argument to `transition`
/// without duplicating this table.
pub fn status_str(s: &ComputerStatus) -> &'static str {
    match s {
        ComputerStatus::Active => "Active",
        ComputerStatus::Disabled => "Disabled",
        ComputerStatus::Quarantined => "Quarantined",
        ComputerStatus::Deleted => "Deleted",
    }
}

// ─── Repository functions ─────────────────────────────────────────────────────

/// Fetch one computer by string id. A malformed (non-UUID) id is treated as
/// `Ok(None)` (callers map to 404) rather than an error — keeping not-found
/// behaviour uniform. `Err` is reserved for genuine DB failures (callers → 500).
///
/// Returns `(ADComputer, updated_at)` so callers can thread the version token
/// into a subsequent `transition` call.
#[allow(dead_code)]
pub async fn get(
    pool: &PgPool,
    id: &str,
) -> Result<Option<(ADComputer, DateTime<Utc>)>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<AdComputerRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM ad_computers \
         WHERE id = $1 AND namespace_state = 'Verified' \
           AND EXISTS ( \
                SELECT 1 FROM site_registry AS registry \
                WHERE registry.unlocode = ad_computers.namespace_owner_site \
                  AND registry.active \
                  AND ad_computers.namespace_owner_site = ad_computers.site \
           )"
    ))
    .bind(uid)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Fetch one computer by its unique `name`. Returns `Ok(None)` when no row
/// exists; `Err` for genuine DB failures.
///
/// Returns `(ADComputer, updated_at)` so callers can thread the version token
/// into a subsequent `transition` call.
pub async fn get_by_name(
    pool: &PgPool,
    name: &str,
) -> Result<Option<(ADComputer, DateTime<Utc>)>, sqlx::Error> {
    let row: Option<AdComputerRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM ad_computers \
         WHERE name = $1 AND namespace_state = 'Verified' \
           AND EXISTS ( \
                SELECT 1 FROM site_registry AS registry \
                WHERE registry.unlocode = ad_computers.namespace_owner_site \
                  AND registry.active \
                  AND ad_computers.namespace_owner_site = ad_computers.site \
           )"
    ))
    .bind(name)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Return all computers, optionally filtered by site. An empty `site` returns
/// all rows. Results are ordered by `site, name` for stable pagination.
#[allow(dead_code)]
pub async fn list(pool: &PgPool, site: &str) -> Result<Vec<ADComputer>, sqlx::Error> {
    let rows: Vec<AdComputerRow> = if site.is_empty() {
        sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM ad_computers \
             WHERE namespace_state = 'Verified' \
               AND EXISTS ( \
                SELECT 1 FROM site_registry AS registry \
                WHERE registry.unlocode = ad_computers.namespace_owner_site \
                  AND registry.active \
                  AND ad_computers.namespace_owner_site = ad_computers.site \
             ) ORDER BY site, name"
        ))
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM ad_computers \
             WHERE site = $1 AND namespace_state = 'Verified' \
               AND EXISTS ( \
                    SELECT 1 FROM site_registry AS registry \
                    WHERE registry.unlocode = ad_computers.namespace_owner_site \
                      AND registry.active \
                      AND ad_computers.namespace_owner_site = ad_computers.site \
               ) ORDER BY name"
        ))
        .bind(site)
        .fetch_all(pool)
        .await?
    };

    rows.into_iter()
        .map(|r| r.into_model().map(|(m, _)| m))
        .collect()
}

/// Insert a new computer and return the persisted row. The caller supplies a
/// model with an already-generated UUID string as `id` (from the engine's
/// `prestage_computer` function, which now returns `Uuid::new_v4().to_string()`).
///
/// `last_logon` and `created_at` are bound from the RFC-3339 strings in the
/// model so the response matches the engine-produced timestamps exactly.
/// `metadata` is serialized to JSON and bound as `::jsonb`. `updated_at` is
/// left to the DB default (`NOW()`).
/// Accepts any `sqlx::PgExecutor` — pass `pool` for a standalone call, or
/// `&mut *tx` to share a transaction with an audit write.
pub async fn insert(
    executor: impl sqlx::PgExecutor<'_>,
    r: &ADComputer,
) -> Result<ADComputer, sqlx::Error> {
    let id = Uuid::parse_str(&r.id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let last_logon: DateTime<Utc> = chrono::DateTime::parse_from_rfc3339(&r.last_logon)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let created_at: DateTime<Utc> = chrono::DateTime::parse_from_rfc3339(&r.created_at)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let metadata_json = serde_json::to_string(&r.metadata).unwrap_or_else(|_| "{}".to_string());

    let row: AdComputerRow = sqlx::query_as(&format!(
        "INSERT INTO ad_computers \
         (id, name, site, ou_path, status, last_logon, os, created_at, metadata, \
          namespace_owner_site, namespace_policy_version, namespace_state) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, 'Verified') \
         RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(&r.name)
    .bind(&r.site)
    .bind(&r.ou_path)
    .bind(status_str(&r.status))
    .bind(last_logon)
    .bind(&r.os)
    .bind(created_at)
    .bind(&metadata_json)
    .bind(&r.site)
    .bind(DIRECTORY_NAMESPACE_POLICY_VERSION)
    .fetch_one(executor)
    .await?;

    row.into_model().map(|(m, _)| m)
}

/// Atomically transition a computer to its new state IFF the DB row still
/// matches BOTH `expected_status` AND `expected_updated_at`.
///
/// Using `updated_at` as the version token prevents a stale write from winning
/// even when status matches: any concurrent mutation (move, disable, etc.)
/// advances `updated_at`, so a stale caller loaded before that mutation
/// will not match and receives `Ok(None)` (caller → 409).
///
/// Returns `Ok(None)` when the row is absent or was concurrently modified;
/// returns `Ok(Some((persisted, new_updated_at)))` on success.
///
/// Accepts any `sqlx::PgExecutor<'_>` (pool reference OR `&mut *tx`) so a
/// handler can compose the mutation and an audit row in a single atomic tx.
pub async fn transition(
    executor: impl sqlx::PgExecutor<'_>,
    expected_status: &str,
    expected_updated_at: DateTime<Utc>,
    r: &ADComputer,
) -> Result<Option<(ADComputer, DateTime<Utc>)>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(&r.id) else {
        return Ok(None);
    };

    let metadata_json = serde_json::to_string(&r.metadata).unwrap_or_else(|_| "{}".to_string());

    let row: Option<AdComputerRow> = sqlx::query_as(&format!(
        "UPDATE ad_computers SET \
         name = $2, \
         site = $3, \
         ou_path = $4, \
         status = $5, \
         os = $6, \
         metadata = $7::jsonb, \
         updated_at = NOW() \
         WHERE id = $1 AND status = $8 AND updated_at = $9 \
           AND namespace_state = 'Verified' \
           AND EXISTS ( \
                SELECT 1 FROM site_registry AS registry \
                WHERE registry.unlocode = ad_computers.namespace_owner_site \
                  AND registry.active \
                  AND ad_computers.namespace_owner_site = ad_computers.site \
           ) \
         RETURNING {COLUMNS}"
    ))
    .bind(uid)
    .bind(&r.name)
    .bind(&r.site)
    .bind(&r.ou_path)
    .bind(status_str(&r.status))
    .bind(&r.os)
    .bind(&metadata_json)
    .bind(expected_status)
    .bind(expected_updated_at)
    .fetch_optional(executor)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

// ─── Reviewed quarantine recovery ───────────────────────────────────────────

const RECOVERY_REVIEW_COLUMNS: &str = "id, computer_id, expected_updated_at, reason, \
     requested_by, approved_by, state, expires_at, approved_at";

#[derive(Debug, sqlx::FromRow)]
pub struct QuarantineRecoveryReviewRow {
    pub id: Uuid,
    pub computer_id: Uuid,
    pub expected_updated_at: DateTime<Utc>,
    pub reason: String,
    pub requested_by: String,
    pub approved_by: Option<String>,
    pub state: String,
    pub expires_at: DateTime<Utc>,
    pub approved_at: Option<DateTime<Utc>>,
}

/// Resolve the immutable computer id before acquiring locks. Recovery
/// workflows then lock review rows before the computer row in every path.
pub async fn id_by_name(conn: &mut PgConnection, name: &str) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT id FROM ad_computers \
         WHERE name = $1 AND namespace_state = 'Verified' \
           AND EXISTS ( \
                SELECT 1 FROM site_registry AS registry \
                WHERE registry.unlocode = ad_computers.namespace_owner_site \
                  AND registry.active \
                  AND ad_computers.namespace_owner_site = ad_computers.site \
           )",
    )
    .bind(name)
    .fetch_optional(&mut *conn)
    .await
}

pub async fn get_by_name_for_update(
    conn: &mut PgConnection,
    name: &str,
) -> Result<Option<(ADComputer, DateTime<Utc>, String)>, sqlx::Error> {
    let row: Option<AdComputerRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM ad_computers \
         WHERE name = $1 AND namespace_state = 'Verified' \
           AND EXISTS ( \
                SELECT 1 FROM site_registry AS registry \
                WHERE registry.unlocode = ad_computers.namespace_owner_site \
                  AND registry.active \
                  AND ad_computers.namespace_owner_site = ad_computers.site \
           ) FOR UPDATE"
    ))
    .bind(name)
    .fetch_optional(&mut *conn)
    .await?;

    row.map(|row| {
        let namespace_state = row.namespace_state.clone();
        row.into_model()
            .map(|(computer, updated_at)| (computer, updated_at, namespace_state))
    })
    .transpose()
}

pub async fn get_by_id_for_update(
    conn: &mut PgConnection,
    id: Uuid,
) -> Result<Option<(ADComputer, DateTime<Utc>, String)>, sqlx::Error> {
    let row: Option<AdComputerRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM ad_computers \
         WHERE id = $1 AND namespace_state = 'Verified' \
           AND EXISTS ( \
                SELECT 1 FROM site_registry AS registry \
                WHERE registry.unlocode = ad_computers.namespace_owner_site \
                  AND registry.active \
                  AND ad_computers.namespace_owner_site = ad_computers.site \
           ) FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;

    row.map(|row| {
        let namespace_state = row.namespace_state.clone();
        row.into_model()
            .map(|(computer, updated_at)| (computer, updated_at, namespace_state))
    })
    .transpose()
}

pub async fn expire_recovery_reviews(
    conn: &mut PgConnection,
    computer_id: Uuid,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "WITH writer_contract AS ( \
             SELECT set_config('ryuki.ad_recovery_writer_contract', 'ad-recovery-v2', TRUE) \
         ) \
         UPDATE ad_quarantine_recovery_reviews \
         SET state = 'Expired' \
         FROM writer_contract \
         WHERE computer_id = $1 \
           AND state IN ('Pending', 'Approved') \
           AND expires_at <= NOW()",
    )
    .bind(computer_id)
    .execute(&mut *conn)
    .await?;
    Ok(result.rows_affected())
}

pub async fn create_recovery_review(
    conn: &mut PgConnection,
    computer_id: Uuid,
    expected_updated_at: DateTime<Utc>,
    reason: &str,
    requested_by: &str,
) -> Result<QuarantineRecoveryReviewRow, sqlx::Error> {
    sqlx::query_as(&format!(
        "WITH writer_contract AS ( \
             SELECT set_config('ryuki.ad_recovery_writer_contract', 'ad-recovery-v2', TRUE) \
         ) \
         INSERT INTO ad_quarantine_recovery_reviews \
         (computer_id, expected_updated_at, reason, requested_by, expires_at) \
         SELECT $1, $2, $3, $4, statement_timestamp() + INTERVAL '24 hours' \
         FROM writer_contract \
         RETURNING {RECOVERY_REVIEW_COLUMNS}"
    ))
    .bind(computer_id)
    .bind(expected_updated_at)
    .bind(reason)
    .bind(requested_by)
    .fetch_one(&mut *conn)
    .await
}

pub async fn get_recovery_review_for_update(
    conn: &mut PgConnection,
    review_id: Uuid,
) -> Result<Option<QuarantineRecoveryReviewRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT {RECOVERY_REVIEW_COLUMNS} \
         FROM ad_quarantine_recovery_reviews AS review \
         WHERE id = $1 \
           AND EXISTS ( \
                SELECT 1 \
                FROM ad_computers AS computer \
                JOIN site_registry AS registry \
                  ON registry.unlocode = computer.namespace_owner_site \
                WHERE computer.id = review.computer_id \
                  AND computer.namespace_state = 'Verified' \
                  AND computer.namespace_owner_site = computer.site \
                  AND registry.active \
           ) FOR UPDATE"
    ))
    .bind(review_id)
    .fetch_optional(&mut *conn)
    .await
}

pub async fn approve_recovery_review(
    conn: &mut PgConnection,
    review_id: Uuid,
    approved_by: &str,
) -> Result<Option<QuarantineRecoveryReviewRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        "WITH writer_contract AS ( \
             SELECT set_config('ryuki.ad_recovery_writer_contract', 'ad-recovery-v2', TRUE) \
         ) \
         UPDATE ad_quarantine_recovery_reviews \
         SET state = 'Approved', approved_by = $2 \
         FROM writer_contract \
         WHERE id = $1 AND state = 'Pending' AND expires_at > NOW() \
           AND requested_by <> $2 \
         RETURNING {RECOVERY_REVIEW_COLUMNS}"
    ))
    .bind(review_id)
    .bind(approved_by)
    .fetch_optional(&mut *conn)
    .await
}

pub async fn mark_recovery_review_applied(
    conn: &mut PgConnection,
    review_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "WITH writer_contract AS ( \
             SELECT set_config('ryuki.ad_recovery_writer_contract', 'ad-recovery-v2', TRUE) \
         ) \
         UPDATE ad_quarantine_recovery_reviews \
         SET state = 'Applied' \
         FROM writer_contract \
         WHERE id = $1 AND state = 'Approved' AND expires_at > NOW()",
    )
    .bind(review_id)
    .execute(&mut *conn)
    .await?;
    Ok(result.rows_affected() == 1)
}

// ─── DB integration tests ────────────────────────────────────────────────────
//
// Run with:
//   RYUKI_DATABASE_URL=postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform \
//     cargo test -p ryuki-api -- --test-threads=1 ad_computers_db_tests
//
// Tests SKIP when RYUKI_DATABASE_URL is unset; FAIL (panic) if the URL is set
// but connect or migrate fails — a migration error must not be silently skipped.
#[cfg(test)]
mod ad_computers_db_tests {
    use super::*;
    use ryuki_engine::ad_computer_lifecycle::{
        delete_computer_model, disable_computer_model, enable_computer_model, move_computer_model,
        prestage_computer, release_quarantine_model, QuarantineRecoveryDecision,
    };

    // Serializes DB tests so they don't contend on shared rows.
    static DB_TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Returns `None` only when `RYUKI_DATABASE_URL` is absent or empty —
    /// tests are skipped in that case. If the URL IS set but connect or migrate
    /// fails, this function panics so the failure is never silently swallowed.
    async fn test_pool() -> Option<PgPool> {
        let url = std::env::var("RYUKI_DATABASE_URL").ok()?;
        if url.is_empty() {
            return None;
        }
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("RYUKI_DATABASE_URL is set but connection failed");
        crate::database::run_migrations(&pool)
            .await
            .expect("migrations must apply");
        Some(pool)
    }

    async fn cleanup(pool: &PgPool, id: &str) {
        if let Ok(uid) = Uuid::parse_str(id) {
            sqlx::query("SELECT purge_ad_recovery_reviews_for_maintenance($1)")
                .bind(uid)
                .execute(pool)
                .await
                .ok();
            sqlx::query("DELETE FROM ad_computers WHERE id = $1")
                .bind(uid)
                .execute(pool)
                .await
                .ok();
        }
    }

    // ── round_trip ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn round_trip() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let sequence = 1000 + (Uuid::new_v4().as_u128() % 9000) as u16;
        let name = format!("DEFRA-SRV-{sequence:04}");
        let computer = prestage_computer(&name, "DEFRA", "OU=Servers,OU=DEFRA,DC=corp,DC=local")
            .expect("prestage");

        let persisted = insert(&pool, &computer).await.expect("insert");
        assert_eq!(persisted.name, name);
        assert_eq!(persisted.site, "DEFRA");
        assert_eq!(persisted.status, ComputerStatus::Active);
        assert_eq!(persisted.ou_path, "OU=Servers,OU=DEFRA,DC=corp,DC=local");

        let (fetched, _) = get_by_name(&pool, &name)
            .await
            .expect("get_by_name")
            .expect("row exists");
        assert_eq!(fetched.id, persisted.id);
        assert_eq!(fetched.status, ComputerStatus::Active);

        cleanup(&pool, &persisted.id).await;
    }

    // ── disable_transition ────────────────────────────────────────────────────

    #[tokio::test]
    async fn disable_transition() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let computer = prestage_computer(
            "DEFRA-SRV-92",
            "DEFRA",
            "OU=Servers,OU=DEFRA,DC=corp,DC=local",
        )
        .expect("prestage");
        let _inserted = insert(&pool, &computer).await.expect("insert");
        let (persisted, updated_at) = get_by_name(&pool, "DEFRA-SRV-92")
            .await
            .expect("get_by_name")
            .expect("row exists");

        let updated =
            disable_computer_model(&persisted, "Scheduled maintenance").expect("disable_model");
        let before = status_str(&persisted.status);
        let (after, _) = transition(&pool, before, updated_at, &updated)
            .await
            .expect("transition")
            .expect("row updated");

        assert_eq!(after.status, ComputerStatus::Disabled);
        assert_eq!(
            after.metadata.get("disable_reason").map(String::as_str),
            Some("Scheduled maintenance")
        );

        cleanup(&pool, &persisted.id).await;
    }

    // ── enable_transition ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn enable_transition() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let computer = prestage_computer(
            "DEFRA-SRV-93",
            "DEFRA",
            "OU=Servers,OU=DEFRA,DC=corp,DC=local",
        )
        .expect("prestage");
        let _inserted = insert(&pool, &computer).await.expect("insert");
        let (persisted, updated_at_0) = get_by_name(&pool, "DEFRA-SRV-93")
            .await
            .expect("get_by_name")
            .expect("row exists");

        // First disable it.
        let disabled = disable_computer_model(&persisted, "Test").expect("disable_model");
        let before_disable = status_str(&persisted.status);
        let (disabled_persisted, updated_at_1) =
            transition(&pool, before_disable, updated_at_0, &disabled)
                .await
                .expect("disable transition")
                .expect("row updated");
        assert_eq!(disabled_persisted.status, ComputerStatus::Disabled);

        // Now enable it.
        let enabled = enable_computer_model(&disabled_persisted).expect("enable_model");
        let before_enable = status_str(&disabled_persisted.status);
        let (enabled_persisted, _) = transition(&pool, before_enable, updated_at_1, &enabled)
            .await
            .expect("enable transition")
            .expect("row updated");
        assert_eq!(enabled_persisted.status, ComputerStatus::Active);
        assert!(!enabled_persisted.metadata.contains_key("disable_reason"));

        cleanup(&pool, &persisted.id).await;
    }

    // ── delete_transition ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_transition() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let computer = prestage_computer(
            "DEFRA-SRV-94",
            "DEFRA",
            "OU=Servers,OU=DEFRA,DC=corp,DC=local",
        )
        .expect("prestage");
        let _inserted = insert(&pool, &computer).await.expect("insert");
        let (persisted, updated_at) = get_by_name(&pool, "DEFRA-SRV-94")
            .await
            .expect("get_by_name")
            .expect("row exists");

        let deleted = delete_computer_model(&persisted).expect("delete_model");
        let before = status_str(&persisted.status);
        let (after, _) = transition(&pool, before, updated_at, &deleted)
            .await
            .expect("transition")
            .expect("row updated");

        assert_eq!(after.status, ComputerStatus::Deleted);
        // Row is soft-deleted — still retrievable by id.
        let (fetched, _) = get(&pool, &persisted.id)
            .await
            .expect("get")
            .expect("row exists");
        assert_eq!(fetched.status, ComputerStatus::Deleted);

        cleanup(&pool, &persisted.id).await;
    }

    // ── cas_false ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn cas_false() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let computer = prestage_computer(
            "DEFRA-SRV-95",
            "DEFRA",
            "OU=Servers,OU=DEFRA,DC=corp,DC=local",
        )
        .expect("prestage");
        let _inserted = insert(&pool, &computer).await.expect("insert");
        let (persisted, updated_at) = get_by_name(&pool, "DEFRA-SRV-95")
            .await
            .expect("get_by_name")
            .expect("row exists");

        // Supply the wrong expected_status — transition should return Ok(None).
        let disabled = disable_computer_model(&persisted, "CAS test").expect("disable_model");
        let result = transition(&pool, "Disabled", updated_at, &disabled)
            .await
            .expect("no db error");

        assert!(result.is_none(), "CAS with wrong status should return None");

        cleanup(&pool, &persisted.id).await;
    }

    // ── move_transition ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn move_transition() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let computer = prestage_computer(
            "DEFRA-SRV-96",
            "DEFRA",
            "OU=Servers,OU=DEFRA,DC=corp,DC=local",
        )
        .expect("prestage");
        let _inserted = insert(&pool, &computer).await.expect("insert");
        let (persisted, updated_at) = get_by_name(&pool, "DEFRA-SRV-96")
            .await
            .expect("get_by_name")
            .expect("row exists");

        let moved = move_computer_model(&persisted, "OU=DMZ,OU=DEFRA,DC=corp,DC=local")
            .expect("move_model");

        // CAS: status + updated_at must match.
        let before_status = status_str(&persisted.status);
        let (after, _) = transition(&pool, before_status, updated_at, &moved)
            .await
            .expect("transition")
            .expect("row updated");

        assert_eq!(after.ou_path, "OU=DMZ,OU=DEFRA,DC=corp,DC=local");
        assert_eq!(after.status, ComputerStatus::Active);

        // A second concurrent move with the OLD updated_at should now fail.
        let stale = move_computer_model(&persisted, "OU=Management,OU=DEFRA,DC=corp,DC=local")
            .expect("move_model stale");
        let result = transition(&pool, before_status, updated_at, &stale)
            .await
            .expect("no db error");
        assert!(result.is_none(), "stale updated_at CAS should return None");

        cleanup(&pool, &persisted.id).await;
    }

    // ── stale_updated_at_cas ──────────────────────────────────────────────────
    //
    // Exercises the updated_at version guard directly: load a computer, advance
    // updated_at via a successful transition, then verify that a second transition
    // using the OLD expected_updated_at is rejected.

    #[tokio::test]
    async fn stale_updated_at_cas() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let computer = prestage_computer(
            "DEFRA-SRV-97",
            "DEFRA",
            "OU=Servers,OU=DEFRA,DC=corp,DC=local",
        )
        .expect("prestage");
        let persisted = insert(&pool, &computer).await.expect("insert");
        let (loaded, old_updated_at) = get_by_name(&pool, "DEFRA-SRV-97")
            .await
            .expect("get_by_name")
            .expect("row exists");

        // Advance updated_at via a successful disable transition.
        let disabled = disable_computer_model(&loaded, "advance version").expect("disable_model");
        let before_status = status_str(&loaded.status);
        let (_, new_updated_at) = transition(&pool, before_status, old_updated_at, &disabled)
            .await
            .expect("first transition")
            .expect("first transition succeeded");

        // Sanity: the version token advanced.
        assert_ne!(
            old_updated_at, new_updated_at,
            "updated_at must advance after a transition"
        );

        // Now attempt another transition using the OLD updated_at — must be rejected.
        let delete_attempt = delete_computer_model(&disabled).expect("delete_model");
        let result = transition(&pool, "Disabled", old_updated_at, &delete_attempt)
            .await
            .expect("no db error");

        assert!(
            result.is_none(),
            "transition with stale updated_at must return None"
        );

        cleanup(&pool, &persisted.id).await;
    }

    #[tokio::test]
    async fn namespace_trigger_rejects_cross_site_and_caller_chosen_ou_provenance() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let sequence = 1000 + (Uuid::new_v4().as_u128() % 9000) as u16;
        let name = format!("DEFRA-DEV-{sequence:04}");
        let valid = prestage_computer(&name, "DEFRA", "OU=Development,OU=DEFRA,DC=corp,DC=local")
            .expect("valid server-derived namespace");

        let mut cross_site = valid.clone();
        cross_site.site = "GBLON".into();
        let error = insert(&pool, &cross_site)
            .await
            .expect_err("DB trigger must repeat name/site ownership validation");
        assert!(error.as_database_error().is_some());

        let mut caller_ou = valid.clone();
        caller_ou.id = Uuid::new_v4().to_string();
        caller_ou.ou_path = "OU=Development,OU=GBLON,DC=corp,DC=local".into();
        let error = insert(&pool, &caller_ou)
            .await
            .expect_err("DB trigger must reject a foreign caller-chosen OU");
        assert!(error.as_database_error().is_some());

        let persisted = insert(&pool, &valid)
            .await
            .expect("insert canonical namespace owner");
        let reassigned_name = format!("GBLON-DEV-{sequence:04}");
        let reassignment = sqlx::query(
            "UPDATE ad_computers \
             SET name = $2, site = 'GBLON', namespace_owner_site = 'GBLON', \
                 ou_path = 'OU=Development,OU=GBLON,DC=corp,DC=local' \
             WHERE id = $1",
        )
        .bind(Uuid::parse_str(&persisted.id).expect("persisted id"))
        .bind(&reassigned_name)
        .execute(&pool)
        .await;
        let reassignment_error = reassignment
            .expect_err("verified global computer ownership must not be transferred by update");
        assert!(
            reassignment_error
                .as_database_error()
                .is_some_and(|database| database.message().contains("immutable")),
            "the namespace immutability trigger must be the rejecting control"
        );
        cleanup(&pool, &persisted.id).await;

        let inconsistent_verified: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ad_computers \
             WHERE namespace_state = 'Verified' \
               AND (namespace_owner_site IS DISTINCT FROM site \
                    OR namespace_policy_version IS DISTINCT FROM 'directory-namespace-v1')",
        )
        .fetch_one(&pool)
        .await
        .expect("inspect migrated namespace provenance");
        assert_eq!(
            inconsistent_verified, 0,
            "legacy rows may be verified only when owner provenance is consistent"
        );

        let unsafe_quarantine: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ad_computers \
             WHERE namespace_state = 'Quarantined' \
               AND status NOT IN ('Quarantined', 'Deleted')",
        )
        .fetch_one(&pool)
        .await
        .expect("inspect legacy quarantine state");
        assert_eq!(
            unsafe_quarantine, 0,
            "legacy namespace mismatches must be sticky-quarantined"
        );
    }

    #[test]
    fn inactive_legacy_backfill_requires_active_owners_and_asserts_the_result() {
        let migration =
            include_str!("../../../../migrations/177_directory_namespace_quarantine_recovery.sql");
        assert!(
            migration.contains("COALESCE(registry.active, false)"),
            "AD legacy classification must require an active canonical owner"
        );
        assert!(
            migration.contains("COALESCE(owner.active, false)"),
            "gMSA legacy classification must require the longest owner to be active"
        );
        assert!(
            migration.contains("legacy directory namespace backfill admitted an inactive owner"),
            "migration must fail rather than commit an inactive Verified backfill"
        );
        assert!(
            migration.contains("OLD.namespace_state = 'Quarantined'")
                && migration
                    .contains("quarantined AD namespace provenance requires trusted repair"),
            "a legacy quarantined AD row must not self-promote into operational provenance"
        );
    }

    #[tokio::test]
    async fn deactivation_gates_ad_without_state_change_and_reactivation_restores_verified() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let token = Uuid::new_v4().simple().to_string();
        let site = format!("ADACT{}", &token[..8]).to_ascii_uppercase();
        let site_model = ryuki_engine::site_registry::SiteEntry {
            unlocode: site.clone(),
            name: "AD active-owner gate test".into(),
            country: "Test".into(),
            country_code: "ZZ".into(),
            timezone: "UTC".into(),
            active: true,
        };
        ryuki_engine::site_registry::upsert_site(
            site_model.clone(),
            ryuki_engine::site_registry::SiteCodeSystem::Custom,
        )
        .expect("register active test site in engine cache");
        let site_row = crate::repos::site_registry::SiteEntryRow {
            unlocode: site.clone(),
            code_system: "custom".into(),
            name: site_model.name,
            country: site_model.country,
            country_code: site_model.country_code,
            timezone: site_model.timezone,
            active: true,
        };
        assert!(crate::repos::site_registry::insert(&pool, &site_row)
            .await
            .expect("insert active test site"));

        let sequence = 1000 + (Uuid::new_v4().as_u128() % 9000) as u16;
        let name = format!("{site}-DEV-{sequence:04}");
        let computer = prestage_computer(
            &name,
            &site,
            &format!("OU=Development,OU={site},DC=corp,DC=local"),
        )
        .expect("create canonical active-site computer");
        let persisted = insert(&pool, &computer).await.expect("insert computer");
        let computer_id = Uuid::parse_str(&persisted.id).expect("computer id");
        let (loaded, version) = get_by_name(&pool, &name)
            .await
            .expect("load active computer")
            .expect("active owner exposes verified computer");
        let disabled = disable_computer_model(&loaded, "active-owner gate")
            .expect("prepare ordinary transition");
        let before: (String, String, DateTime<Utc>) = sqlx::query_as(
            "SELECT status, namespace_state, updated_at FROM ad_computers WHERE id = $1",
        )
        .bind(computer_id)
        .fetch_one(&pool)
        .await
        .expect("read state before deactivation");

        assert!(crate::repos::site_registry::set_active(&pool, &site, false)
            .await
            .expect("deactivate owner site"));
        assert!(
            ryuki_engine::site_registry::is_valid_site(&site),
            "stale engine cache remains active to prove DB authority is fail-closed"
        );
        assert!(
            get_by_name(&pool, &name)
                .await
                .expect("inactive lookup")
                .is_none(),
            "ordinary read must hide a Verified resource under an inactive owner"
        );
        assert!(
            list(&pool, &site).await.expect("inactive list").is_empty(),
            "ordinary inventory must hide inactive-owner resources"
        );
        assert!(
            transition(&pool, "Active", version, &disabled)
                .await
                .expect("inactive transition is a clean miss")
                .is_none(),
            "repository mutation must fail closed before touching inactive-owner state"
        );
        let no_op = sqlx::query("UPDATE ad_computers SET status = status WHERE id = $1")
            .bind(computer_id)
            .execute(&pool)
            .await
            .expect_err("DB trigger must fence stale-replica mutation attempts");
        assert!(no_op
            .as_database_error()
            .is_some_and(|database| database.message().contains("active owner site")));
        let mut recovery_tx = pool.begin().await.expect("begin inactive recovery probe");
        let recovery = create_recovery_review(
            &mut recovery_tx,
            computer_id,
            version,
            "inactive owner must block recovery",
            "inactive-owner-maker",
        )
        .await;
        assert!(
            recovery.is_err(),
            "recovery-row trigger must reject an inactive directory owner"
        );
        recovery_tx
            .rollback()
            .await
            .expect("rollback inactive recovery probe");

        let after_block: (String, String, DateTime<Utc>) = sqlx::query_as(
            "SELECT status, namespace_state, updated_at FROM ad_computers WHERE id = $1",
        )
        .bind(computer_id)
        .fetch_one(&pool)
        .await
        .expect("read state after blocked operations");
        assert_eq!(
            after_block, before,
            "deactivation and denials change no resource state"
        );

        assert!(crate::repos::site_registry::set_active(&pool, &site, true)
            .await
            .expect("reactivate owner site"));
        let (reactivated, reactivated_version) = get_by_name(&pool, &name)
            .await
            .expect("reactivated lookup")
            .expect("reactivation restores an unchanged Verified resource");
        assert_eq!(reactivated.status, ComputerStatus::Active);
        assert_eq!(reactivated_version, version);

        cleanup(&pool, &persisted.id).await;
        sqlx::query("DELETE FROM site_registry WHERE unlocode = $1")
            .bind(&site)
            .execute(&pool)
            .await
            .expect("cleanup test site");
        ryuki_engine::site_registry::deactivate_site(&site)
            .expect("deactivate test site in engine cache");
    }

    #[tokio::test]
    async fn concurrent_authorized_claims_keep_one_global_name_winner() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let sequence = 1000 + (Uuid::new_v4().as_u128() % 9000) as u16;
        let name = format!("NLAMS-TEST-{sequence:04}");
        let first = prestage_computer(&name, "NLAMS", "OU=Testing,OU=NLAMS,DC=corp,DC=local")
            .expect("first authorized claim");
        let second = prestage_computer(&name, "NLAMS", "OU=Testing,OU=NLAMS,DC=corp,DC=local")
            .expect("second authorized claim");

        let (left, right) = tokio::join!(insert(&pool, &first), insert(&pool, &second));
        assert_eq!(
            usize::from(left.is_ok()) + usize::from(right.is_ok()),
            1,
            "global uniqueness must serialize two valid first claims"
        );
        let winner = left.as_ref().ok().or_else(|| right.as_ref().ok()).unwrap();
        cleanup(&pool, &winner.id).await;
    }

    #[tokio::test]
    async fn database_quarantine_requires_fresh_maker_checker_review() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let sequence = 1000 + (Uuid::new_v4().as_u128() % 9000) as u16;
        let name = format!("DEFRA-MGMT-{sequence:04}");
        let computer = prestage_computer(&name, "DEFRA", "OU=Management,OU=DEFRA,DC=corp,DC=local")
            .expect("valid computer");
        let persisted = insert(&pool, &computer).await.expect("insert");
        let computer_id = Uuid::parse_str(&persisted.id).unwrap();

        sqlx::query(
            "UPDATE ad_computers \
             SET status = 'Quarantined', \
                 metadata = metadata || '{\"quarantine_reason\":\"synthetic investigation\"}'::jsonb, \
                 updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(computer_id)
        .execute(&pool)
        .await
        .expect("seed quarantine state");

        let unreviewed = sqlx::query(
            "UPDATE ad_computers SET status = 'Disabled', updated_at = NOW() WHERE id = $1",
        )
        .bind(computer_id)
        .execute(&pool)
        .await;
        assert!(
            unreviewed.is_err(),
            "DB trigger must reject ordinary Quarantined -> Disabled"
        );

        let (_, quarantined_at) = get_by_name(&pool, &name)
            .await
            .expect("read quarantine")
            .expect("computer exists");
        let mut create_tx = pool.begin().await.expect("begin review request");
        let review = create_recovery_review(
            &mut create_tx,
            computer_id,
            quarantined_at,
            "reviewed synthetic recovery",
            "recovery-maker",
        )
        .await
        .expect("create recovery review");
        create_tx.commit().await.expect("commit review request");

        let mut approve_tx = pool.begin().await.expect("begin approval");
        let approved = approve_recovery_review(&mut approve_tx, review.id, "recovery-checker")
            .await
            .expect("approve query")
            .expect("distinct checker approves");
        approve_tx.commit().await.expect("commit approval");

        let mut apply_tx = pool.begin().await.expect("begin apply");
        let locked_review = get_recovery_review_for_update(&mut apply_tx, approved.id)
            .await
            .expect("lock review")
            .expect("review exists");
        let (locked, version, namespace_state) = get_by_id_for_update(&mut apply_tx, computer_id)
            .await
            .expect("lock computer")
            .expect("computer exists");
        assert_eq!(namespace_state, "Verified");
        let decision = QuarantineRecoveryDecision {
            review_id: locked_review.id.to_string(),
            reason: locked_review.reason.clone(),
            approved_at: locked_review.approved_at.unwrap().to_rfc3339(),
        };
        let recovered = release_quarantine_model(&locked, &decision).expect("typed release");
        let (after, _) = transition(&mut *apply_tx, "Quarantined", version, &recovered)
            .await
            .expect("release transition")
            .expect("CAS succeeds");
        assert!(
            mark_recovery_review_applied(&mut apply_tx, locked_review.id)
                .await
                .expect("mark applied")
        );
        apply_tx.commit().await.expect("commit recovery");

        assert_eq!(after.status, ComputerStatus::Disabled);
        assert_eq!(
            after.metadata.get("quarantine_reason").map(String::as_str),
            Some("synthetic investigation")
        );
        cleanup(&pool, &persisted.id).await;
    }
}
