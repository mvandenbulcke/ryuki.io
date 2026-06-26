//! Repository functions for `ad_computers`.
//!
//! All functions are pure over `&PgPool`; callers (handlers in `contracts.rs`)
//! are responsible for mapping `sqlx::Error` → 500 and `None` → 404.
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
use sqlx::PgPool;
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

    let row: Option<AdComputerRow> =
        sqlx::query_as(&format!("SELECT {COLUMNS} FROM ad_computers WHERE id = $1"))
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
        "SELECT {COLUMNS} FROM ad_computers WHERE name = $1"
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
            "SELECT {COLUMNS} FROM ad_computers ORDER BY site, name"
        ))
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM ad_computers WHERE site = $1 ORDER BY name"
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
         (id, name, site, ou_path, status, last_logon, os, created_at, metadata) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb) \
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
        prestage_computer,
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

        let computer = prestage_computer("DEFRA-SRV-91", "DEFRA", "OU=Servers,DC=corp,DC=local")
            .expect("prestage");

        let persisted = insert(&pool, &computer).await.expect("insert");
        assert_eq!(persisted.name, "DEFRA-SRV-91");
        assert_eq!(persisted.site, "DEFRA");
        assert_eq!(persisted.status, ComputerStatus::Active);
        assert_eq!(persisted.ou_path, "OU=Servers,DC=corp,DC=local");

        let (fetched, _) = get_by_name(&pool, "DEFRA-SRV-91")
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

        let computer = prestage_computer("DEFRA-SRV-92", "DEFRA", "OU=Servers,DC=corp,DC=local")
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

        let computer = prestage_computer("DEFRA-SRV-93", "DEFRA", "OU=Servers,DC=corp,DC=local")
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

        let computer = prestage_computer("DEFRA-SRV-94", "DEFRA", "OU=Servers,DC=corp,DC=local")
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

        let computer = prestage_computer("DEFRA-SRV-95", "DEFRA", "OU=Servers,DC=corp,DC=local")
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

        let computer = prestage_computer("DEFRA-SRV-96", "DEFRA", "OU=Servers,DC=corp,DC=local")
            .expect("prestage");
        let _inserted = insert(&pool, &computer).await.expect("insert");
        let (persisted, updated_at) = get_by_name(&pool, "DEFRA-SRV-96")
            .await
            .expect("get_by_name")
            .expect("row exists");

        let moved = move_computer_model(&persisted, "OU=DMZ,DC=corp,DC=local").expect("move_model");

        // CAS: status + updated_at must match.
        let before_status = status_str(&persisted.status);
        let (after, _) = transition(&pool, before_status, updated_at, &moved)
            .await
            .expect("transition")
            .expect("row updated");

        assert_eq!(after.ou_path, "OU=DMZ,DC=corp,DC=local");
        assert_eq!(after.status, ComputerStatus::Active);

        // A second concurrent move with the OLD updated_at should now fail.
        let stale = move_computer_model(&persisted, "OU=Management,DC=corp,DC=local")
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

        let computer = prestage_computer("DEFRA-SRV-97", "DEFRA", "OU=Servers,DC=corp,DC=local")
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
}
