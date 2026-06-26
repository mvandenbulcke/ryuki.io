//! Repository functions for `site_registry`.
//!
//! # Design: write-through cache
//! The engine's static store is the process-local cache for reads (cross-engine
//! validators call is_valid_site / get_active_site_codes directly). The DB is
//! the durable source of truth for the `active` flag.
//!
//! # Toggle handlers
//! `set_active` is the single write path — it updates the `active` column and
//! returns `true` when a row was found (rows_affected > 0). The handler then
//! calls the engine's activate_site/deactivate_site to keep the static in sync.
//!
//! # Startup hydration
//! `list_active_states` is called once at startup by main() after migrations;
//! the returned vec is passed to `ryuki_engine::site_registry::hydrate_active_states`.
//!
//! # No xmin CAS
//! A boolean toggle is idempotent / last-write-wins, so no optimistic-lock
//! token is needed (unlike lifecycle transitions).

use sqlx::PgPool;

// ─── Row struct ───────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
#[allow(dead_code)]
pub struct SiteEntryRow {
    pub unlocode: String,
    pub name: String,
    pub country: String,
    pub country_code: String,
    pub timezone: String,
    pub active: bool,
}

// ─── Fns ──────────────────────────────────────────────────────────────────────

/// Toggle the active flag for a site.
///
/// Returns `Ok(true)` when the row was found and updated, `Ok(false)` when the
/// unlocode is unknown (the handler maps this to 404).
pub async fn set_active(
    executor: impl sqlx::PgExecutor<'_>,
    unlocode: &str,
    active: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("UPDATE site_registry SET active = $1 WHERE unlocode = $2")
        .bind(active)
        .bind(unlocode)
        .execute(executor)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// Fetch a single site row by unlocode.
#[allow(dead_code)]
pub async fn get(pool: &PgPool, unlocode: &str) -> Result<Option<SiteEntryRow>, sqlx::Error> {
    sqlx::query_as::<_, SiteEntryRow>(
        "SELECT unlocode, name, country, country_code, timezone, active \
         FROM site_registry WHERE unlocode = $1",
    )
    .bind(unlocode)
    .fetch_optional(pool)
    .await
}

/// Load all (unlocode, active) pairs — used by startup hydration.
pub async fn list_active_states(pool: &PgPool) -> Result<Vec<(String, bool)>, sqlx::Error> {
    let rows: Vec<(String, bool)> = sqlx::query_as("SELECT unlocode, active FROM site_registry")
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

// ─── DB integration tests ────────────────────────────────────────────────────
//
// Run with:
//   RYUKI_DATABASE_URL=postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform \
//     cargo test -p ryuki-api -- --test-threads=1 site_registry_db_tests
//
// Tests SKIP when RYUKI_DATABASE_URL is unset; FAIL (panic) if the URL is set
// but connect or migrate fails.
#[cfg(test)]
mod site_registry_db_tests {
    use super::*;
    use crate::database::DB_TEST_SERIAL;
    use ryuki_engine::site_registry as engine;

    /// Returns a FRESH owned pool per test invocation.
    /// Returns `None` only when `RYUKI_DATABASE_URL` is absent or empty —
    /// tests are skipped in that case. If the URL IS set but connect or
    /// migrate fails, this function panics.
    async fn global_pool() -> Option<PgPool> {
        let url = match std::env::var("RYUKI_DATABASE_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!("site_registry_db_tests: RYUKI_DATABASE_URL not set — skipping");
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
    async fn set_active_persists() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        // Use a site that is seeded as active (DEFRA).
        // Deactivate it, verify the DB reflects the change, then restore.
        let found = set_active(pool, "DEFRA", false).await.unwrap();
        assert!(found, "DEFRA must be a known site");
        let row = get(pool, "DEFRA").await.unwrap().expect("row must exist");
        assert!(
            !row.active,
            "DEFRA must be inactive after set_active(false)"
        );

        // Restore.
        set_active(pool, "DEFRA", true).await.unwrap();
        let row2 = get(pool, "DEFRA").await.unwrap().expect("row must exist");
        assert!(row2.active, "DEFRA must be active again after restore");
    }

    #[tokio::test]
    async fn list_active_states_returns_toggle() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        // Set GBLON inactive, then check list_active_states contains it as false.
        set_active(pool, "GBLON", false).await.unwrap();
        let states = list_active_states(pool).await.unwrap();
        let gblon = states
            .iter()
            .find(|(u, _)| u == "GBLON")
            .expect("GBLON must be in states");
        assert!(!gblon.1, "GBLON must appear inactive in list_active_states");

        // Restore.
        set_active(pool, "GBLON", true).await.unwrap();
    }

    #[tokio::test]
    async fn hydration_round_trip_is_valid_site_reflects_persisted_toggle() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        // 1. Set NLAMS inactive in DB.
        set_active(pool, "NLAMS", false).await.unwrap();

        // 2. Load active states from DB and hydrate the engine static.
        let states = list_active_states(pool).await.unwrap();
        engine::hydrate_active_states(&states);

        // 3. The engine's is_valid_site must now return false for NLAMS
        //    (proves the cross-engine read reflects the persisted toggle).
        assert!(
            !engine::is_valid_site("NLAMS"),
            "is_valid_site('NLAMS') must be false after DB set_active(false) + hydrate"
        );

        // 4. Restore DB + engine static.
        set_active(pool, "NLAMS", true).await.unwrap();
        let restored = list_active_states(pool).await.unwrap();
        engine::hydrate_active_states(&restored);
        assert!(
            engine::is_valid_site("NLAMS"),
            "NLAMS must be valid again after restore"
        );
    }

    #[tokio::test]
    async fn set_active_unknown_unlocode_returns_false() {
        let _guard = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let pool = &pool;

        let found = set_active(pool, "ZZZZ9", true).await.unwrap();
        assert!(
            !found,
            "unknown unlocode must return false (rows_affected == 0)"
        );
    }
}
