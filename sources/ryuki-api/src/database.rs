use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

static POOL: OnceLock<Option<PgPool>> = OnceLock::new();
static MIGRATION_STATUS: AtomicU8 = AtomicU8::new(MigrationStatus::NotApplied as u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MigrationStatus {
    NotApplied = 0,
    Applied = 1,
    Failed = 2,
}

impl MigrationStatus {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Applied,
            2 => Self::Failed,
            _ => Self::NotApplied,
        }
    }
}

pub fn get_db() -> Option<&'static PgPool> {
    POOL.get().and_then(|o| o.as_ref())
}

pub fn migration_status() -> MigrationStatus {
    MigrationStatus::from_u8(MIGRATION_STATUS.load(Ordering::Acquire))
}

fn set_migration_status(status: MigrationStatus) {
    MIGRATION_STATUS.store(status as u8, Ordering::Release);
}

pub struct PoolMetrics {
    pub connected: bool,
    pub size: usize,
    pub idle: usize,
    pub active: usize,
}

/// Build a platform-health board whose database component reflects a REAL
/// connectivity probe when a pool is configured.
///
/// `health_monitor::run_all_checks()` is a simulated, always-healthy board: its
/// gauge would report `platform-db = 1` even during a total database outage,
/// silently defeating any alert wired to it. When a pool exists this probes it
/// (`SELECT 1`) and folds the real verdict in, so the gauge and aggregate tell
/// the truth. With no pool it returns the simulated board unchanged, so a
/// deliberate dry-run deployment is not misreported as a database outage.
/// Alerting-safe: a probe that errors reports the database `Unhealthy`.
pub async fn live_platform_health() -> ryuki_engine::health_monitor::PlatformHealth {
    use ryuki_engine::health_monitor;
    let mut health = health_monitor::run_all_checks();
    if let Some(pool) = get_db() {
        // Bound the probe so a /metrics scrape can never hang on a saturated or
        // wedged pool up to the 30s acquire timeout: a database that cannot
        // answer SELECT 1 within a few seconds is itself unhealthy. Alerting-safe
        // — a timeout, a query error, or any non-1 answer all map to Unhealthy,
        // never silently healthy.
        let probe = sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(pool);
        let probe_ok = matches!(
            tokio::time::timeout(Duration::from_secs(3), probe).await,
            Ok(Ok(1))
        );
        health_monitor::override_check(
            &mut health,
            health_monitor::database_health_from_probe(probe_ok),
        );
    }
    health
}

pub fn pool_metrics() -> PoolMetrics {
    match get_db() {
        Some(pool) => {
            let size = pool.size() as usize;
            let idle = pool.num_idle();
            let active = size.saturating_sub(idle);
            PoolMetrics {
                connected: true,
                size,
                idle,
                active,
            }
        }
        None => PoolMetrics {
            connected: false,
            size: 0,
            idle: 0,
            active: 0,
        },
    }
}

pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("../../migrations").run(pool).await
}

/// Whether a failed database connection is fatal instead of falling back to
/// in-memory stores (RYUKI_DATABASE__REQUIRED / database.required). Loaded
/// directly from configuration on the failure path so this module does not
/// depend on process startup order; only consulted when connecting fails.
fn database_required() -> bool {
    match ryuki_core::config::RyukiConfig::load() {
        Ok(config) => config.database.required,
        // A malformed unrelated env var must not fail this flag open into the
        // silent in-memory fallback it exists to prevent: read the raw env
        // value directly when full config parsing is unavailable.
        Err(_) => std::env::var("RYUKI_DATABASE__REQUIRED")
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(false),
    }
}

pub async fn try_connect_with_url(
    url: &str,
    max_connections: u32,
    min_connections: u32,
    idle_timeout_secs: u64,
    acquire_timeout_secs: u64,
    max_lifetime_secs: u64,
) {
    // Set-once: `POOL` is a `OnceLock`, so once it has been initialized a second
    // call could neither replace it nor store its pool — it would just open a
    // throwaway connection and drop it. Skip entirely when already initialized.
    // (Matters under test, where global_pool() calls this once per test.)
    if POOL.get().is_some() {
        return;
    }
    let pool = match PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(min_connections)
        .idle_timeout(Duration::from_secs(idle_timeout_secs))
        .acquire_timeout(Duration::from_secs(acquire_timeout_secs))
        .max_lifetime(Duration::from_secs(max_lifetime_secs))
        // #12: bound every statement at the DB so a runaway query (missing index,
        // bad plan, full scan) cannot pin a pool connection until the much-larger
        // request timeout (60-300s) fires and saturate the pool. 30s is generous
        // for this control plane's small-table OLTP and its fast DDL migrations,
        // yet well below the request timeout so the statement aborts first.
        // `lock_timeout` (10s, < statement_timeout) bounds waits on a contended
        // lock specifically — the advisory-chain / row locks are held only
        // briefly, so a longer wait means real pile-up and should fail fast and
        // retry rather than queue behind statement_timeout. Both are
        // session-scoped, set once per physical connection.
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                use sqlx::Executor;
                conn.execute("SET statement_timeout = '30s'; SET lock_timeout = '10s'")
                    .await?;
                Ok(())
            })
        })
        .connect(url)
        .await
    {
        Ok(pool) => {
            tracing::info!("database connected");
            Some(pool)
        }
        Err(e) => {
            if database_required() {
                tracing::error!(
                    "database unavailable and database.required is true; refusing in-memory fallback: {e}"
                );
                std::process::exit(1);
            }
            tracing::warn!("database unavailable, falling back to in-memory stores: {e}");
            None
        }
    };
    POOL.set(pool).ok();
}

pub async fn migrate_if_connected() -> MigrationStatus {
    let Some(pool) = get_db() else {
        set_migration_status(MigrationStatus::NotApplied);
        return MigrationStatus::NotApplied;
    };

    match run_migrations(pool).await {
        Ok(()) => {
            set_migration_status(MigrationStatus::Applied);
            MigrationStatus::Applied
        }
        Err(e) => {
            set_migration_status(MigrationStatus::Failed);
            tracing::error!(error = %e, "database migration failed");
            MigrationStatus::Failed
        }
    }
}

#[cfg(test)]
pub fn set_migration_status_for_test(status: MigrationStatus) {
    set_migration_status(status);
}

/// Process-wide serialization guard for DB-touching integration tests. All
/// tests that connect to and query the live Postgres (the migrations check in
/// `main::db_tests` and the lifecycle/logout/token tests in
/// `contracts::db_lifecycle_tests`) acquire this so they run mutually
/// exclusive — otherwise the shared, small connection pools are exhausted and
/// queries `PoolTimedOut` under `cargo test`'s parallel scheduling.
#[cfg(test)]
pub static DB_TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
mod tests {
    use super::{
        get_db, live_platform_health, migration_status, set_migration_status_for_test,
        try_connect_with_url, MigrationStatus, DB_TEST_SERIAL,
    };
    use ryuki_engine::health_monitor::{HealthSource, HealthStatus};

    /// #12: every pooled connection must carry the per-statement timeout set in
    /// `after_connect`, so a runaway query aborts at the DB instead of pinning a
    /// connection until the request timeout fires.
    #[tokio::test]
    async fn statement_timeout_is_set_on_pool_connections() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Ok(url) = std::env::var("RYUKI_DATABASE_URL") else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        try_connect_with_url(&url, 2, 1, 300, 30, 1800).await;
        let pool = get_db().expect("pool must be connected");
        let stmt: String = sqlx::query_scalar("SHOW statement_timeout")
            .fetch_one(pool)
            .await
            .expect("SHOW statement_timeout");
        assert_eq!(
            stmt, "30s",
            "every pooled connection must carry the 30s statement_timeout from after_connect"
        );
        let lock: String = sqlx::query_scalar("SHOW lock_timeout")
            .fetch_one(pool)
            .await
            .expect("SHOW lock_timeout");
        assert_eq!(
            lock, "10s",
            "every pooled connection must carry the 10s lock_timeout from after_connect"
        );
    }

    #[test]
    fn migration_status_tracks_updates() {
        set_migration_status_for_test(MigrationStatus::NotApplied);
        assert_eq!(migration_status(), MigrationStatus::NotApplied);

        set_migration_status_for_test(MigrationStatus::Applied);
        assert_eq!(migration_status(), MigrationStatus::Applied);

        set_migration_status_for_test(MigrationStatus::Failed);
        assert_eq!(migration_status(), MigrationStatus::Failed);
    }

    #[tokio::test]
    async fn live_platform_health_leaves_db_simulated_without_a_pool() {
        // No pool configured => a deliberate dry-run deployment. The board must
        // NOT be flipped to a database outage: the db component stays the
        // simulated placeholder, so we never page on an intentionally-absent DB.
        // (Skips if some other test in this binary already initialized the pool.)
        if get_db().is_some() {
            eprintln!("SKIP: a database pool is configured in this test binary");
            return;
        }
        let health = live_platform_health().await;
        let db = health
            .checks
            .iter()
            .find(|c| c.component == "platform-db")
            .expect("platform-db check present");
        assert_eq!(db.source, HealthSource::Simulated);
        assert_eq!(db.status, HealthStatus::Healthy);
    }
}
