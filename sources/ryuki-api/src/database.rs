use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::OnceLock;
use std::time::Duration;

static POOL: OnceLock<Option<PgPool>> = OnceLock::new();

pub fn get_db() -> Option<&'static PgPool> {
    POOL.get().and_then(|o| o.as_ref())
}

pub struct PoolMetrics {
    pub connected: bool,
    pub size: usize,
    pub idle: usize,
    pub active: usize,
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

pub async fn try_connect_with_url(
    url: &str,
    max_connections: u32,
    min_connections: u32,
    idle_timeout_secs: u64,
    acquire_timeout_secs: u64,
    max_lifetime_secs: u64,
) {
    let pool = match PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(min_connections)
        .idle_timeout(Duration::from_secs(idle_timeout_secs))
        .acquire_timeout(Duration::from_secs(acquire_timeout_secs))
        .max_lifetime(Duration::from_secs(max_lifetime_secs))
        .connect(url)
        .await
    {
        Ok(pool) => {
            tracing::info!("database connected");
            Some(pool)
        }
        Err(e) => {
            tracing::warn!("database unavailable, falling back to in-memory stores: {e}");
            None
        }
    };
    POOL.set(pool).ok();
}

pub async fn migrate_if_connected() {
    if let Some(pool) = get_db() {
        if let Err(e) = run_migrations(pool).await {
            tracing::error!(error = %e, "database migration failed");
        }
    }
}
