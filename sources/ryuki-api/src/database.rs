use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::OnceLock;

static POOL: OnceLock<Option<PgPool>> = OnceLock::new();

pub fn get_db() -> Option<&'static PgPool> {
    POOL.get().and_then(|o| o.as_ref())
}

pub async fn connect(url: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(5)
        .connect(url)
        .await
        .expect("failed to connect to PostgreSQL")
}

pub async fn run_migrations(pool: &PgPool) {
    sqlx::migrate!("../../migrations")
        .run(pool)
        .await
        .expect("failed to run database migrations");
}

pub async fn try_connect_with_url(url: &str) {
    let pool = match PgPoolOptions::new().max_connections(5).connect(url).await {
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
        run_migrations(pool).await;
    }
}
