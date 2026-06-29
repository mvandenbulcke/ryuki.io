//! Repository functions for `configuration_items` (the CMDB, migration 014).
//!
//! This is the FIRST authenticated, DB-backed read of the real CMDB table — every
//! existing `/api/cmdb/*` endpoint serves an in-memory mock (the impact graph) or a
//! hardcoded export, not this table. Callers (handlers in `contracts.rs`) map
//! `sqlx::Error` → 500 and `None` → 404.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// One configuration item. `id` is the UUID PK as text (so a by-UUID endpoint can be
/// added later); the response carries it for that forward path. All columns are
/// `NOT NULL` in migration 014, so the model has no `Option`s. Infra metadata only — no
/// secret/credential material lives in this table.
#[derive(sqlx::FromRow, serde::Serialize)]
pub struct ConfigurationItem {
    pub id: String,
    pub ci_name: String,
    pub ci_type: String,
    pub criticality: String,
    pub site: String,
    pub owner: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Fetch one CI by its UNIQUE `ci_name`. `None` (caller → 404) when absent. `Err` is
/// reserved for genuine DB failures (caller → 500).
pub async fn get_by_name(
    pool: &PgPool,
    ci_name: &str,
) -> Result<Option<ConfigurationItem>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id::text AS id, ci_name, ci_type, criticality, site, owner, \
                created_at, updated_at \
         FROM configuration_items WHERE ci_name = $1",
    )
    .bind(ci_name)
    .fetch_optional(pool)
    .await
}
