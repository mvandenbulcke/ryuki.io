//! Repository functions for `configuration_items` (the CMDB, migration 014).
//!
//! This is the FIRST authenticated, DB-backed read of the real CMDB table — every
//! existing `/api/cmdb/*` endpoint serves an in-memory mock (the impact graph) or a
//! hardcoded export, not this table. Callers (handlers in `contracts.rs`) map
//! `sqlx::Error` → 500 and `None` → 404.

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgPool};

const COLUMNS: &str = "ci.id::text AS id, ci.ci_name, ci.ci_type, ci.criticality, \
     ci.site, ci.environment, ci.owner, ci.created_at, ci.updated_at";

/// One configuration item. `id` is the UUID PK as text (so a by-UUID endpoint can be
/// added later); the response carries it for that forward path. `environment`
/// is nullable because migration 168 deliberately leaves inventory whose
/// environment is not authoritatively known unclassified rather than guessing
/// from a CI name. Infra metadata only — no secret/credential material lives in
/// this table.
#[derive(sqlx::FromRow, serde::Serialize)]
pub struct ConfigurationItem {
    pub id: String,
    pub ci_name: String,
    pub ci_type: String,
    pub criticality: String,
    pub site: String,
    pub environment: Option<String>,
    pub owner: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Fetch one CI by its UNIQUE `ci_name` only when its current site has an exact
/// active registry relation and both canonical axes are within the verified
/// principal's scope. Missing, inactive, foreign, and unresolved-environment
/// rows all return `None` so the caller can use one non-enumerating 404.
pub async fn get_authorized_by_name(
    pool: &PgPool,
    ci_name: &str,
    site_scopes: &[String],
    environment_scopes: &[String],
) -> Result<Option<ConfigurationItem>, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} \
         FROM configuration_items AS ci \
         INNER JOIN site_registry AS sr \
                 ON sr.unlocode = ci.site AND sr.active = true \
         WHERE ci.ci_name = $1 \
           AND (cardinality($2::text[]) = 0 OR ci.site = ANY($2)) \
           AND (cardinality($3::text[]) = 0 \
                OR (NULLIF(btrim(ci.environment), '') IS NOT NULL \
                    AND ci.environment = ANY($3)))"
    ))
    .bind(ci_name)
    .bind(site_scopes)
    .bind(environment_scopes)
    .fetch_optional(pool)
    .await
}

/// Resolve one CI by its canonical name only when it is inside the verified
/// principal's site/environment scope. The predicate runs before the row is
/// decoded, and a caller-owned transaction holds a `NO KEY UPDATE` lock so the
/// authoritative site, environment, name, and owner cannot change between
/// authorization and snapshot persistence.
pub async fn get_authorized_by_name_for_no_key_update(
    connection: &mut PgConnection,
    ci_name: &str,
    site_scopes: &[String],
    environment_scopes: &[String],
) -> Result<Option<ConfigurationItem>, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} \
         FROM configuration_items AS ci \
         INNER JOIN site_registry AS sr \
                 ON sr.unlocode = ci.site AND sr.active = true \
         WHERE ci.ci_name = $1 \
           AND (cardinality($2::text[]) = 0 OR ci.site = ANY($2)) \
           AND (cardinality($3::text[]) = 0 \
                OR (NULLIF(btrim(ci.environment), '') IS NOT NULL \
                    AND ci.environment = ANY($3))) \
         FOR NO KEY UPDATE OF ci, sr"
    ))
    .bind(ci_name)
    .bind(site_scopes)
    .bind(environment_scopes)
    .fetch_optional(connection)
    .await
}
