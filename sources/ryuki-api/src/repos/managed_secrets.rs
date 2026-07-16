//! Bounded scheduler reads over managed-secret metadata.
//!
//! This module deliberately exposes only the non-sensitive fields required by
//! `secret_rotation_due_scan`.  It never selects `vault_path`, secret type, or
//! credential material.

/// Repository-level ceiling for one secret-rotation scheduler page.
const MAX_SCHEDULER_SCAN_PAGE: i64 = 100;

#[derive(sqlx::FromRow)]
pub struct SecretRotationScanRow {
    pub scan_seq: i64,
    pub id: String,
    pub name: String,
    pub next_rotation_due: String,
    pub status: String,
    pub site: String,
    pub owner: String,
}

/// Bound the current metadata cycle by its largest visible sequence.  Later
/// sequence allocations cannot extend the active cycle; an earlier allocation
/// that commits late is recovered after the cursor resets on exhaustion.
pub async fn rotation_scan_high_water(
    executor: impl sqlx::PgExecutor<'_>,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COALESCE(MAX(scan_seq), 0) \
         FROM managed_secret_scheduler_population",
    )
    .fetch_one(executor)
    .await
}

/// Fetch one bounded raw keyset page before applying rotation eligibility.  The
/// scheduler advances through every population row, including retired/rotating
/// entries, so filtering cannot create cursor gaps or make a short matching page
/// look like population exhaustion. Rows above `high_water_seq` wait for the
/// next cycle.
pub async fn rotation_scan_page(
    executor: impl sqlx::PgExecutor<'_>,
    cursor_seq: i64,
    high_water_seq: i64,
    limit: i64,
) -> Result<Vec<SecretRotationScanRow>, sqlx::Error> {
    if cursor_seq < 0
        || high_water_seq < cursor_seq
        || !(1..=MAX_SCHEDULER_SCAN_PAGE).contains(&limit)
    {
        return Err(sqlx::Error::Protocol(
            "secret-rotation scheduler page requires 0 <= cursor <= high-water and limit 1..=100"
                .to_string(),
        ));
    }
    sqlx::query_as(
        "SELECT population.scan_seq, secret.id, secret.name, \
                secret.next_rotation_due, secret.status, secret.site, secret.owner \
         FROM ( \
             SELECT scan_seq, secret_id \
             FROM managed_secret_scheduler_population \
             WHERE scan_seq > $1 AND scan_seq <= $2 \
             ORDER BY scan_seq \
             LIMIT $3 \
         ) population \
         JOIN managed_secrets secret ON secret.id = population.secret_id \
         ORDER BY population.scan_seq",
    )
    .bind(cursor_seq)
    .bind(high_water_seq)
    .bind(limit)
    .fetch_all(executor)
    .await
}
