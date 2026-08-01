//! Durable single-use receipts for authenticated inbound webhook deliveries.
//!
//! The handler claims the delivery, appends the domain event, and binds the two
//! in one transaction. A unique `(connection_id, delivery_id)` key is the
//! concurrency boundary: a losing transaction reads the committed winner and
//! returns its event id only when the authenticated envelope matches exactly.

use sha2::{Digest, Sha256};

pub const CLEANUP_BATCH: i64 = 128;

/// Stable, domain-separated advisory-lock key for one connection-scoped
/// delivery id. A 64-bit hash collision only serializes unrelated deliveries;
/// it cannot weaken replay rejection.
pub fn advisory_lock_key(connection_id: &str, delivery_id: &str) -> i64 {
    let mut hasher = Sha256::new();
    hasher.update(b"ryuki-inbound-webhook-receipt-lock-v1");
    hasher.update((connection_id.len() as u64).to_be_bytes());
    hasher.update(connection_id.as_bytes());
    hasher.update((delivery_id.len() as u64).to_be_bytes());
    hasher.update(delivery_id.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0_u8; 8];
    key.copy_from_slice(&digest[..8]);
    i64::from_be_bytes(key)
}

/// One previously accepted delivery.
#[derive(Debug, sqlx::FromRow)]
pub struct ReceiptRow {
    pub signature_version: i16,
    pub webhook_secret_ref: Option<String>,
    pub webhook_secret_generation: Option<i64>,
    pub authority_context_sha256: Option<String>,
    pub webhook_vendor_type: Option<String>,
    pub webhook_site_scope: Option<String>,
    pub signed_at: chrono::DateTime<chrono::Utc>,
    pub body_sha256: String,
    pub event_id: Option<i64>,
}

/// Mark this transaction as implementing the v2 authority-bound
/// signed-envelope/receipt contract. Migration 207 rejects legacy webhook-event
/// writers that do not set this marker, so deployment overlap fails closed.
pub async fn enable_contract_v2(connection: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config('ryuki.inbound_webhook_contract', '2', true)")
        .execute(connection)
        .await?;
    Ok(())
}

/// Serialize one delivery key for the life of the current transaction.
///
/// This lock is acquired before the authoritative `clock_timestamp()` read.
/// Expiry cleanup attempts the same key without waiting, so it can never remove
/// a receipt while a request has already passed the final freshness boundary.
pub async fn lock_delivery(
    connection: &mut sqlx::PgConnection,
    advisory_lock_key: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(advisory_lock_key)
        .execute(connection)
        .await?;
    Ok(())
}

/// Try to claim an authenticated delivery before appending its event.
///
/// The caller must already hold [`lock_delivery`] and must have checked for an
/// existing receipt. `false` therefore signals an application/database contract
/// violation rather than an ordinary replay race.
#[allow(clippy::too_many_arguments)]
pub async fn try_claim(
    connection: &mut sqlx::PgConnection,
    connection_id: &str,
    delivery_id: &str,
    signature_version: i16,
    webhook_secret_ref: &str,
    webhook_secret_generation: i64,
    authority_context_sha256: &str,
    webhook_vendor_type: &str,
    webhook_site_scope: Option<&str>,
    signed_at: chrono::DateTime<chrono::Utc>,
    body_sha256: &str,
    advisory_lock_key: i64,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<bool, sqlx::Error> {
    let inserted: Option<String> = sqlx::query_scalar(
        "INSERT INTO inbound_webhook_receipts \
         (connection_id, delivery_id, signature_version, webhook_secret_ref, \
          webhook_secret_generation, authority_context_sha256, webhook_vendor_type, \
          webhook_site_scope, signed_at, body_sha256, advisory_lock_key, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
         ON CONFLICT (connection_id, delivery_id) DO NOTHING \
         RETURNING delivery_id",
    )
    .bind(connection_id)
    .bind(delivery_id)
    .bind(signature_version)
    .bind(webhook_secret_ref)
    .bind(webhook_secret_generation)
    .bind(authority_context_sha256)
    .bind(webhook_vendor_type)
    .bind(webhook_site_scope)
    .bind(signed_at)
    .bind(body_sha256)
    .bind(advisory_lock_key)
    .bind(expires_at)
    .fetch_optional(connection)
    .await?;
    Ok(inserted.is_some())
}

/// Remove an expired prior use of this exact delivery id while its advisory
/// lock is held. This permits a sender to reuse an id after the replay window
/// without racing the global cleanup worker.
pub async fn delete_expired_target(
    connection: &mut sqlx::PgConnection,
    connection_id: &str,
    delivery_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM inbound_webhook_receipts \
         WHERE connection_id = $1 AND delivery_id = $2 AND expires_at < $3",
    )
    .bind(connection_id)
    .bind(delivery_id)
    .bind(now)
    .execute(connection)
    .await?;
    Ok(result.rows_affected())
}

/// Lock and read the committed winner after a receipt-key conflict.
pub async fn get_for_update(
    connection: &mut sqlx::PgConnection,
    connection_id: &str,
    delivery_id: &str,
) -> Result<Option<ReceiptRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT signature_version, webhook_secret_ref, webhook_secret_generation, \
                authority_context_sha256, webhook_vendor_type, webhook_site_scope, \
                signed_at, body_sha256, event_id \
         FROM inbound_webhook_receipts \
         WHERE connection_id = $1 AND delivery_id = $2 \
         FOR UPDATE",
    )
    .bind(connection_id)
    .bind(delivery_id)
    .fetch_optional(connection)
    .await
}

/// Bind the winning claim to the event appended in the same transaction.
pub async fn bind_event(
    connection: &mut sqlx::PgConnection,
    connection_id: &str,
    delivery_id: &str,
    event_id: i64,
) -> Result<bool, sqlx::Error> {
    let bound: Option<i64> = sqlx::query_scalar(
        "UPDATE inbound_webhook_receipts \
         SET event_id = $3 \
         WHERE connection_id = $1 AND delivery_id = $2 AND event_id IS NULL \
         RETURNING event_id",
    )
    .bind(connection_id)
    .bind(delivery_id)
    .bind(event_id)
    .fetch_optional(connection)
    .await?;
    Ok(bound == Some(event_id))
}

/// Delete one bounded oldest-first batch outside every accepted freshness
/// window. The worker first row-locks a bounded candidate set, then attempts
/// each candidate's delivery advisory lock without waiting. A live delivery
/// transaction therefore makes cleanup skip its receipt, while cleanup never
/// waits in the opposite lock order and cannot deadlock with claim/event work.
pub async fn cleanup_expired(pool: &sqlx::PgPool) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let now: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    let result = sqlx::query(
        "WITH candidates AS MATERIALIZED ( \
             SELECT connection_id, delivery_id, advisory_lock_key \
             FROM inbound_webhook_receipts \
             WHERE expires_at < $1 \
             ORDER BY expires_at, connection_id, delivery_id \
             LIMIT $2 \
             FOR UPDATE SKIP LOCKED \
         ), unlocked AS MATERIALIZED ( \
             SELECT connection_id, delivery_id \
             FROM candidates \
             WHERE pg_try_advisory_xact_lock(advisory_lock_key) \
         ) \
         DELETE FROM inbound_webhook_receipts AS receipt \
         USING unlocked \
         WHERE receipt.connection_id = unlocked.connection_id \
           AND receipt.delivery_id = unlocked.delivery_id",
    )
    .bind(now)
    .bind(CLEANUP_BATCH)
    .execute(&mut *tx)
    .await?;
    let deleted = result.rows_affected();
    tx.commit().await?;
    Ok(deleted)
}

/// Reclaim expired receipts independently of public requests. Each iteration
/// is time-bounded and deletes at most [`CLEANUP_BATCH`] rows, so anonymous
/// traffic cannot schedule cleanup work and a backlog cannot monopolize the
/// database.
pub fn spawn_cleanup(pool: sqlx::PgPool, interval_secs: u64) {
    const LOOP_NAME: &str = "inbound-webhook-receipt-cleanup";
    tokio::spawn(async move {
        crate::background::register_loop(LOOP_NAME, interval_secs);
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await;
        let timeout = crate::background::iteration_timeout(interval_secs);
        let mut consecutive_failures = 0_u32;
        loop {
            ticker.tick().await;
            match crate::background::run_bounded(timeout, cleanup_expired(&pool)).await {
                Ok(deleted) => {
                    consecutive_failures = 0;
                    crate::background::record_loop_success(LOOP_NAME);
                    tracing::debug!(deleted, "expired webhook receipt cleanup completed");
                }
                Err(error) => {
                    let backoff = crate::background::note_failure(&mut consecutive_failures);
                    match error {
                        crate::background::IterError::Failed(error) => tracing::error!(
                            error = %error,
                            consecutive_failures,
                            backoff_intervals = backoff,
                            "expired webhook receipt cleanup failed; backing off"
                        ),
                        crate::background::IterError::TimedOut => tracing::error!(
                            timeout_secs = timeout.as_secs(),
                            consecutive_failures,
                            backoff_intervals = backoff,
                            "expired webhook receipt cleanup timed out; backing off"
                        ),
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(
                        interval_secs.saturating_mul(backoff),
                    ))
                    .await;
                }
            }
        }
    });
}
