//! Repository for the operational domain-event stream (#11).
//!
//! `domain_events` is an append-only operational feed (migration 110), distinct
//! from the compliance-grade `audit_log`. Events are emitted atomically with the
//! state change that produced them (e.g. inside `apply_transition_audited`'s tx),
//! so `insert` takes any `PgExecutor` — the caller passes `&mut *tx` to share its
//! transaction, or `&PgPool` for a standalone write.

/// A new event to append. Borrowed fields so callers can emit without cloning.
/// `payload` carries non-secret references/summary only.
pub struct NewEvent<'a> {
    pub event_type: &'a str,
    pub aggregate_type: &'a str,
    pub aggregate_id: &'a str,
    pub site: Option<&'a str>,
    pub environment: Option<&'a str>,
    pub actor: &'a str,
    pub payload: serde_json::Value,
}

/// Append one event. Returns the new event id. Single-statement, so it accepts
/// any executor (a pooled connection or a borrowed transaction).
pub async fn insert<'e, E>(executor: E, event: NewEvent<'_>) -> Result<i64, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO domain_events \
         (event_type, aggregate_type, aggregate_id, site, environment, actor, payload) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(event.event_type)
    .bind(event.aggregate_type)
    .bind(event.aggregate_id)
    .bind(event.site)
    .bind(event.environment)
    .bind(event.actor)
    .bind(event.payload)
    .fetch_one(executor)
    .await?;
    Ok(id)
}

/// One stored event, as read by the feed endpoint.
#[derive(sqlx::FromRow)]
pub struct EventRow {
    pub id: i64,
    pub event_type: String,
    pub aggregate_type: String,
    pub aggregate_id: String,
    pub site: Option<String>,
    pub environment: Option<String>,
    pub actor: String,
    pub payload: serde_json::Value,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
}

/// List recent events, newest first, optionally filtered by `event_type` and/or
/// `aggregate_id`, and scoped to a principal's `site_scopes` / `env_scopes`.
///
/// Scope is pushed into SQL (NOT filtered in the caller after the fact) so the
/// `LIMIT` only ever counts rows the principal may see — otherwise a scoped
/// principal could get a short page when the DB's top-N included out-of-scope
/// rows. The predicate mirrors `ryuki_engine::auth::scope_permits`: an EMPTY
/// scope list is unrestricted (sees every value), and a NULL column (a
/// platform-wide event) is visible to everyone. `limit` bounds the page; the
/// `id` tiebreaker keeps ordering stable within an `occurred_at`.
pub async fn list(
    pool: &sqlx::PgPool,
    event_type: Option<&str>,
    aggregate_id: Option<&str>,
    site_scopes: &[String],
    env_scopes: &[String],
    limit: i64,
) -> Result<Vec<EventRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, event_type, aggregate_type, aggregate_id, site, environment, actor, \
                payload, occurred_at \
         FROM domain_events \
         WHERE ($1::text IS NULL OR event_type = $1) \
           AND ($2::text IS NULL OR aggregate_id = $2) \
           AND (cardinality($3::text[]) = 0 OR site IS NULL OR site = ANY($3)) \
           AND (cardinality($4::text[]) = 0 OR environment IS NULL OR environment = ANY($4)) \
         ORDER BY occurred_at DESC, id DESC \
         LIMIT $5",
    )
    .bind(event_type)
    .bind(aggregate_id)
    .bind(site_scopes)
    .bind(env_scopes)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// List the alert-worthy slice of the stream (#11 slice 2a/2b): events whose
/// payload `to_status` is in `alert_statuses` (the engine's coarse union of every
/// alert-worthy status across aggregate types). The status filter is pushed into
/// SQL — alerts are rare relative to all events, so an in-memory filter of a
/// recent-N page would return near-empty pages. The caller then applies the
/// PRECISE per-aggregate rule via the engine classifier (dropping any spurious
/// (aggregate, status) pair), so the coarse SQL filter and the per-aggregate
/// labels cannot drift. Same scope semantics as [`list`].
pub async fn list_alerts(
    pool: &sqlx::PgPool,
    aggregate_id: Option<&str>,
    alert_statuses: &[String],
    site_scopes: &[String],
    env_scopes: &[String],
    limit: i64,
) -> Result<Vec<EventRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, event_type, aggregate_type, aggregate_id, site, environment, actor, \
                payload, occurred_at \
         FROM domain_events \
         WHERE payload->>'to_status' = ANY($1) \
           AND ($2::text IS NULL OR aggregate_id = $2) \
           AND (cardinality($3::text[]) = 0 OR site IS NULL OR site = ANY($3)) \
           AND (cardinality($4::text[]) = 0 OR environment IS NULL OR environment = ANY($4)) \
         ORDER BY occurred_at DESC, id DESC \
         LIMIT $5",
    )
    .bind(alert_statuses)
    .bind(aggregate_id)
    .bind(site_scopes)
    .bind(env_scopes)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Acknowledge an alert event (#11 slice 2e): upsert the ack satellite keyed by
/// the `domain_events` row id. Re-acking updates the actor / time / note in place.
/// Returns `Ok(false)` when no such event exists (caller → 404) — distinguished
/// from a genuine DB failure — by checking existence first; the FK would also
/// reject a bad id, but a clean 404 reads better than a constraint error.
/// Fetch a single event's (site, environment) scope tags for an authorization
/// check (#2). Both are nullable (NULL = platform-wide on that axis). Returns
/// `None` when the event id is unknown so the caller can 404 without a separate
/// existence query.
pub async fn event_scope(
    pool: &sqlx::PgPool,
    event_id: i64,
) -> Result<Option<(Option<String>, Option<String>)>, sqlx::Error> {
    sqlx::query_as("SELECT site, environment FROM domain_events WHERE id = $1")
        .bind(event_id)
        .fetch_optional(pool)
        .await
}

pub async fn ack_alert(
    pool: &sqlx::PgPool,
    event_id: i64,
    actor: &str,
    note: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM domain_events WHERE id = $1")
        .bind(event_id)
        .fetch_optional(pool)
        .await?;
    if exists.is_none() {
        return Ok(false);
    }
    sqlx::query(
        "INSERT INTO alert_acks (event_id, acknowledged_by, acknowledged_at, note) \
         VALUES ($1, $2, NOW(), $3) \
         ON CONFLICT (event_id) DO UPDATE SET \
           acknowledged_by = EXCLUDED.acknowledged_by, \
           acknowledged_at = NOW(), \
           note = EXCLUDED.note",
    )
    .bind(event_id)
    .bind(actor)
    .bind(note)
    .execute(pool)
    .await?;
    Ok(true)
}

/// One acknowledgement, as joined onto an alert in the feed.
#[derive(sqlx::FromRow)]
pub struct AckRow {
    pub event_id: i64,
    pub acknowledged_by: String,
    pub acknowledged_at: chrono::DateTime<chrono::Utc>,
}

/// Fetch the acks for a set of alert event ids (the feed merges them in). Empty
/// `ids` short-circuits to an empty result without a query.
pub async fn acks_for(pool: &sqlx::PgPool, ids: &[i64]) -> Result<Vec<AckRow>, sqlx::Error> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as(
        "SELECT event_id, acknowledged_by, acknowledged_at FROM alert_acks WHERE event_id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(pool)
    .await
}
