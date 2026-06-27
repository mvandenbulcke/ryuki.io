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
