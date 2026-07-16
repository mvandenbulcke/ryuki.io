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
/// scope list is unrestricted on that axis, and a value the principal holds
/// matches.
///
/// CROSS-SCOPE RULE (#2 fix). A NULL on an axis means "this event has NO value
/// on that axis" — NOT "visible to everyone scoped on that axis". The old
/// per-axis `IS NULL` clauses leaked a CONCRETE scope value across the OTHER
/// axis, in BOTH directions:
///   * SITE-ONLY events (concrete site, NULL environment — e.g. a decommission,
///     or a site-scoped SLO/budget) reached an ENVIRONMENT-scoped principal: it
///     is unrestricted on the site axis (empty `site_scope` ⇒ `cardinality = 0`)
///     and matched `environment IS NULL`, so it saw every site's events.
///   * ENV-ONLY events (NULL site, concrete environment — e.g. a cross-site
///     SLO/budget) reached a SITE-scoped principal the same way via `site IS
///     NULL`.
///
/// In both cases the mutating handlers fail CLOSED for that principal
/// (`site_scope_guard_or_404`; or `multi_scope_permits`, which denies a scoped
/// principal a row that is NULL on its scoped axis), so the feed was more
/// permissive than the handler.
///
/// The fix is SYMMETRIC: a NULL axis is "platform-wide visible" only when the
/// event is global on BOTH axes (`site IS NULL AND environment IS NULL`). So an
/// event is visible iff, on each axis, the principal is unrestricted OR the
/// event's CONCRETE value is in scope — or the event is genuinely global on both
/// axes (the deliberate observability baseline everyone sees).
///
/// `agent_job` events are the exception to the event row's stored axes. Their
/// authoritative scope is `agent_jobs.spec.request_id -> requests`, just like
/// [`list_alerts`] and [`ack_alert`]. Generic listing must therefore join that
/// relation, project its axes, and fail closed for malformed/orphaned jobs;
/// treating legacy NULL/NULL job events as global would disclose request-bound
/// operations across sites. `limit` bounds the page; the `id` tiebreaker keeps
/// ordering stable within an `occurred_at`.
pub async fn list(
    pool: &sqlx::PgPool,
    event_type: Option<&str>,
    aggregate_id: Option<&str>,
    site_scopes: &[String],
    env_scopes: &[String],
    limit: i64,
) -> Result<Vec<EventRow>, sqlx::Error> {
    // Build the WHERE from ONLY the active scalar filters. The old
    // `($n::text IS NULL OR col = $n)` shape degrades to a sequential scan under
    // a GENERIC prepared plan (sqlx caches prepared statements) — and
    // domain_events is append-only with no retention (migration 111), so it grows
    // without bound. A clean `aggregate_id = $n` predicate lets the planner seek
    // via idx_domain_events_aggregate_id_occurred (migration 144); a clean
    // `event_type = $n` uses idx_domain_events_type. The scope predicates are
    // ALWAYS present (see the SYMMETRIC cross-scope rule documented above) and use
    // bound `= ANY(array)` (not the OR-NULL scalar antipattern). Column names in
    // the format strings are compile-time literals; every value is a BOUND
    // parameter, so this is injection-safe.
    let mut preds: Vec<String> = Vec::new();
    let mut n = 0;
    if event_type.is_some() {
        n += 1;
        preds.push(format!("e.event_type = ${n}"));
    }
    if aggregate_id.is_some() {
        n += 1;
        preds.push(format!("e.aggregate_id = ${n}"));
    }
    let site_pos = {
        n += 1;
        n
    };
    preds.push(format!(
        "((e.aggregate_type = 'agent_job' \
            AND r.id IS NOT NULL \
            AND (cardinality(${site_pos}::text[]) = 0 OR r.site = ANY(${site_pos}))) \
          OR \
          (e.aggregate_type <> 'agent_job' \
            AND (cardinality(${site_pos}::text[]) = 0 OR e.site = ANY(${site_pos}) \
                 OR (e.site IS NULL AND e.environment IS NULL))))"
    ));
    let env_pos = {
        n += 1;
        n
    };
    preds.push(format!(
        "((e.aggregate_type = 'agent_job' \
            AND r.id IS NOT NULL \
            AND (cardinality(${env_pos}::text[]) = 0 OR r.environment = ANY(${env_pos}))) \
          OR \
          (e.aggregate_type <> 'agent_job' \
            AND (cardinality(${env_pos}::text[]) = 0 OR e.environment = ANY(${env_pos}) \
                 OR (e.environment IS NULL AND e.site IS NULL))))"
    ));
    let limit_pos = {
        n += 1;
        n
    };
    let sql = format!(
        "SELECT e.id, e.event_type, e.aggregate_type, e.aggregate_id, \
                CASE WHEN e.aggregate_type = 'agent_job' THEN r.site ELSE e.site END AS site, \
                CASE WHEN e.aggregate_type = 'agent_job' THEN r.environment ELSE e.environment END AS environment, \
                e.actor, e.payload, e.occurred_at \
         FROM domain_events AS e \
         LEFT JOIN agent_jobs AS j \
           ON e.aggregate_type = 'agent_job' \
          AND j.id = CASE \
                WHEN pg_input_is_valid(e.aggregate_id, 'uuid') \
                THEN e.aggregate_id::uuid \
                ELSE NULL \
              END \
         LEFT JOIN requests AS r ON r.id = CASE \
                WHEN pg_input_is_valid(j.spec->>'request_id', 'uuid') \
                THEN (j.spec->>'request_id')::uuid \
                ELSE NULL \
              END \
         WHERE {} \
         ORDER BY e.occurred_at DESC, e.id DESC \
         LIMIT ${limit_pos}",
        preds.join(" AND ")
    );

    // Bind in the SAME order the placeholders were assigned above.
    let mut q = sqlx::query_as::<_, EventRow>(&sql);
    if let Some(et) = event_type {
        q = q.bind(et);
    }
    if let Some(ag) = aggregate_id {
        q = q.bind(ag);
    }
    q.bind(site_scopes)
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
/// labels cannot drift. Same scope semantics as [`list`] — including the
/// SYMMETRIC cross-scope rule: a NULL axis is platform-wide only when BOTH axes
/// are NULL, so a site-only alert (a site-scoped SLO/budget breach) never leaks
/// to an environment-scoped principal, and an env-only alert never leaks to a
/// site-scoped one — matching the handlers that fail closed for each.
///
/// `agent_job` is the exception to the event row's stored axes: jobs are control
/// plane objects, but each job is authoritatively bound to a request.  Their old
/// event emitters stored NULL/NULL and put `request_id` only in caller-readable
/// JSON.  Never trust that payload for authorization.  Join the immutable event
/// aggregate id through `agent_jobs.spec.request_id` to `requests`, fail closed
/// for an orphan/malformed link, apply scope before LIMIT/projection, and project
/// the authoritative request axes into the feed.
pub async fn list_alerts(
    pool: &sqlx::PgPool,
    aggregate_id: Option<&str>,
    alert_statuses: &[String],
    site_scopes: &[String],
    env_scopes: &[String],
    limit: i64,
) -> Result<Vec<EventRow>, sqlx::Error> {
    // `to_status = ANY($1)` (the selective primary filter, served by the mig-138
    // partial expression index) is ALWAYS present. `aggregate_id` is built
    // dynamically — the old `($n::text IS NULL OR aggregate_id = $n)` shape had the
    // same generic-plan seq-scan risk as `list`. Column literals are compile-time;
    // all values are bound parameters.
    let mut preds: Vec<String> = vec!["e.payload->>'to_status' = ANY($1)".to_string()];
    let mut n = 1;
    if aggregate_id.is_some() {
        n += 1;
        preds.push(format!("e.aggregate_id = ${n}"));
    }
    let site_pos = {
        n += 1;
        n
    };
    preds.push(format!(
        "((e.aggregate_type = 'agent_job' \
            AND r.id IS NOT NULL \
            AND (cardinality(${site_pos}::text[]) = 0 OR r.site = ANY(${site_pos}))) \
          OR \
          (e.aggregate_type <> 'agent_job' \
            AND (cardinality(${site_pos}::text[]) = 0 OR e.site = ANY(${site_pos}) \
                 OR (e.site IS NULL AND e.environment IS NULL))))"
    ));
    let env_pos = {
        n += 1;
        n
    };
    preds.push(format!(
        "((e.aggregate_type = 'agent_job' \
            AND r.id IS NOT NULL \
            AND (cardinality(${env_pos}::text[]) = 0 OR r.environment = ANY(${env_pos}))) \
          OR \
          (e.aggregate_type <> 'agent_job' \
            AND (cardinality(${env_pos}::text[]) = 0 OR e.environment = ANY(${env_pos}) \
                 OR (e.environment IS NULL AND e.site IS NULL))))"
    ));
    let limit_pos = {
        n += 1;
        n
    };
    let sql = format!(
        "SELECT e.id, e.event_type, e.aggregate_type, e.aggregate_id, \
                CASE WHEN e.aggregate_type = 'agent_job' THEN r.site ELSE e.site END AS site, \
                CASE WHEN e.aggregate_type = 'agent_job' THEN r.environment ELSE e.environment END AS environment, \
                e.actor, e.payload, e.occurred_at \
         FROM domain_events AS e \
         LEFT JOIN agent_jobs AS j \
           ON e.aggregate_type = 'agent_job' \
          AND j.id = CASE \
                WHEN pg_input_is_valid(e.aggregate_id, 'uuid') \
                THEN e.aggregate_id::uuid \
                ELSE NULL \
              END \
         LEFT JOIN requests AS r ON r.id = CASE \
                WHEN pg_input_is_valid(j.spec->>'request_id', 'uuid') \
                THEN (j.spec->>'request_id')::uuid \
                ELSE NULL \
              END \
         WHERE {} \
         ORDER BY e.occurred_at DESC, e.id DESC \
         LIMIT ${limit_pos}",
        preds.join(" AND ")
    );

    // Bind in the SAME order the placeholders were assigned above.
    let mut q = sqlx::query_as::<_, EventRow>(&sql).bind(alert_statuses);
    if let Some(ag) = aggregate_id {
        q = q.bind(ag);
    }
    q.bind(site_scopes)
        .bind(env_scopes)
        .bind(limit)
        .fetch_all(pool)
        .await
}

/// Acknowledge one alert only when the same SQL statement can prove it is both
/// alert-worthy and in the principal's scope.  The INSERT .. SELECT predicate
/// is the mutation boundary: a denied/missing/non-alert event returns `false`
/// and cannot race between a separate authorization read and the UPSERT.
///
/// Request-linked `agent_job` alerts derive scope from the authoritative
/// `agent_jobs.spec.request_id -> requests` relation, never the independently
/// stored scalar request id, nullable event axes, or payload JSON. Orphaned
/// jobs/events are deliberately indistinguishable from missing rows.
#[allow(clippy::too_many_arguments)]
pub async fn ack_alert(
    pool: &sqlx::PgPool,
    event_id: i64,
    actor: &str,
    note: Option<&str>,
    alert_aggregate_types: &[String],
    alert_statuses: &[String],
    site_scopes: &[String],
    env_scopes: &[String],
) -> Result<bool, sqlx::Error> {
    let acknowledged: Option<i64> = sqlx::query_scalar(
        "INSERT INTO alert_acks (event_id, acknowledged_by, acknowledged_at, note) \
         SELECT e.id, $4, NOW(), $5 \
         FROM domain_events AS e \
         LEFT JOIN agent_jobs AS j \
           ON e.aggregate_type = 'agent_job' \
          AND j.id = CASE \
                WHEN pg_input_is_valid(e.aggregate_id, 'uuid') \
                THEN e.aggregate_id::uuid \
                ELSE NULL \
              END \
         LEFT JOIN requests AS r ON r.id = CASE \
                WHEN pg_input_is_valid(j.spec->>'request_id', 'uuid') \
                THEN (j.spec->>'request_id')::uuid \
                ELSE NULL \
              END \
         WHERE e.id = $1 \
           AND EXISTS ( \
             SELECT 1 \
             FROM unnest($2::text[], $3::text[]) \
                  AS eligible(aggregate_type, to_status) \
             WHERE eligible.aggregate_type = e.aggregate_type \
               AND eligible.to_status = e.payload->>'to_status' \
           ) \
           AND ( \
             (e.aggregate_type = 'agent_job' \
               AND r.id IS NOT NULL \
               AND (cardinality($6::text[]) = 0 OR r.site = ANY($6)) \
               AND (cardinality($7::text[]) = 0 OR r.environment = ANY($7))) \
             OR \
             (e.aggregate_type <> 'agent_job' \
               AND (cardinality($6::text[]) = 0 OR e.site = ANY($6) \
                    OR (e.site IS NULL AND e.environment IS NULL)) \
               AND (cardinality($7::text[]) = 0 OR e.environment = ANY($7) \
                    OR (e.environment IS NULL AND e.site IS NULL))) \
           ) \
         ON CONFLICT (event_id) DO UPDATE SET \
           acknowledged_by = EXCLUDED.acknowledged_by, \
           acknowledged_at = NOW(), \
           note = EXCLUDED.note \
         RETURNING event_id",
    )
    .bind(event_id)
    .bind(alert_aggregate_types)
    .bind(alert_statuses)
    .bind(actor)
    .bind(note)
    .bind(site_scopes)
    .bind(env_scopes)
    .fetch_optional(pool)
    .await?;
    Ok(acknowledged.is_some())
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
