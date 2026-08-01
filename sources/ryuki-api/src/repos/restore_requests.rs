//! Repository functions for `restore_requests`.
//!
//! All functions are pure over `&PgPool`; callers (handlers in `contracts.rs`)
//! are responsible for mapping `sqlx::Error` → 500 and `None` → 404.
//!
//! # Approver column
//! The DB table has an `approver TEXT` column (from migration 007) but the
//! engine model does not expose it directly — the approver is stored in
//! `metadata["approver"]` by `approve_restore`. The repo reads `approver` from
//! `metadata` on insert/transition and writes it back to the DB column so the
//! field is queryable at the DB level. It is never selected into the Row struct.
//!
//! # Audit parameter
//! `transition` accepts an `_audit_action: Option<&str>` parameter for
//! signature parity with the snapshot/patch_waves templates, but restore_requests
//! do not have a dedicated audit table — the parameter is intentionally unused.

use chrono::{DateTime, Utc};
use ryuki_engine::models::{RestoreRequest, RestoreStatus, RestoreType};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

// ─── Column list ─────────────────────────────────────────────────────────────

/// SELECT column list. UUID → text so sqlx binds into String; JSONB → text
/// so we can `serde_json::from_str` it. `approver` is NOT selected into the
/// row — it lives in `metadata["approver"]` in the engine model.
pub const COLUMNS: &str = "id::text AS id, \
     source_ci_key, \
     restore_type, \
     restore_point, \
     target_site, \
     target_environment, \
     verification_plan, \
     retention_need, \
     owner, \
     status, \
     dry_run_plan, \
     metadata::text AS metadata, \
     created_at";

// ─── Row struct ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct RestoreRequestRow {
    pub id: String,
    pub source_ci_key: String,
    pub restore_type: String,
    pub restore_point: String,
    pub target_site: String,
    pub target_environment: String,
    pub verification_plan: String,
    pub retention_need: String,
    pub owner: String,
    pub status: String,
    pub dry_run_plan: Option<String>,
    /// Raw JSON text from JSONB::text cast, e.g. `{"dry_run":"true"}`.
    pub metadata: String,
    /// `created_at` is forwarded to the model. The DB-managed `updated_at`
    /// column is not part of `RestoreRequest`, so it is neither selected nor
    /// decoded (the UPDATE in `transition` still sets it to NOW()).
    pub created_at: DateTime<Utc>,
}

impl RestoreRequestRow {
    /// Convert a DB row into the engine model.
    ///
    /// JSONB-text and enum-name fields are deserialized via `serde_json`. A
    /// parse failure means the persisted row is corrupt; we surface it as a
    /// decode error (caller → 500) rather than silently substituting defaults —
    /// a subsequent `transition` would otherwise persist those defaults over the
    /// real data, since the CAS only guards `status`, not the other columns.
    pub fn into_model(self) -> Result<RestoreRequest, sqlx::Error> {
        fn decode<T: serde::de::DeserializeOwned>(
            raw: &str,
            field: &str,
        ) -> Result<T, sqlx::Error> {
            serde_json::from_str(raw).map_err(|e| {
                sqlx::Error::Decode(
                    format!("restore_requests.{field}: corrupt persisted value: {e}").into(),
                )
            })
        }

        let metadata: std::collections::HashMap<String, String> =
            decode(&self.metadata, "metadata")?;

        // Enum variants are stored as their serde name (e.g. "Planned", "Approved");
        // decode via the engine's Deserialize impl. A DB CHECK constraint
        // (migration 060) keeps these in the legal set.
        let status: RestoreStatus = decode(&format!("\"{}\"", self.status), "status")?;

        // restore_type is stored as the serde name (e.g. "FullVm"); the Display
        // form ("full-vm") is different — we must quote-wrap for JSON decode.
        let restore_type: RestoreType =
            decode(&format!("\"{}\"", self.restore_type), "restore_type")?;

        Ok(RestoreRequest {
            id: self.id,
            source_ci_key: self.source_ci_key,
            restore_type,
            restore_point: self.restore_point,
            target_site: self.target_site,
            target_environment: self.target_environment,
            verification_plan: self.verification_plan,
            retention_need: self.retention_need,
            owner: self.owner,
            status,
            dry_run_plan: self.dry_run_plan,
            created_at: self.created_at.to_rfc3339(),
            metadata,
        })
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

/// Canonical serde variant name for a `RestoreStatus` value as stored in the DB.
/// `pub` so transition handlers can supply `expected_status` without duplicating
/// this table.
pub fn status_str(s: &RestoreStatus) -> &'static str {
    match s {
        RestoreStatus::Draft => "Draft",
        RestoreStatus::Validated => "Validated",
        RestoreStatus::Planned => "Planned",
        RestoreStatus::Approved => "Approved",
        RestoreStatus::Locked => "Locked",
        RestoreStatus::Executed => "Executed",
        RestoreStatus::Verified => "Verified",
        RestoreStatus::Completed => "Completed",
        RestoreStatus::Failed => "Failed",
    }
}

/// Canonical serde variant name for a `RestoreType` value as stored in the DB.
/// These are the PascalCase serde names, NOT the Display "kebab-case" forms.
pub fn restore_type_str(t: &RestoreType) -> &'static str {
    match t {
        RestoreType::FullVm => "FullVm",
        RestoreType::FileLevel => "FileLevel",
        RestoreType::ApplicationItem => "ApplicationItem",
        RestoreType::InstantVmRecovery => "InstantVmRecovery",
    }
}

// ─── Repository functions ─────────────────────────────────────────────────────

/// Server-resolved source authority for one restore plan. Fields are private so
/// application callers cannot manufacture a trusted binding from request text;
/// only [`resolve_authorized_source_for_plan`] constructs this value.
pub struct AuthorizedRestoreSource {
    configuration_item_id: Uuid,
    restore_point_id: Uuid,
    source_ci_key: String,
    captured_at: DateTime<Utc>,
    source_site: String,
    source_environment: String,
}

#[derive(sqlx::FromRow)]
struct AuthorizedRestoreSourceRow {
    configuration_item_id: Uuid,
    restore_point_id: Uuid,
    source_ci_key: String,
    captured_at: DateTime<Utc>,
    source_site: String,
    source_environment: String,
}

impl AuthorizedRestoreSource {
    pub fn source_ci_key(&self) -> &str {
        &self.source_ci_key
    }

    pub fn restore_point(&self) -> String {
        self.captured_at.to_rfc3339()
    }
}

/// Resolve and lock one exact persisted restore point and its current CMDB/site
/// authority. Scope predicates run before materialization, so a caller cannot
/// distinguish a foreign source from a missing source. The caller keeps the CI
/// and site locks through [`insert`]; the insert trigger independently locks
/// and rechecks the select-only restore-point row before granting authority.
pub async fn resolve_authorized_source_for_plan(
    connection: &mut PgConnection,
    source_ci_key: &str,
    captured_at: DateTime<Utc>,
    site_scopes: &[String],
    environment_scopes: &[String],
) -> Result<Option<AuthorizedRestoreSource>, sqlx::Error> {
    let row: Option<AuthorizedRestoreSourceRow> = sqlx::query_as(
        "SELECT ci.id AS configuration_item_id, point.id AS restore_point_id, \
                ci.ci_name AS source_ci_key, point.captured_at, \
                ci.site AS source_site, ci.environment AS source_environment \
         FROM backup_restore_points AS point \
         JOIN configuration_items AS ci ON ci.id = point.configuration_item_id \
         JOIN site_registry AS registry \
           ON registry.unlocode COLLATE \"C\" = ci.site COLLATE \"C\" \
          AND registry.active = TRUE \
         WHERE ci.ci_name COLLATE \"C\" = $1 COLLATE \"C\" \
           AND point.captured_at = $2 \
           AND point.status = 'Available' \
           AND ci.environment IS NOT NULL \
           AND btrim(ci.environment) <> '' \
           AND (cardinality($3::text[]) = 0 OR ci.site COLLATE \"C\" = ANY($3)) \
           AND (cardinality($4::text[]) = 0 OR ci.environment COLLATE \"C\" = ANY($4)) \
         FOR NO KEY UPDATE OF ci \
         FOR SHARE OF registry",
    )
    .bind(source_ci_key)
    .bind(captured_at)
    .bind(site_scopes)
    .bind(environment_scopes)
    .fetch_optional(connection)
    .await?;

    Ok(row.map(|row| AuthorizedRestoreSource {
        configuration_item_id: row.configuration_item_id,
        restore_point_id: row.restore_point_id,
        source_ci_key: row.source_ci_key,
        captured_at: row.captured_at,
        source_site: row.source_site,
        source_environment: row.source_environment,
    }))
}

/// Insert a new restore request and return the persisted row. The caller
/// supplies the model with an already-generated UUID string as `id`; we parse
/// it for the PK.
///
/// `created_at`/`updated_at` are not bound here — the DB column defaults (NOW())
/// own them. We `RETURNING` the inserted row so the returned model carries the
/// DB-authoritative timestamps (the response then matches a subsequent `get`).
///
/// The `approver` column is written from `r.metadata.get("approver")` so it
/// stays queryable at the DB level even though the engine model stores it in
/// metadata.
pub async fn insert(
    executor: impl sqlx::PgExecutor<'_>,
    r: &RestoreRequest,
    source: &AuthorizedRestoreSource,
) -> Result<RestoreRequest, sqlx::Error> {
    let id = Uuid::parse_str(&r.id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let meta = serde_json::to_string(&r.metadata).unwrap_or_else(|_| "{}".into());
    let approver: Option<&String> = r.metadata.get("approver");

    if r.source_ci_key != source.source_ci_key || r.restore_point != source.restore_point() {
        return Err(sqlx::Error::Protocol(
            "restore model does not match its authorized source binding".to_string(),
        ));
    }

    let row: RestoreRequestRow = sqlx::query_as(&format!(
        "INSERT INTO restore_requests \
         (id, source_ci_key, restore_type, restore_point, target_site, target_environment, \
          verification_plan, retention_need, owner, status, dry_run_plan, approver, metadata, \
          authority_state, authority_reason, source_configuration_item_id, restore_point_id, \
          source_site, source_environment, source_scope_provenance) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, \
                 'Verified', NULL, $14, $15, $16, $17, 'backup-restore-point') \
         RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(&r.source_ci_key)
    .bind(restore_type_str(&r.restore_type))
    .bind(&r.restore_point)
    .bind(&r.target_site)
    .bind(&r.target_environment)
    .bind(&r.verification_plan)
    .bind(&r.retention_need)
    .bind(&r.owner)
    .bind(status_str(&r.status))
    .bind(&r.dry_run_plan)
    .bind(approver)
    .bind(&meta)
    .bind(source.configuration_item_id)
    .bind(source.restore_point_id)
    .bind(&source.source_site)
    .bind(&source.source_environment)
    .fetch_one(executor)
    .await?;

    row.into_model()
}

/// Fetch one restore request by string id. A malformed (non-UUID) id is treated
/// as `Ok(None)` (callers map to 404) rather than an error — keeping every
/// handler's not-found behaviour uniform. `Err` is reserved for genuine DB
/// failures (callers map to 500).
pub async fn get(pool: &PgPool, id: &str) -> Result<Option<RestoreRequest>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<RestoreRequestRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM restore_requests WHERE id = $1"
    ))
    .bind(uid)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Build the per-axis scope predicate (#2/#14) shared by [`list_page`] and
/// [`count`] so a page and its total can never drift apart.
///
/// `None` = unrestricted on that axis (per `scope_permits`, a LITERALLY empty
/// scope vec) → no predicate. `Some(values)` = `col = ANY(values)`; the handler
/// passes trimmed, distinct entries, keeping blanks — an all-blank scope
/// matches no real site/environment (fail closed), exactly like the old
/// in-memory `row_scope_permits` filter. Predicates are built PER BRANCH —
/// never a `($n IS NULL OR col = $n)` over an indexed column, which degrades
/// to a seq scan under a generic prepared plan. Column names are compile-time
/// literals; every value is a bound parameter (injection-safe).
fn scope_preds(
    sites: Option<&[String]>,
    environments: Option<&[String]>,
) -> (String, Vec<Vec<String>>) {
    let mut preds: Vec<String> = Vec::new();
    let mut binds: Vec<Vec<String>> = Vec::new();
    if let Some(s) = sites {
        binds.push(s.to_vec());
        preds.push(format!("target_site = ANY(${})", binds.len()));
    }
    if let Some(e) = environments {
        binds.push(e.to_vec());
        preds.push(format!("target_environment = ANY(${})", binds.len()));
    }
    let clause = if preds.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", preds.join(" AND "))
    };
    (clause, binds)
}

/// One `LIMIT`/`OFFSET` page of restore requests (#14), creation time
/// descending, with the principal's DUAL-AXIS scope pushed into SQL — the paged
/// replacement for the old fetch-all `list` + in-memory `row_scope_permits`
/// retain. `ORDER BY created_at DESC, id DESC` ends in the unique PK, so equal
/// timestamps still yield a stable, non-overlapping page cut.
pub async fn list_page(
    pool: &PgPool,
    sites: Option<&[String]>,
    environments: Option<&[String]>,
    limit: i64,
    offset: i64,
) -> Result<Vec<RestoreRequest>, sqlx::Error> {
    let (where_clause, binds) = scope_preds(sites, environments);
    let sql = format!(
        "SELECT {COLUMNS} FROM restore_requests{where_clause} \
         ORDER BY created_at DESC, id DESC LIMIT ${} OFFSET ${}",
        binds.len() + 1,
        binds.len() + 2
    );
    let mut q = sqlx::query_as::<_, RestoreRequestRow>(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    let rows = q.bind(limit).bind(offset).fetch_all(pool).await?;
    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Count restore requests under the SAME scope predicate as [`list_page`] —
/// the pagination total (`X-Total-Count`).
pub async fn count(
    pool: &PgPool,
    sites: Option<&[String]>,
    environments: Option<&[String]>,
) -> Result<i64, sqlx::Error> {
    let (where_clause, binds) = scope_preds(sites, environments);
    let sql = format!("SELECT COUNT(*) FROM restore_requests{where_clause}");
    let mut q = sqlx::query_scalar::<_, i64>(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    q.fetch_one(pool).await
}

/// One protected system's restore-test recency aggregate (#47).
#[derive(sqlx::FromRow)]
pub struct RestoreTestRecencyRow {
    pub source_ci_key: String,
    /// `updated_at` of the most recent request in a SUCCESSFUL state
    /// (`Verified`/`Completed`); `None` ⇒ never successfully tested.
    pub last_successful_test: Option<DateTime<Utc>>,
    pub successful_test_count: i64,
    pub total_requests: i64,
}

/// Per system that has restore-request history (`source_ci_key`): when its last
/// SUCCESSFUL restore test (status `Verified`/`Completed`) ran, how many
/// succeeded, and how many restore requests exist in total. Ordered most-at-risk
/// first — never-succeeded (`NULL`) then oldest. Pure over the pool.
///
/// `last_successful_test` uses `max(updated_at)` over rows CURRENTLY in a success
/// state. `transition()` stamps `updated_at = NOW()` on every CAS write, and
/// today it is only ever invoked to CHANGE status — so for a row resting in
/// `Verified`/`Completed` `updated_at` is the instant it entered that state, the
/// success time. CAVEAT: this is an advisory recency signal, not an audited
/// success timestamp. If future code ever updates a success-state row WITHOUT a
/// status change (e.g. editing metadata), `updated_at` would drift and an old
/// test could read as recent; the precise fix would be a dedicated `succeeded_at`
/// column. Systems that have NEVER had a restore request do not appear (that is a
/// coverage question, not a recency one).
///
/// Executor-generic (`impl PgExecutor`) so it runs both over a `&PgPool` (the
/// #47 read handler) and inside a `&mut *tx` (the #52 `restore_overdue_scan`
/// tick) — `&PgPool` already satisfies `PgExecutor`, so existing callers are
/// unaffected.
pub async fn restore_test_recency(
    executor: impl sqlx::PgExecutor<'_>,
    site: Option<&str>,
    environment: Option<&str>,
) -> Result<Vec<RestoreTestRecencyRow>, sqlx::Error> {
    // #2: scope the aggregate to the caller's site/environment BEFORE grouping, so
    // a scoped principal never learns source_ci_key / recency for rows outside its
    // scope. A NULL bind = no filter on that axis (an unrestricted principal).
    sqlx::query_as(
        "SELECT request.source_ci_key, \
                max(request.updated_at) FILTER ( \
                    WHERE request.status IN ('Verified', 'Completed') \
                ) \
                    AS last_successful_test, \
                count(*) FILTER ( \
                    WHERE request.status IN ('Verified', 'Completed') \
                ) \
                    AS successful_test_count, \
                count(*) AS total_requests \
         FROM restore_requests AS request \
         JOIN site_registry AS target_registry \
           ON target_registry.unlocode COLLATE \"C\" = request.target_site COLLATE \"C\" \
          AND target_registry.active = TRUE \
         JOIN backup_restore_points AS point \
           ON point.id = request.restore_point_id \
          AND point.configuration_item_id = request.source_configuration_item_id \
          AND point.status = 'Available' \
         JOIN configuration_items AS source_ci \
           ON source_ci.id = request.source_configuration_item_id \
          AND source_ci.ci_name COLLATE \"C\" = request.source_ci_key COLLATE \"C\" \
          AND source_ci.site COLLATE \"C\" = request.source_site COLLATE \"C\" \
          AND source_ci.environment COLLATE \"C\" = \
              request.source_environment COLLATE \"C\" \
         JOIN site_registry AS source_registry \
           ON source_registry.unlocode COLLATE \"C\" = source_ci.site COLLATE \"C\" \
          AND source_registry.active = TRUE \
         WHERE ($1::text IS NULL OR request.target_site = $1) \
           AND ($2::text IS NULL OR request.target_environment = $2) \
           AND request.authority_state = 'Verified' \
         GROUP BY request.source_ci_key \
         ORDER BY max(request.updated_at) FILTER ( \
                      WHERE request.status IN ('Verified', 'Completed') \
                  ) \
                  ASC NULLS FIRST, request.source_ci_key ASC",
    )
    .bind(site)
    .bind(environment)
    .fetch_all(executor)
    .await
}

/// Systems whose MOST RECENT restore_request is in `Failed` status (#52 slice 2).
///
/// "Latest is Failed" — NOT "has ever failed". A system that failed last month
/// but succeeded yesterday is excluded (its newest attempt succeeded). The inner
/// `DISTINCT ON (source_ci_key) ... ORDER BY source_ci_key, updated_at DESC,
/// created_at DESC, id DESC` picks the newest row per system; the outer
/// `WHERE status = 'Failed'` keeps only systems whose newest attempt failed.
///
/// Tie-break: `id` is a `gen_random_uuid()` (NOT chronological), so `id DESC`
/// alone could pick the wrong row on an equal-`updated_at` tie. `created_at`
/// (NOT NULL) is the chronological discriminator; `id` is only a final
/// deterministic fallback.
///
/// Blank `source_ci_key` exclusion is done in the SCHEDULER arm in Rust (the same
/// `trim().is_empty()` check `enqueue_if_absent` uses), NOT here in SQL: a SQL
/// `btrim` only strips spaces, so a tab/newline-only key would pass a SQL filter
/// yet still be rejected by the Rust check and abort the tick. Skipping per-row in
/// Rust matches ANY whitespace exactly and mirrors the overdue arm.
///
/// Executor-generic (`impl PgExecutor`) so it runs over a `&PgPool` or inside the
/// `restore_overdue_scan` tick's `&mut *tx`.
#[allow(dead_code)]
pub async fn latest_failed_systems(
    executor: impl sqlx::PgExecutor<'_>,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT source_ci_key FROM ( \
             SELECT DISTINCT ON (request.source_ci_key) \
                    request.source_ci_key, request.status \
             FROM restore_requests AS request \
             JOIN site_registry AS target_registry \
               ON target_registry.unlocode COLLATE \"C\" = request.target_site COLLATE \"C\" \
              AND target_registry.active = TRUE \
             JOIN backup_restore_points AS point \
               ON point.id = request.restore_point_id \
              AND point.configuration_item_id = request.source_configuration_item_id \
              AND point.status = 'Available' \
             JOIN configuration_items AS source_ci \
               ON source_ci.id = request.source_configuration_item_id \
              AND source_ci.ci_name COLLATE \"C\" = request.source_ci_key COLLATE \"C\" \
              AND source_ci.site COLLATE \"C\" = request.source_site COLLATE \"C\" \
              AND source_ci.environment COLLATE \"C\" = \
                  request.source_environment COLLATE \"C\" \
             JOIN site_registry AS source_registry \
               ON source_registry.unlocode COLLATE \"C\" = source_ci.site COLLATE \"C\" \
              AND source_registry.active = TRUE \
             WHERE request.authority_state = 'Verified' \
             ORDER BY request.source_ci_key, request.updated_at DESC, \
                      request.created_at DESC, request.id DESC \
         ) latest \
         WHERE status = 'Failed' \
         ORDER BY source_ci_key",
    )
    .fetch_all(executor)
    .await
}

// ─── Bounded scheduler projection ──────────────────────────────────────────

/// Repository-level ceiling for one restore scheduler page.  The scheduler
/// passes the same value, while rejecting wider limits prevents a future caller
/// from accidentally turning the helper back into a population-wide `fetch_all`.
const MAX_SCHEDULER_SCAN_PAGE: i64 = 100;

/// One durable protected-system authority tuple in a bounded restore scheduler
/// page. The summary trigger owns its immutable `scan_seq` and exact recency /
/// latest-status facts, so later history updates neither move it between pages
/// nor force the scheduler to regroup the restore-request population.
#[derive(sqlx::FromRow)]
pub struct RestoreSchedulerScanRow {
    pub scan_seq: i64,
    pub source_ci_key: String,
    pub site: String,
    pub environment: String,
    pub last_successful_test: Option<DateTime<Utc>>,
    pub successful_test_count: i64,
    pub total_requests: i64,
    pub latest_status: String,
    /// The latest request for this tuple lacks current source/target authority.
    /// Historical quarantined evidence remains immutable but does not poison a
    /// later, independently authorized replan.
    pub authority_quarantined: bool,
}

/// Bound the current restore-request cycle by its largest visible sequence.
/// Later sequence allocations wait for the next cycle; an earlier allocation
/// that commits late is also recovered after the cursor resets on exhaustion.
pub async fn scheduler_scan_high_water(
    executor: impl sqlx::PgExecutor<'_>,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COALESCE(MAX(scan_seq), 0) \
         FROM restore_scheduler_system_summary",
    )
    .fetch_one(executor)
    .await
}

/// Return at most `limit` distinct system/scope tuples in immutable first-seen
/// order, strictly after `cursor_seq` and no later than the cycle high-water
/// mark. Target site/environment are typed durable summary columns, not queue
/// metadata. The query is a direct scan-sequence index page: no base-population
/// GROUP BY, DISTINCT, or per-page history fan-out remains.
pub async fn scheduler_scan_page(
    executor: impl sqlx::PgExecutor<'_>,
    cursor_seq: i64,
    high_water_seq: i64,
    limit: i64,
) -> Result<Vec<RestoreSchedulerScanRow>, sqlx::Error> {
    if cursor_seq < 0
        || high_water_seq < cursor_seq
        || !(1..=MAX_SCHEDULER_SCAN_PAGE).contains(&limit)
    {
        return Err(sqlx::Error::Protocol(
            "restore scheduler page requires 0 <= cursor <= high-water and limit 1..=100"
                .to_string(),
        ));
    }
    sqlx::query_as(
        "SELECT scan_seq, source_ci_key, target_site AS site, \
                target_environment AS environment, last_successful_test, \
                successful_test_count, total_requests, latest_status, \
                (NOT EXISTS ( \
                    SELECT 1 FROM site_registry AS registry \
                    WHERE registry.unlocode COLLATE \"C\" = \
                          summary.target_site COLLATE \"C\" \
                      AND registry.active = TRUE \
                ) OR NOT EXISTS ( \
                    SELECT 1 \
                    FROM restore_requests AS request \
                    JOIN backup_restore_points AS point \
                      ON point.id = request.restore_point_id \
                     AND point.configuration_item_id = request.source_configuration_item_id \
                     AND point.status = 'Available' \
                    JOIN configuration_items AS source_ci \
                      ON source_ci.id = request.source_configuration_item_id \
                     AND source_ci.ci_name COLLATE \"C\" = \
                         request.source_ci_key COLLATE \"C\" \
                     AND source_ci.site COLLATE \"C\" = request.source_site COLLATE \"C\" \
                     AND source_ci.environment COLLATE \"C\" = \
                         request.source_environment COLLATE \"C\" \
                    JOIN site_registry AS source_registry \
                      ON source_registry.unlocode COLLATE \"C\" = source_ci.site COLLATE \"C\" \
                     AND source_registry.active = TRUE \
                    WHERE request.id = summary.latest_request_id \
                      AND request.authority_state = 'Verified' \
                      AND md5(request.source_ci_key) = md5(summary.source_ci_key) \
                      AND md5(request.target_site) = md5(summary.target_site) \
                      AND md5(request.target_environment) = md5(summary.target_environment) \
                      AND request.source_ci_key COLLATE \"C\" = \
                          summary.source_ci_key COLLATE \"C\" \
                      AND request.target_site COLLATE \"C\" = \
                          summary.target_site COLLATE \"C\" \
                      AND request.target_environment COLLATE \"C\" = \
                          summary.target_environment COLLATE \"C\" \
                )) AS authority_quarantined \
         FROM restore_scheduler_system_summary AS summary \
         WHERE scan_seq > $1 AND scan_seq <= $2 \
         ORDER BY scan_seq \
         LIMIT $3",
    )
    .bind(cursor_seq)
    .bind(high_water_seq)
    .bind(limit)
    .fetch_all(executor)
    .await
}

/// Atomically transition a restore request to its new state IFF its current DB
/// status still equals `expected_status` (optimistic lock). Returns `Ok(None)`
/// when the row is absent or its status had already changed (caller → 409), or
/// `Ok(Some(persisted))` on success — the DB row after the write (with the
/// DB-owned `updated_at`) so the caller's response matches a subsequent `get`.
///
/// All mutable columns are updated together with `status` so a single CAS write
/// keeps all fields in sync. `updated_at` is set to NOW() by the DB.
/// Every transition preserves the currently persisted `metadata.planned_by`.
/// An `Approved` target has the additional atomic maker/checker predicate that
/// this identity is nonempty and differs from the server-derived approver.
/// Makerless legacy rows therefore fail closed instead of acquiring fabricated
/// provenance.
///
/// `_audit_action` is accepted for signature parity with the snapshots template
/// but is intentionally unused — restore_requests have no audit table yet.
pub async fn transition(
    executor: impl sqlx::PgExecutor<'_>,
    expected_status: &str,
    r: &RestoreRequest,
    _audit_action: Option<&str>,
) -> Result<Option<RestoreRequest>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(&r.id) else {
        return Ok(None);
    };

    let meta = serde_json::to_string(&r.metadata).unwrap_or_else(|_| "{}".into());
    let approver: Option<&String> = r.metadata.get("approver");
    let planned_by: Option<&String> = r.metadata.get("planned_by");

    let row: Option<RestoreRequestRow> = sqlx::query_as(&format!(
        "UPDATE restore_requests SET \
         source_ci_key = $2, \
         restore_type = $3, \
         restore_point = $4, \
         target_site = $5, \
         target_environment = $6, \
         verification_plan = $7, \
         retention_need = $8, \
         owner = $9, \
         status = $10, \
         dry_run_plan = $11, \
         approver = $12, \
         metadata = $13::jsonb, \
         updated_at = NOW() \
         WHERE id = $1 AND status = $14 \
           AND authority_state = 'Verified' \
           AND source_ci_key COLLATE \"C\" \
               IS NOT DISTINCT FROM $2::text COLLATE \"C\" \
           AND target_site COLLATE \"C\" \
               IS NOT DISTINCT FROM $5::text COLLATE \"C\" \
           AND target_environment COLLATE \"C\" \
               IS NOT DISTINCT FROM $6::text COLLATE \"C\" \
           AND EXISTS ( \
             SELECT 1 FROM site_registry AS registry \
             WHERE registry.unlocode COLLATE \"C\" = \
                   restore_requests.target_site COLLATE \"C\" \
               AND registry.active = TRUE \
           ) \
           AND EXISTS ( \
             SELECT 1 \
             FROM backup_restore_points AS point \
             JOIN configuration_items AS source_ci \
               ON source_ci.id = point.configuration_item_id \
              AND source_ci.ci_name COLLATE \"C\" = \
                  restore_requests.source_ci_key COLLATE \"C\" \
              AND source_ci.site COLLATE \"C\" = \
                  restore_requests.source_site COLLATE \"C\" \
              AND source_ci.environment COLLATE \"C\" = \
                  restore_requests.source_environment COLLATE \"C\" \
             JOIN site_registry AS source_registry \
               ON source_registry.unlocode COLLATE \"C\" = source_ci.site COLLATE \"C\" \
              AND source_registry.active = TRUE \
             WHERE point.id = restore_requests.restore_point_id \
               AND point.configuration_item_id = \
                   restore_requests.source_configuration_item_id \
               AND point.status = 'Available' \
           ) \
           AND metadata->>'planned_by' IS NOT DISTINCT FROM $15 \
           AND ( \
             $10 NOT IN ('Approved', 'Locked', 'Executed', 'Verified', \
                         'Completed', 'Failed') OR ( \
               metadata->>'planned_by' IS NOT NULL \
               AND btrim(metadata->>'planned_by') <> '' \
               AND metadata->>'planned_by' = $15 \
               AND $12 IS NOT NULL \
               AND btrim($12) <> '' \
               AND $12 = btrim($12) \
               AND metadata->>'planned_by' <> $12 \
             ) \
           ) \
         RETURNING {COLUMNS}"
    ))
    .bind(uid)
    .bind(&r.source_ci_key)
    .bind(restore_type_str(&r.restore_type))
    .bind(&r.restore_point)
    .bind(&r.target_site)
    .bind(&r.target_environment)
    .bind(&r.verification_plan)
    .bind(&r.retention_need)
    .bind(&r.owner)
    .bind(status_str(&r.status))
    .bind(&r.dry_run_plan)
    .bind(approver)
    .bind(&meta)
    .bind(expected_status)
    .bind(planned_by)
    .fetch_optional(executor)
    .await?;

    row.map(|row| row.into_model()).transpose()
}

#[cfg(test)]
mod security_contract_tests {
    #[test]
    fn forward_migration_quarantines_unproved_sites_and_installs_a_live_fence() {
        let migration =
            include_str!("../../../../migrations/202_restore_active_site_authority.sql");
        assert!(migration.contains("LOCK TABLE site_registry IN SHARE MODE"));
        assert!(migration.contains("LOCK TABLE restore_requests IN ACCESS EXCLUSIVE MODE"));
        assert!(migration.contains("request.authority_state = 'Verified'"));
        assert!(migration.contains("registry.unlocode COLLATE \"C\" = request.target_site"));
        assert!(migration.contains("registry.active = TRUE"));
        assert!(migration.contains("inactive-or-missing-target-site-requires-replan"));
        assert!(migration.contains("FOR SHARE"));
        assert!(migration.contains("ENABLE ALWAYS TRIGGER restore_requests_active_site_authority"));
        assert!(migration
            .contains("verified restore authority remains without an active canonical site"));
    }

    #[test]
    fn source_authority_requires_typed_points_and_never_backfills_legacy_text() {
        let migration = include_str!("../../../../migrations/206_restore_source_authority.sql");
        assert!(migration.contains("CREATE TABLE backup_restore_points"));
        assert!(migration.contains("unverified-source-asset-requires-replan"));
        assert!(migration.contains("source_configuration_item_id UUID"));
        assert!(migration.contains("restore_point_id UUID"));
        assert!(migration.contains("source_site TEXT"));
        assert!(migration.contains("source_environment TEXT"));
        assert!(migration.contains("REFERENCES backup_restore_points(id, configuration_item_id)"));
        assert!(migration.contains("point.status = 'Available'"));
        assert!(migration.contains("registry.active = TRUE"));
        assert!(migration.contains("FOR NO KEY UPDATE OF point, ci"));
        assert!(migration.contains("FOR SHARE OF registry"));
        assert!(migration.contains("NEW.restore_point COLLATE \"C\""));
        assert!(migration.contains("OLD.restore_point COLLATE \"C\""));
        assert!(migration.contains("ci.site COLLATE \"C\" = NEW.source_site COLLATE \"C\""));
        assert!(migration.contains("ENABLE ALWAYS TRIGGER restore_requests_source_authority"));
        assert!(
            migration.contains("verified restore authority remains without a current typed source")
        );
        assert!(!migration.contains("SET source_configuration_item_id = ci.id"));
    }
}
