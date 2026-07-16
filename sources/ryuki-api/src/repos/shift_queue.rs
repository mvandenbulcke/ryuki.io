//! Repository functions for `shift_queue`.
//!
//! The shift queue is the operations work-item surface (migration 029). Until
//! #52 every INSERT into it lived inline in tests/seeds; this is the first
//! reusable writer, kept minimal and scoped to the restore-test producers
//! (`restore-test-overdue`, `restore-test-failed`).
//!
//! # Authority-scoped dedup
//! Migration 170 replaces the legacy metadata-expression indexes with typed
//! partial unique indexes. Resource work is unique by
//! `(item_type, source_ci_key, site, environment)` and explicit fleet-global
//! work by `(item_type, source_ci_key)`. Quarantined legacy rows participate in
//! neither contract and therefore cannot suppress verified work. The common
//! `NOT EXISTS` predicate and the concurrency-safe unique index use the exact
//! same tuple.

use sqlx::{PgExecutor, PgPool};

/// The overdue/never-tested restore signal (#52 slice 1). Fixed so the dedup key
/// and the partial unique index always agree.
pub const RESTORE_OVERDUE_ITEM_TYPE: &str = "restore-test-overdue";

/// The FAILED-latest restore signal (#52 slice 2). Fixed so the dedup key and the
/// partial unique index always agree.
pub const RESTORE_FAILED_ITEM_TYPE: &str = "restore-test-failed";

/// A restore history tuple containing one or more rows whose durable authority
/// or maker/checker provenance is quarantined. The scheduler uses a digest-only
/// global key so malformed or oversized legacy values are never copied into a
/// queue btree key or operator payload.
pub const RESTORE_AUTHORITY_QUARANTINED_ITEM_TYPE: &str = "restore-authority-quarantined";

/// The OVERDUE secret-rotation signal (#7). A secret whose `next_rotation_due` has
/// passed. Fixed so the dedup key and the partial unique index always agree.
pub const SECRET_ROTATION_DUE_ITEM_TYPE: &str = "secret-rotation-due";

/// The INVALID secret-rotation-date signal (#7, codex MAJOR). A secret whose
/// `next_rotation_due` is not parseable as RFC3339 — surfaced (not silently skipped) so
/// the data-integrity problem is visible. Fixed so the dedup key and the partial unique
/// index always agree.
pub const SECRET_ROTATION_INVALID_ITEM_TYPE: &str = "secret-rotation-invalid-due";

/// The EXPIRING/EXPIRED legal-hold signal (#17). An Active hold within 30 days of (or
/// past) its `expiry_date`. Fixed so the dedup key and the partial unique index agree.
pub const LEGAL_HOLD_EXPIRY_ITEM_TYPE: &str = "legal-hold-expiring";

/// The OVERDUE recertification-campaign signal (#12). An `Active` campaign past its
/// `end_date`. The dedup `source_ci_key` is INSTANCE-specific (`{id}@{start_date_ms}`),
/// not the bare campaign id, so a reused id never suppresses a new overdue campaign.
pub const RECERTIFICATION_OVERDUE_ITEM_TYPE: &str = "recertification-overdue";

/// The EXPIRING/EXPIRED TLS-certificate signal (run-3). A cert whose `valid_to` is
/// within (or past) the actionable window. `source_ci_key` is the bare cert id (a
/// UUID, never reused; renewal updates the same row's `valid_to`). The open item is
/// REFRESHED each scan so an expiring-soon item upgrades to expired (+ P2→P1).
pub const CERTIFICATE_EXPIRY_ITEM_TYPE: &str = "certificate-expiring";

/// The OVERDUE/DUE-SOON gMSA password-rotation signal (run-3). A gMSA whose computed
/// rotation deadline (`last_rotation_at + managed_password_interval_days`) is within
/// (or past) the actionable window. `source_ci_key` is the bare gMSA id (a UUID,
/// never reused). The open item is REFRESHED each scan so a due-soon item upgrades to
/// overdue (+ P3→P2). Framed as "verify AD-side rotation", NOT manual rotation.
pub const GMSA_EXPIRY_ITEM_TYPE: &str = "gmsa-expiring";

/// The EXPIRING/EXPIRED out-of-band (iLO/iDRAC/IPMI) management-endpoint TLS-cert
/// signal (run-3). An `oob_endpoints` row whose `cert_expiry` is within (or past) the
/// actionable window. `source_ci_key` is the bare OOB endpoint id (a UUID, never
/// reused). The open item is REFRESHED each scan so an expiring-soon item upgrades to
/// expired (+ P3→P2). Reuses the cert expiry classifier (same TLS-cert-expiry shape).
pub const OOB_CERT_EXPIRY_ITEM_TYPE: &str = "oob-cert-expiring";

/// The OVERDUE DR-test signal (#58). A DR plan (status 'active' or 'approved') whose
/// `next_test_due` has passed. `source_ci_key` is the bare plan id (a TEXT PK, never
/// reused). One deduped OPEN item per plan; re-enqueued after resolution if still
/// overdue on the next daily scan (migration 139).
pub const DR_TEST_OVERDUE_ITEM_TYPE: &str = "dr-test-overdue";

/// The MISSED-patch-window signal (#59). A patch wave in status 'Scheduled' whose
/// committed window start (`schedule->>'start'`) has passed without the wave moving to
/// 'InProgress'. `source_ci_key` is the bare wave id. One deduped OPEN item per wave;
/// re-enqueued after resolution if still overdue on the next daily scan (migration 140).
pub const PATCH_WAVE_OVERDUE_ITEM_TYPE: &str = "patch-wave-overdue";

/// The STALE-golden-image signal (#60). A promoted golden image whose `build_date` is
/// older than the monthly refresh window — the live base image is missing recent patches.
/// `source_ci_key` is the bare image id. One deduped OPEN item per image; re-enqueued
/// after resolution if still stale on the next daily scan (migration 141).
pub const GOLDEN_IMAGE_STALE_ITEM_TYPE: &str = "golden-image-stale";

/// The OVERDUE drift-recheck signal (#31 slice 1). An 'operational' deployment whose most
/// recent successful live-apply verification (agent_jobs.result_status in 'applied'/'verified')
/// is older than ryuki_engine::drift_scan::DRIFT_RECHECK_INTERVAL_DAYS. `source_ci_key` is the
/// bare request id (a UUID). One deduped OPEN item per request; re-enqueued after resolution if
/// still overdue on the next daily scan (migration 145).
pub const DRIFT_RECHECK_OVERDUE_ITEM_TYPE: &str = "drift-recheck-overdue";

/// Server-derived authorization classification for a scheduler work item.
/// Callers must construct `Resource` only from typed source columns selected by
/// the scheduler repository; descriptive queue metadata is never consulted.
#[derive(Debug, Clone, Copy)]
pub enum ShiftQueueAuthority<'a> {
    Resource {
        site: &'a str,
        environment: Option<&'a str>,
    },
    /// The producer's source object is intentionally fleet-wide rather than
    /// missing scope. This is distinct from unresolved legacy work.
    Global,
}

/// Enqueue ONE open `item_type` work item for the exact typed authority tuple.
/// Returns `rows_affected()` — `1` when a new item was inserted, `0` when that
/// same authority tuple already exists, a concurrent writer won, or a resource
/// site is not currently an ACTIVE canonical registry entry.
///
/// `item_type` is a code-controlled constant (`RESTORE_OVERDUE_ITEM_TYPE` /
/// `RESTORE_FAILED_ITEM_TYPE`), never user input; it is bound into BOTH the
/// INSERT and the NOT EXISTS dedup predicate so the produced row and the dedup
/// key can never drift.
///
/// `metadata` is descriptive only. It must be valid JSON and its diagnostic
/// `source_ci_key` must exactly agree with the typed argument, preventing audit
/// payloads from naming a different source than the persisted dedup authority.
/// The source/site/environment tuple must already be canonical (trimmed,
/// nonblank); this function never repairs or infers authority from JSON.
///
/// Executor-generic (`impl PgExecutor`) so the scheduler tick can run it on
/// `&mut *tx` and any future caller can run it on a pool.
#[allow(clippy::too_many_arguments)]
pub async fn enqueue_if_absent(
    executor: impl PgExecutor<'_>,
    item_type: &str,
    source_ci_key: &str,
    authority: ShiftQueueAuthority<'_>,
    title: &str,
    description: &str,
    priority: &str,
    metadata: &str,
) -> Result<u64, sqlx::Error> {
    if source_ci_key.trim().is_empty() || source_ci_key != source_ci_key.trim() {
        return Err(sqlx::Error::Protocol(
            "enqueue_if_absent: source_ci_key must be canonical and nonempty".into(),
        ));
    }
    let metadata_value: serde_json::Value = serde_json::from_str(metadata).map_err(|error| {
        sqlx::Error::Protocol(format!(
            "enqueue_if_absent: metadata is not valid JSON: {error}"
        ))
    })?;
    if metadata_value
        .get("source_ci_key")
        .and_then(serde_json::Value::as_str)
        != Some(source_ci_key)
    {
        return Err(sqlx::Error::Protocol(
            "enqueue_if_absent: metadata source_ci_key must match typed authority".into(),
        ));
    }

    let result = match authority {
        ShiftQueueAuthority::Resource { site, environment } => {
            if site.trim().is_empty()
                || site != site.trim()
                || environment.is_some_and(|value| value.trim().is_empty() || value != value.trim())
            {
                return Err(sqlx::Error::Protocol(
                    "enqueue_if_absent: resource scope must be canonical and nonempty".into(),
                ));
            }
            sqlx::query(
                "INSERT INTO shift_queue (item_type, title, description, priority, metadata, \
                                          source_ci_key, visibility_kind, site, environment, \
                                          scope_provenance) \
                 SELECT $1, $2, $3, $4, $5::jsonb, $6, 'resource', $7, $8, \
                        'scheduler-resource-v1' \
                 FROM site_registry AS registry \
                 WHERE registry.unlocode = $7 AND registry.active = true \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM shift_queue AS queued \
                       WHERE queued.item_type = $1 \
                         AND queued.source_ci_key = $6 \
                         AND queued.visibility_kind = 'resource' \
                         AND queued.site = $7 \
                         AND queued.environment IS NOT DISTINCT FROM $8 \
                         AND queued.resolved = false \
                   ) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(item_type)
            .bind(title)
            .bind(description)
            .bind(priority)
            .bind(metadata)
            .bind(source_ci_key)
            .bind(site)
            .bind(environment)
            .execute(executor)
            .await?
        }
        ShiftQueueAuthority::Global => {
            sqlx::query(
                "INSERT INTO shift_queue (item_type, title, description, priority, metadata, \
                                      source_ci_key, visibility_kind, scope_provenance) \
             SELECT $1, $2, $3, $4, $5::jsonb, $6, 'global', 'scheduler-global-v1' \
             WHERE NOT EXISTS ( \
                 SELECT 1 FROM shift_queue AS queued \
                 WHERE queued.item_type = $1 \
                   AND queued.source_ci_key = $6 \
                   AND queued.visibility_kind = 'global' \
                   AND queued.resolved = false \
             ) \
             ON CONFLICT DO NOTHING",
            )
            .bind(item_type)
            .bind(title)
            .bind(description)
            .bind(priority)
            .bind(metadata)
            .bind(source_ci_key)
            .execute(executor)
            .await?
        }
    };
    Ok(result.rows_affected())
}

/// Secret-safe triage projection for the operator list endpoint. `metadata` (jsonb)
/// is DELIBERATELY excluded (the shift-contract's `no-raw-provider-payloads` rule;
/// `/my-items` omits it too).
#[derive(Debug, sqlx::FromRow)]
pub struct ShiftQueueListRow {
    pub id: String,
    pub item_type: String,
    pub title: String,
    pub description: String,
    pub priority: String,
    pub assigned_to: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub acknowledged: bool,
    pub escalated: bool,
    pub resolved: bool,
}

/// Optional filters for [`list_filtered`]. Every field is `None` ⇒ "do not filter".
#[derive(Debug, Default)]
pub struct ShiftQueueFilter<'a> {
    pub item_type: Option<&'a str>,
    pub priority: Option<&'a str>,
    pub assigned_to: Option<&'a str>,
    pub resolved: Option<bool>,
    pub acknowledged: Option<bool>,
    pub escalated: Option<bool>,
    /// `Some(true)` ⇒ only UNASSIGNED (`assigned_to IS NULL`); `Some(false)` ⇒ only
    /// assigned; `None` ⇒ no filter.
    pub unassigned: Option<bool>,
}

/// Server-derived row authorization for shift work. Caller-controlled filters
/// are deliberately separate: this policy is always applied before ordering,
/// pagination, counting, or projection.
#[derive(Debug)]
pub struct ShiftQueueAccess<'a> {
    pub sites: &'a [String],
    pub environments: &'a [String],
    pub principal: &'a str,
    pub all_sites: bool,
    pub all_environments: bool,
    pub allow_global: bool,
    pub bypass_owner: bool,
}

/// Filtered + paginated operator triage list.
///
/// The server-derived resource policy is evaluated first. EVERY caller filter
/// is then a BOUND parameter applied via the `($N::type IS NULL OR col = $N)`
/// pattern — an unset filter matches every authorized row, and no user input is
/// concatenated into SQL. Ordered `priority ASC` (P1<P2<P3), `created_at ASC`,
/// then immutable `id ASC`, so offset pagination is deterministic for a stable
/// relation. The caller passes `limit + 1` to derive `has_more` without a COUNT.
pub async fn list_filtered(
    pool: &PgPool,
    access: &ShiftQueueAccess<'_>,
    filter: &ShiftQueueFilter<'_>,
    limit: i64,
    offset: i64,
) -> Result<Vec<ShiftQueueListRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id::text AS id, item_type, title, description, priority, assigned_to, \
                created_at, acknowledged, escalated, resolved \
         FROM shift_queue \
         WHERE ( \
             (visibility_kind = 'resource' \
              AND EXISTS (SELECT 1 FROM site_registry AS authorized_site \
                          WHERE authorized_site.unlocode = shift_queue.site \
                            AND authorized_site.active = true) \
              AND ($1::bool OR site = ANY($2::text[])) \
              AND ($3::bool OR environment = ANY($4::text[])) \
              AND ($5::bool OR owner_principal IS NULL OR owner_principal = $6)) \
             OR (visibility_kind = 'global' AND $7::bool) \
         ) \
           AND ($8::text IS NULL OR item_type = $8) \
           AND ($9::text IS NULL OR priority = $9) \
           AND ($10::text IS NULL OR assigned_to = $10) \
           AND ($11::bool IS NULL OR resolved = $11) \
           AND ($12::bool IS NULL OR acknowledged = $12) \
           AND ($13::bool IS NULL OR escalated = $13) \
           AND ($14::bool IS NULL OR (assigned_to IS NULL) = $14) \
         ORDER BY priority ASC, created_at ASC, id ASC \
         LIMIT $15 OFFSET $16",
    )
    .bind(access.all_sites)
    .bind(access.sites)
    .bind(access.all_environments)
    .bind(access.environments)
    .bind(access.bypass_owner)
    .bind(access.principal)
    .bind(access.allow_global)
    .bind(filter.item_type)
    .bind(filter.priority)
    .bind(filter.assigned_to)
    .bind(filter.resolved)
    .bind(filter.acknowledged)
    .bind(filter.escalated)
    .bind(filter.unassigned)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}
