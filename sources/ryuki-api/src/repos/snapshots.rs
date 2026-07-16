//! Repository functions for `snapshots`.
//!
//! Every public read and transition requires the verified principal's site and
//! environment scopes. Scope is applied in SQL through the immutable CMDB UUID
//! relation introduced by migration 168, before rows are ordered, paginated,
//! locked, or decoded. A legacy row without a resolvable relation is therefore
//! invisible and immutable through this repository (fail closed).

use chrono::{DateTime, Utc};
use ryuki_engine::models::{SnapshotRecord, SnapshotStatus};
use std::collections::HashMap;
use uuid::Uuid;

// ─── Column list ─────────────────────────────────────────────────────────────

/// SELECT projection for an authorized `snapshots AS s` joined to its
/// authoritative `configuration_items AS ci` resource. The canonical CI name
/// is returned instead of the old descriptive copy on `snapshots`, so a CMDB
/// rename cannot create two competing identities.
pub const AUTHORIZED_COLUMNS: &str = "s.id::text AS id, \
     ci.id::text AS configuration_item_id, \
     ci.ci_name AS platform_ci_key, \
     ci.site, \
     ci.environment, \
     s.created_by, \
     s.scope_provenance, \
     s.snapshot_purpose, \
     s.requested_expiry, \
     s.owner, \
     s.support_group, \
     s.change_context, \
     s.status, \
     s.policy_decision, \
     s.backup_impact, \
     s.remediation_plan, \
     s.metadata::text AS metadata, \
     s.created_at, \
     s.updated_at";

/// Shared SQL authorization relation. Literal-empty scope arrays mean
/// unrestricted, matching `AuthSession`; otherwise the canonical value must be
/// held. A NULL environment is never visible to an environment-scoped actor.
/// The inner joins also quarantine unresolved legacy rows and CIs whose current
/// site lacks an exact active site-registry relation.
const AUTHORIZED_FROM: &str = "snapshots AS s \
     INNER JOIN configuration_items AS ci ON ci.id = s.configuration_item_id \
     INNER JOIN site_registry AS sr ON sr.unlocode = ci.site AND sr.active = true";
const AUTHORIZED_PREDICATE: &str = "(cardinality($1::text[]) = 0 OR ci.site = ANY($1)) \
     AND (cardinality($2::text[]) = 0 \
          OR (NULLIF(btrim(ci.environment), '') IS NOT NULL \
              AND ci.environment = ANY($2)))";

/// One stale-flag request may claim at most this many eligible rows. Claimed
/// rows transition out of the eligible states, so repeated calls advance the
/// work set without a deep OFFSET or an unbounded transaction.
pub const MAX_STALE_SNAPSHOT_BATCH: i64 = 100;

/// Largest legacy OFFSET accepted by the interactive snapshot inventory.
pub const MAX_SNAPSHOT_LIST_OFFSET: i64 = 10_000;

/// Counting one row beyond the supported offset window is enough to tell
/// clients that the total is capped without scanning the complete unbounded
/// governance log.
pub const MAX_AUTHORIZED_COUNT_SCAN: i64 = MAX_SNAPSHOT_LIST_OFFSET + 1;

// ─── Row struct ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
pub struct SnapshotRow {
    pub id: String,
    pub configuration_item_id: String,
    pub platform_ci_key: String,
    pub site: String,
    pub environment: Option<String>,
    pub created_by: Option<String>,
    pub scope_provenance: String,
    pub snapshot_purpose: String,
    pub requested_expiry: String,
    pub owner: String,
    pub support_group: String,
    pub change_context: String,
    pub status: String,
    /// Nullable TEXT columns — decoded directly, not via JSONB.
    pub policy_decision: Option<String>,
    pub backup_impact: Option<String>,
    pub remediation_plan: Option<String>,
    /// Raw JSON text from JSONB::text cast, e.g. `{"key":"value"}`.
    pub metadata: String,
    /// Timestamps decoded as chrono types; converted to RFC-3339 strings in
    /// `into_model`.
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SnapshotRow {
    /// Convert a DB row into the engine model.
    ///
    /// JSONB-text and enum-name fields are deserialized via `serde_json`. A
    /// parse failure means the persisted row is corrupt; we surface it as a
    /// decode error (caller → 500) rather than silently substituting defaults —
    /// a subsequent `transition` would otherwise persist those defaults over the
    /// real data, since the CAS only guards `status`, not the other columns.
    pub fn into_model(self) -> Result<SnapshotRecord, sqlx::Error> {
        fn decode<T: serde::de::DeserializeOwned>(
            raw: &str,
            field: &str,
        ) -> Result<T, sqlx::Error> {
            serde_json::from_str(raw).map_err(|e| {
                sqlx::Error::Decode(
                    format!("snapshots.{field}: corrupt persisted value: {e}").into(),
                )
            })
        }

        let metadata: HashMap<String, String> = decode(&self.metadata, "metadata")?;

        // Enum variants are stored as their serde name (e.g. "Draft",
        // "ReviewRequested"); decode via the engine's Deserialize impl. A DB
        // CHECK constraint (migration 059) keeps these in the legal set.
        let status: SnapshotStatus = decode(&format!("\"{}\"", self.status), "status")?;

        Ok(SnapshotRecord {
            id: self.id,
            configuration_item_id: Some(self.configuration_item_id),
            platform_ci_key: self.platform_ci_key,
            site: Some(self.site),
            environment: self.environment,
            created_by: self.created_by,
            scope_provenance: Some(self.scope_provenance),
            snapshot_purpose: self.snapshot_purpose,
            requested_expiry: self.requested_expiry,
            owner: self.owner,
            support_group: self.support_group,
            change_context: self.change_context,
            status,
            policy_decision: self.policy_decision,
            backup_impact: self.backup_impact,
            remediation_plan: self.remediation_plan,
            created_at: self.created_at.to_rfc3339(),
            updated_at: self.updated_at.to_rfc3339(),
            metadata,
        })
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

/// Canonical serde variant name for a `SnapshotStatus` value as stored in the
/// DB (e.g. `"Draft"`, `"ReviewRequested"`). `pub` so transition handlers can
/// supply the `expected_status` argument to `transition` without duplicating
/// this table.
pub fn status_str(s: &SnapshotStatus) -> &'static str {
    match s {
        SnapshotStatus::Draft => "Draft",
        SnapshotStatus::ReviewRequested => "ReviewRequested",
        SnapshotStatus::ExpiryApproved => "ExpiryApproved",
        SnapshotStatus::StaleFlagged => "StaleFlagged",
        SnapshotStatus::RemediationPlanned => "RemediationPlanned",
        SnapshotStatus::Expired => "Expired",
        SnapshotStatus::Completed => "Completed",
        SnapshotStatus::Failed => "Failed",
    }
}

// ─── Repository functions ─────────────────────────────────────────────────────

/// Insert a snapshot bound to the already authorized CMDB UUID. The
/// `INSERT ... SELECT` repeats both the UUID and canonical-name relation inside
/// the write, so a stale or mismatched caller-side resolution cannot create a
/// governance row for a different resource.
pub async fn insert_authorized(
    executor: impl sqlx::PgExecutor<'_>,
    r: &SnapshotRecord,
    configuration_item_id: &str,
    site_scopes: &[String],
    environment_scopes: &[String],
    created_by: &str,
) -> Result<SnapshotRecord, sqlx::Error> {
    let id = Uuid::parse_str(&r.id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
    let configuration_item_id =
        Uuid::parse_str(configuration_item_id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let meta = serde_json::to_string(&r.metadata).unwrap_or_else(|_| "{}".into());

    let row: SnapshotRow = sqlx::query_as(&format!(
        "WITH inserted AS ( \
             INSERT INTO snapshots \
             (id, configuration_item_id, platform_ci_key, created_by, scope_provenance, \
              snapshot_purpose, requested_expiry, owner, support_group, change_context, \
              status, policy_decision, backup_impact, remediation_plan, metadata) \
             SELECT $1, ci.id, ci.ci_name, $6, 'cmdb-configuration-item', \
                    $7, $8, $9, $10, $11, $12, $13, $14, $15, $16::jsonb \
             FROM configuration_items AS ci \
             INNER JOIN site_registry AS sr \
                     ON sr.unlocode = ci.site AND sr.active = true \
             WHERE ci.id = $2 AND ci.ci_name = $3 \
               AND (cardinality($4::text[]) = 0 OR ci.site = ANY($4)) \
               AND (cardinality($5::text[]) = 0 \
                    OR (NULLIF(btrim(ci.environment), '') IS NOT NULL \
                        AND ci.environment = ANY($5))) \
             RETURNING * \
         ) \
         SELECT {AUTHORIZED_COLUMNS} \
         FROM inserted AS s \
         INNER JOIN configuration_items AS ci ON ci.id = s.configuration_item_id \
         INNER JOIN site_registry AS sr ON sr.unlocode = ci.site AND sr.active = true"
    ))
    .bind(id)
    .bind(configuration_item_id)
    .bind(&r.platform_ci_key)
    .bind(site_scopes)
    .bind(environment_scopes)
    .bind(created_by)
    .bind(&r.snapshot_purpose)
    .bind(&r.requested_expiry)
    .bind(&r.owner)
    .bind(&r.support_group)
    .bind(&r.change_context)
    .bind(status_str(&r.status))
    .bind(&r.policy_decision)
    .bind(&r.backup_impact)
    .bind(&r.remediation_plan)
    .bind(&meta)
    .fetch_one(executor)
    .await?;

    row.into_model()
}

/// Fetch one snapshot only when its authoritative CMDB relation is inside the
/// supplied scope. Missing, foreign, and unresolved-legacy rows all return
/// `None`, preserving a single non-enumerating handler response.
pub async fn get_authorized(
    executor: impl sqlx::PgExecutor<'_>,
    id: &str,
    site_scopes: &[String],
    environment_scopes: &[String],
) -> Result<Option<SnapshotRecord>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<SnapshotRow> = sqlx::query_as(&format!(
        "SELECT {AUTHORIZED_COLUMNS} FROM {AUTHORIZED_FROM} \
         WHERE {AUTHORIZED_PREDICATE} AND s.id = $3"
    ))
    .bind(site_scopes)
    .bind(environment_scopes)
    .bind(uid)
    .fetch_optional(executor)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Fetch and lock one authorized snapshot inside a caller-owned transaction.
/// Review/remediation use this so resource authority, lifecycle transition,
/// success audit, and commit share one transaction.
pub async fn get_authorized_for_update(
    executor: impl sqlx::PgExecutor<'_>,
    id: &str,
    site_scopes: &[String],
    environment_scopes: &[String],
) -> Result<Option<SnapshotRecord>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<SnapshotRow> = sqlx::query_as(&format!(
        "SELECT {AUTHORIZED_COLUMNS} FROM {AUTHORIZED_FROM} \
         WHERE {AUTHORIZED_PREDICATE} AND s.id = $3 \
         FOR UPDATE OF s FOR SHARE OF ci, sr"
    ))
    .bind(site_scopes)
    .bind(environment_scopes)
    .bind(uid)
    .fetch_optional(executor)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Claim one bounded batch of authorized, expired, still-actionable snapshots.
/// The scope and lifecycle predicates run before `LIMIT` and locking;
/// unresolved, foreign, terminal, future-expiry, and malformed-expiry rows do
/// not enter the engine input. `SKIP LOCKED` lets concurrent workers claim
/// disjoint rows instead of occupying pool connections behind the same lock.
pub async fn list_stale_candidates_for_update(
    executor: impl sqlx::PgExecutor<'_>,
    site_scopes: &[String],
    environment_scopes: &[String],
    limit: i64,
) -> Result<Vec<SnapshotRecord>, sqlx::Error> {
    let limit = limit.clamp(1, MAX_STALE_SNAPSHOT_BATCH);
    let rows: Vec<SnapshotRow> = sqlx::query_as(&format!(
        "SELECT {AUTHORIZED_COLUMNS} FROM {AUTHORIZED_FROM} \
         WHERE {AUTHORIZED_PREDICATE} \
           AND s.status IN ('Draft', 'ReviewRequested', 'ExpiryApproved') \
           AND CASE \
                 WHEN pg_input_is_valid(s.requested_expiry, 'timestamptz') \
                 THEN s.requested_expiry::timestamptz < NOW() \
                 ELSE false \
               END \
         ORDER BY s.created_at ASC, s.id ASC \
         LIMIT $3 \
         FOR UPDATE OF s SKIP LOCKED FOR SHARE OF ci, sr"
    ))
    .bind(site_scopes)
    .bind(environment_scopes)
    .bind(limit)
    .fetch_all(executor)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// List one authorized page. Scope is applied before ordering/pagination, and
/// [`count_authorized_bounded`] uses the exact same relation and predicate.
pub async fn list_page_authorized(
    executor: impl sqlx::PgExecutor<'_>,
    site_scopes: &[String],
    environment_scopes: &[String],
    limit: i64,
    offset: i64,
) -> Result<Vec<SnapshotRecord>, sqlx::Error> {
    let rows: Vec<SnapshotRow> = sqlx::query_as(&format!(
        "SELECT {AUTHORIZED_COLUMNS} FROM {AUTHORIZED_FROM} \
         WHERE {AUTHORIZED_PREDICATE} \
         ORDER BY s.created_at DESC, s.id DESC LIMIT $3 OFFSET $4"
    ))
    .bind(site_scopes)
    .bind(environment_scopes)
    .bind(limit)
    .bind(offset)
    .fetch_all(executor)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Count at most [`MAX_AUTHORIZED_COUNT_SCAN`] rows from the same authorized
/// relation used by [`list_page_authorized`]. A result equal to the cap is a
/// lower bound, not an exact total; the handler marks it as capped.
pub async fn count_authorized_bounded(
    executor: impl sqlx::PgExecutor<'_>,
    site_scopes: &[String],
    environment_scopes: &[String],
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM ( \
             SELECT 1 FROM {AUTHORIZED_FROM} \
             WHERE {AUTHORIZED_PREDICATE} \
             LIMIT $3 \
         ) AS bounded_snapshots"
    ))
    .bind(site_scopes)
    .bind(environment_scopes)
    .bind(MAX_AUTHORIZED_COUNT_SCAN)
    .fetch_one(executor)
    .await
}

/// Atomically transition a snapshot only if both its prior lifecycle state and
/// current authoritative CMDB scope remain authorized. The scope predicate is
/// repeated in the UPDATE; a handler-side load can never be used as a stale
/// authorization decision.
pub async fn transition_authorized(
    executor: impl sqlx::PgExecutor<'_>,
    site_scopes: &[String],
    environment_scopes: &[String],
    expected_status: &str,
    r: &SnapshotRecord,
) -> Result<Option<SnapshotRecord>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(&r.id) else {
        return Ok(None);
    };

    let meta = serde_json::to_string(&r.metadata).unwrap_or_else(|_| "{}".into());

    let row: Option<SnapshotRow> = sqlx::query_as(&format!(
        "WITH updated AS ( \
             UPDATE snapshots AS s SET \
                 status = $4, \
                 policy_decision = $5, \
                 backup_impact = $6, \
                 remediation_plan = $7, \
                 metadata = $8::jsonb, \
                 updated_at = NOW() \
             FROM configuration_items AS ci \
             INNER JOIN site_registry AS sr \
                     ON sr.unlocode = ci.site AND sr.active = true \
             WHERE s.configuration_item_id = ci.id \
               AND {AUTHORIZED_PREDICATE} \
               AND s.id = $3 AND s.status = $9 \
             RETURNING s.* \
         ) \
         SELECT {AUTHORIZED_COLUMNS} \
         FROM updated AS s \
         INNER JOIN configuration_items AS ci ON ci.id = s.configuration_item_id \
         INNER JOIN site_registry AS sr ON sr.unlocode = ci.site AND sr.active = true"
    ))
    .bind(site_scopes)
    .bind(environment_scopes)
    .bind(uid)
    .bind(status_str(&r.status))
    .bind(&r.policy_decision)
    .bind(&r.backup_impact)
    .bind(&r.remediation_plan)
    .bind(&meta)
    .bind(expected_status)
    .fetch_optional(executor)
    .await?;

    row.map(|row| row.into_model()).transpose()
}
