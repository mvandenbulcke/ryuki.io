//! Repository functions for `vm_day2_operations`.
//!
//! Planning resolves a typed VM target from the authoritative CMDB while the
//! configuration item and its active site row are locked. The operation insert
//! shares that caller-owned transaction, so request-body strings can never be
//! substituted for target identity or authorization scope.
//!
//! The full `VmDay2ChangeRequest` is round-tripped through the `plan_json`
//! JSONB column so later calls can reconstruct the entity faithfully. The
//! scalar columns (`target_ci_key`, `change_type`, `target_value`, `site`,
//! `environment`, `owner`, `maintenance_window`, `status`) are kept in sync
//! for queryability but are not used during reconstruction.

use ryuki_engine::{
    models::{VmChangeStatus, VmChangeType, VmDay2ChangeRequest, VmDay2TargetProvenance},
    vm_operations,
};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

pub const CMDB_TARGET_PROVENANCE: &str = "cmdb-configuration-item";

// ─── Column list ─────────────────────────────────────────────────────────────

/// SELECT column list. UUID → text so sqlx binds into String; JSONB → text
/// so we can `serde_json::from_str` the full entity.
pub const COLUMNS: &str = "op.id::text AS id, op.status, op.plan_json::text AS plan_json";

// ─── Typed target authority ──────────────────────────────────────────────────

/// An exact Server CI whose canonical site is active and whose site and
/// environment are within the verified principal's scope. Fields are private
/// so repository callers cannot forge this capability from request data.
#[derive(Debug, sqlx::FromRow)]
pub struct AuthorizedVmDay2Target {
    configuration_item_id: Uuid,
    target_ci_key: String,
    site: String,
    environment: String,
}

impl AuthorizedVmDay2Target {
    /// Build the engine plan exclusively from axes copied from the locked CMDB
    /// row and bind the immutable UUID/provenance before governance is signed.
    pub fn plan_change(
        &self,
        change_type: VmChangeType,
        target_value: u32,
        owner: &str,
        maintenance_window: &str,
    ) -> Result<VmDay2ChangeRequest, String> {
        let mut operation = vm_operations::plan_vm_day2_change(
            &self.target_ci_key,
            change_type,
            target_value,
            &self.site,
            &self.environment,
            owner,
            maintenance_window,
        )?;
        vm_operations::bind_vm_day2_target_authority(
            &mut operation,
            &self.configuration_item_id.to_string(),
        )?;
        Ok(operation)
    }

    fn matches(&self, operation: &VmDay2ChangeRequest) -> bool {
        operation.target_ci_key == self.target_ci_key
            && operation.site == self.site
            && operation.environment == self.environment
            && authoritative_target_id(operation) == Some(self.configuration_item_id)
    }
}

/// Resolve and lock the one authoritative active VM target inside the caller's
/// transaction. Unknown, inactive, non-Server, unclassified-environment, and
/// out-of-scope rows all return `None`.
pub async fn resolve_authorized_target_for_plan(
    connection: &mut PgConnection,
    target_ci_key: &str,
    site_scopes: &[String],
    environment_scopes: &[String],
) -> Result<Option<AuthorizedVmDay2Target>, sqlx::Error> {
    sqlx::query_as(
        "SELECT ci.id AS configuration_item_id, ci.ci_name AS target_ci_key, \
                ci.site, ci.environment \
         FROM configuration_items AS ci \
         INNER JOIN site_registry AS sr \
                 ON sr.unlocode = ci.site AND sr.active = true \
         WHERE ci.ci_name = $1 \
           AND ci.ci_type = 'Server' \
           AND ci.ci_name = btrim(ci.ci_name) \
           AND ci.ci_name <> '' \
           AND NULLIF(btrim(ci.environment), '') IS NOT NULL \
           AND (cardinality($2::text[]) = 0 OR ci.site = ANY($2)) \
           AND (cardinality($3::text[]) = 0 OR ci.environment = ANY($3)) \
         FOR NO KEY UPDATE OF ci, sr",
    )
    .bind(target_ci_key)
    .bind(site_scopes)
    .bind(environment_scopes)
    .fetch_optional(connection)
    .await
}

// ─── Row struct ──────────────────────────────────────────────────────────────

/// Minimal row struct — the full entity lives in `plan_json`; the `status`
/// column is selected separately so `transition` can apply the CAS guard.
#[derive(sqlx::FromRow)]
pub struct VmDay2OperationRow {
    pub id: String,
    pub status: String,
    /// Raw JSON text from JSONB::text cast — the full `VmDay2ChangeRequest`.
    pub plan_json: Option<String>,
}

impl VmDay2OperationRow {
    /// Convert a DB row into the engine model by deserialising `plan_json`.
    ///
    /// The `status` column is kept in sync with the value encoded inside
    /// `plan_json`, but we use the column value to patch the status after
    /// transitions so that the status is always authoritative from the DB.
    pub fn into_model(self) -> Result<VmDay2ChangeRequest, sqlx::Error> {
        let raw = self
            .plan_json
            .ok_or_else(|| sqlx::Error::Decode("vm_day2_operations.plan_json: NULL".into()))?;

        let mut entity: VmDay2ChangeRequest = serde_json::from_str(&raw).map_err(|e| {
            sqlx::Error::Decode(
                format!("vm_day2_operations.plan_json: corrupt persisted value: {e}").into(),
            )
        })?;

        // Override the embedded status with the authoritative DB column value
        // (it may have been updated by `transition` after the initial insert).
        entity.status = decode_status(&self.status)
            .map_err(|e| sqlx::Error::Decode(format!("vm_day2_operations.status: {e}").into()))?;

        // Override the id with the DB-authoritative UUID string.
        entity.id = self.id;

        Ok(entity)
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

/// Canonical serde variant name for a `VmChangeStatus` as stored in the DB.
pub fn status_str(s: &VmChangeStatus) -> &'static str {
    match s {
        VmChangeStatus::Draft => "Draft",
        VmChangeStatus::Validated => "Validated",
        VmChangeStatus::Planned => "Planned",
        VmChangeStatus::Approved => "Approved",
        VmChangeStatus::Locked => "Locked",
        VmChangeStatus::Executed => "Executed",
        VmChangeStatus::Verified => "Verified",
        VmChangeStatus::Completed => "Completed",
        VmChangeStatus::Failed => "Failed",
    }
}

fn decode_status(s: &str) -> Result<VmChangeStatus, String> {
    // Stored without quotes; wrap in quotes for serde_json to deserialise as
    // a unit-variant string (matches the engine's Serialize/Deserialize impl).
    serde_json::from_str(&format!("\"{s}\"")).map_err(|e| format!("unknown status '{s}': {e}"))
}

fn authoritative_target_id(operation: &VmDay2ChangeRequest) -> Option<Uuid> {
    let authority = operation.target_authority.as_ref()?;
    if authority.provenance != VmDay2TargetProvenance::CmdbConfigurationItem {
        return None;
    }
    Uuid::parse_str(&authority.configuration_item_id).ok()
}

// ─── Repository functions ─────────────────────────────────────────────────────

/// Insert a new VM Day-2 operation in the transaction that still holds the
/// target's CMDB and active-site locks. The private typed target must match all
/// operation axes and its embedded authority binding exactly.
pub async fn insert_authorized(
    connection: &mut PgConnection,
    target: &AuthorizedVmDay2Target,
    op: &VmDay2ChangeRequest,
) -> Result<(), sqlx::Error> {
    let id = Uuid::parse_str(&op.id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
    if !target.matches(op) {
        return Err(sqlx::Error::Protocol(
            "VM Day-2 operation does not match its authorized CMDB target".into(),
        ));
    }

    let change_type = op.change_type.to_string();
    let plan_json = serde_json::to_string(op)
        .map_err(|error| sqlx::Error::Protocol(format!("cannot encode VM Day-2 plan: {error}")))?;

    // Checked u32 -> i32 so an out-of-range target value is rejected up front
    // rather than silently wrapping to a negative scalar column (the queryable
    // column must stay faithful to the JSONB plan_json).
    let target_value =
        i32::try_from(op.target_value).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    sqlx::query(
        "INSERT INTO vm_day2_operations \
         (id, configuration_item_id, target_provenance, target_ci_key, \
          change_type, target_value, site, environment, owner, \
          maintenance_window, status, plan_json) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb)",
    )
    .bind(id)
    .bind(target.configuration_item_id)
    .bind(CMDB_TARGET_PROVENANCE)
    .bind(&op.target_ci_key)
    .bind(&change_type)
    .bind(target_value)
    .bind(&op.site)
    .bind(&op.environment)
    .bind(&op.owner)
    .bind(&op.maintenance_window)
    .bind(status_str(&op.status))
    .bind(&plan_json)
    .execute(connection)
    .await?;

    Ok(())
}

/// Fetch one vm day-2 operation by string id. A malformed (non-UUID) id is
/// treated as `Ok(None)` (callers map to 404) rather than an error — keeping
/// every handler's not-found behaviour uniform.
pub async fn get_authorized(
    pool: &PgPool,
    id: &str,
    site_scopes: &[String],
    environment_scopes: &[String],
) -> Result<Option<VmDay2ChangeRequest>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<VmDay2OperationRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} \
         FROM vm_day2_operations AS op \
         INNER JOIN configuration_items AS ci \
                 ON ci.id = op.configuration_item_id \
                AND ci.ci_name = op.target_ci_key \
                AND ci.ci_type = 'Server' \
                AND ci.site = op.site \
                AND ci.environment = op.environment \
         INNER JOIN site_registry AS sr \
                 ON sr.unlocode = ci.site AND sr.active = true \
         WHERE op.id = $1 \
           AND op.target_provenance = '{CMDB_TARGET_PROVENANCE}' \
           AND (cardinality($2::text[]) = 0 OR ci.site = ANY($2)) \
           AND (cardinality($3::text[]) = 0 OR ci.environment = ANY($3))"
    ))
    .bind(uid)
    .bind(site_scopes)
    .bind(environment_scopes)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_model()).transpose()
}

/// Unscoped internal read used by repository-level tests. It still requires a
/// current exact active CMDB relation and therefore cannot surface unresolved
/// legacy or stale-authority operations.
#[cfg(test)]
pub async fn get(pool: &PgPool, id: &str) -> Result<Option<VmDay2ChangeRequest>, sqlx::Error> {
    get_authorized(pool, id, &[], &[]).await
}

/// Return authorized VM Day-2 operations ordered by creation time descending.
#[allow(dead_code)]
pub async fn list_authorized(
    pool: &PgPool,
    site_scopes: &[String],
    environment_scopes: &[String],
) -> Result<Vec<VmDay2ChangeRequest>, sqlx::Error> {
    let rows: Vec<VmDay2OperationRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} \
         FROM vm_day2_operations AS op \
         INNER JOIN configuration_items AS ci \
                 ON ci.id = op.configuration_item_id \
                AND ci.ci_name = op.target_ci_key \
                AND ci.ci_type = 'Server' \
                AND ci.site = op.site \
                AND ci.environment = op.environment \
         INNER JOIN site_registry AS sr \
                 ON sr.unlocode = ci.site AND sr.active = true \
         WHERE op.target_provenance = '{CMDB_TARGET_PROVENANCE}' \
           AND (cardinality($1::text[]) = 0 OR ci.site = ANY($1)) \
           AND (cardinality($2::text[]) = 0 OR ci.environment = ANY($2)) \
         ORDER BY op.created_at DESC, op.id DESC"
    ))
    .bind(site_scopes)
    .bind(environment_scopes)
    .fetch_all(pool)
    .await?;

    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Atomically transition a vm day-2 operation to its new state IFF its current
/// DB status still equals `expected_status` (optimistic lock) and its durable
/// governance binding is unchanged. Returns
/// `Ok(false)` when the row is absent or its status had already changed
/// (caller → 409). `Ok(true)` on success.
///
/// Both `status` (scalar column for queryability) and `plan_json` (full entity
/// snapshot) are updated atomically within a transaction.
pub async fn transition(
    pool: &PgPool,
    expected_status: &str,
    op: &VmDay2ChangeRequest,
) -> Result<bool, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(&op.id) else {
        return Ok(false);
    };
    let Some(configuration_item_id) = authoritative_target_id(op) else {
        return Ok(false);
    };
    if op.governance.is_none() {
        // Legacy/makerless rows fail closed. They must be replanned so the
        // immutable plan has a server-derived maker and digest binding.
        return Ok(false);
    }

    let plan_json = serde_json::to_string(op).map_err(|error| {
        sqlx::Error::Protocol(format!("cannot encode VM Day-2 transition: {error}"))
    })?;

    let mut tx = pool.begin().await?;

    let res = sqlx::query(
        "UPDATE vm_day2_operations SET \
         status = $2, \
         plan_json = $3::jsonb, \
         updated_at = NOW() \
         WHERE id = $1 AND status = $4 \
           AND configuration_item_id = $5 \
           AND target_provenance = 'cmdb-configuration-item' \
           AND plan_json #>> '{target_authority,configuration_item_id}' = \
               configuration_item_id::text \
           AND plan_json #>> '{target_authority,provenance}' = target_provenance \
           AND plan_json #> '{governance}' = $3::jsonb #> '{governance}' \
           AND (plan_json - 'status' - 'updated_at' - 'metadata' - 'governance') = \
               ($3::jsonb - 'status' - 'updated_at' - 'metadata' - 'governance')",
    )
    .bind(uid)
    .bind(status_str(&op.status))
    .bind(&plan_json)
    .bind(expected_status)
    .bind(configuration_item_id)
    .execute(&mut *tx)
    .await?;

    if res.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(false);
    }

    tx.commit().await?;
    Ok(true)
}

/// Store the maker/checker decision for the exact validated plan. The database
/// repeats the engine checks so a stale read, forged repository caller, or
/// concurrent transition cannot approve a different plan or let its maker act
/// as checker.
pub async fn approve_transition(
    pool: &PgPool,
    op: &VmDay2ChangeRequest,
) -> Result<bool, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(&op.id) else {
        return Ok(false);
    };
    let Some(configuration_item_id) = authoritative_target_id(op) else {
        return Ok(false);
    };
    let Some(governance) = op.governance.as_ref() else {
        return Ok(false);
    };
    let Some(approval) = governance.approval.as_ref() else {
        return Ok(false);
    };
    if op.status != VmChangeStatus::Approved
        || governance.planned_by.trim().is_empty()
        || approval.approved_by.trim().is_empty()
        || governance.planned_by == approval.approved_by
        || governance.plan_digest != approval.plan_digest
        || governance.operation_lock.is_some()
    {
        return Ok(false);
    }

    let plan_json = serde_json::to_string(op).map_err(|error| {
        sqlx::Error::Protocol(format!("cannot encode VM Day-2 approval: {error}"))
    })?;
    let res = sqlx::query(
        "UPDATE vm_day2_operations SET \
         status = 'Approved', plan_json = $2::jsonb, updated_at = NOW() \
         WHERE id = $1 AND status = 'Validated' \
           AND configuration_item_id = $5 \
           AND target_provenance = 'cmdb-configuration-item' \
           AND plan_json #>> '{target_authority,configuration_item_id}' = \
               configuration_item_id::text \
           AND plan_json #>> '{target_authority,provenance}' = target_provenance \
           AND plan_json #>> '{governance,plan_digest}' = $3 \
           AND plan_json #>> '{governance,planned_by}' = $4 \
           AND NULLIF(plan_json #>> '{governance,planned_by}', '') IS NOT NULL \
           AND plan_json #> '{governance,approval}' IS NULL \
           AND plan_json #> '{governance,operation_lock}' IS NULL \
           AND (plan_json - 'status' - 'updated_at' - 'metadata' - 'governance') = \
               ($2::jsonb - 'status' - 'updated_at' - 'metadata' - 'governance') \
           AND $2::jsonb #>> '{governance,approval,plan_digest}' = $3 \
           AND NULLIF($2::jsonb #>> '{governance,approval,approved_by}', '') IS NOT NULL \
           AND $2::jsonb #>> '{governance,approval,approved_by}' <> $4 \
           AND NULLIF($2::jsonb #>> '{governance,approval,approved_at}', '')::timestamptz \
               <= clock_timestamp() + INTERVAL '5 minutes'",
    )
    .bind(uid)
    .bind(&plan_json)
    .bind(&governance.plan_digest)
    .bind(&governance.planned_by)
    .bind(configuration_item_id)
    .execute(pool)
    .await?;

    Ok(res.rows_affected() == 1)
}

/// Acquire a durable, short-lived lock for the exact approved plan. A
/// transaction-scoped advisory lock serializes contenders for the same VM
/// scope; the guarded UPDATE then refuses any still-active overlapping lock.
pub async fn acquire_lock_transition(
    pool: &PgPool,
    op: &VmDay2ChangeRequest,
) -> Result<bool, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(&op.id) else {
        return Ok(false);
    };
    let Some(configuration_item_id) = authoritative_target_id(op) else {
        return Ok(false);
    };
    let Some(governance) = op.governance.as_ref() else {
        return Ok(false);
    };
    let (Some(approval), Some(operation_lock)) = (
        governance.approval.as_ref(),
        governance.operation_lock.as_ref(),
    ) else {
        return Ok(false);
    };
    if op.status != VmChangeStatus::Locked
        || governance.planned_by.trim().is_empty()
        || approval.approved_by.trim().is_empty()
        || governance.planned_by == approval.approved_by
        || governance.plan_digest != approval.plan_digest
        || governance.plan_digest != operation_lock.plan_digest
        || Uuid::parse_str(&operation_lock.lock_id).is_err()
        || operation_lock.locked_by.trim().is_empty()
    {
        return Ok(false);
    }

    let plan_json = serde_json::to_string(op)
        .map_err(|error| sqlx::Error::Protocol(format!("cannot encode VM Day-2 lock: {error}")))?;
    let lock_scope = configuration_item_id.to_string();
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))")
        .bind(&lock_scope)
        .execute(&mut *tx)
        .await?;

    let res = sqlx::query(
        "UPDATE vm_day2_operations AS current_op SET \
         status = 'Locked', plan_json = $2::jsonb, updated_at = NOW() \
         WHERE current_op.id = $1 AND current_op.status = 'Approved' \
           AND current_op.configuration_item_id = $5 \
           AND current_op.target_provenance = 'cmdb-configuration-item' \
           AND current_op.plan_json #>> '{target_authority,configuration_item_id}' = \
               current_op.configuration_item_id::text \
           AND current_op.plan_json #>> '{target_authority,provenance}' = \
               current_op.target_provenance \
           AND current_op.plan_json #>> '{governance,plan_digest}' = $3 \
           AND current_op.plan_json #>> '{governance,planned_by}' = $4 \
           AND current_op.plan_json #> '{governance,approval}' = \
               $2::jsonb #> '{governance,approval}' \
           AND current_op.plan_json #> '{governance,operation_lock}' IS NULL \
           AND (current_op.plan_json - 'status' - 'updated_at' - 'metadata' - 'governance') = \
               ($2::jsonb - 'status' - 'updated_at' - 'metadata' - 'governance') \
           AND $2::jsonb #>> '{governance,operation_lock,plan_digest}' = $3 \
           AND NULLIF($2::jsonb #>> '{governance,operation_lock,lock_id}', '') IS NOT NULL \
           AND NULLIF($2::jsonb #>> '{governance,operation_lock,locked_by}', '') IS NOT NULL \
           AND NULLIF($2::jsonb #>> '{governance,operation_lock,acquired_at}', '')::timestamptz \
               <= clock_timestamp() + INTERVAL '5 minutes' \
           AND NULLIF($2::jsonb #>> '{governance,operation_lock,expires_at}', '')::timestamptz \
               > clock_timestamp() \
           AND NULLIF($2::jsonb #>> '{governance,operation_lock,expires_at}', '')::timestamptz \
               > NULLIF($2::jsonb #>> '{governance,operation_lock,acquired_at}', '')::timestamptz \
           AND NULLIF($2::jsonb #>> '{governance,operation_lock,expires_at}', '')::timestamptz \
               <= NULLIF($2::jsonb #>> '{governance,operation_lock,acquired_at}', '')::timestamptz \
                  + INTERVAL '20 minutes' \
           AND NOT EXISTS ( \
               SELECT 1 FROM vm_day2_operations AS other \
               WHERE other.id <> current_op.id \
                 AND other.configuration_item_id = current_op.configuration_item_id \
                 AND other.target_provenance = 'cmdb-configuration-item' \
                 AND other.status = 'Locked' \
                 AND NULLIF(other.plan_json #>> '{governance,operation_lock,expires_at}', '')::timestamptz \
                     > clock_timestamp() \
           )",
    )
    .bind(uid)
    .bind(&plan_json)
    .bind(&governance.plan_digest)
    .bind(&governance.planned_by)
    .bind(configuration_item_id)
    .execute(&mut *tx)
    .await?;

    if res.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(false);
    }
    tx.commit().await?;
    Ok(true)
}

/// Execute only while the exact stored lock remains active according to the
/// database clock. This closes the application-check/DB-write race: expiry,
/// digest, approval, lock id, and scalar status are one atomic predicate.
pub async fn execute_transition(
    pool: &PgPool,
    op: &VmDay2ChangeRequest,
) -> Result<bool, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(&op.id) else {
        return Ok(false);
    };
    let Some(configuration_item_id) = authoritative_target_id(op) else {
        return Ok(false);
    };
    let Some(governance) = op.governance.as_ref() else {
        return Ok(false);
    };
    let (Some(approval), Some(operation_lock)) = (
        governance.approval.as_ref(),
        governance.operation_lock.as_ref(),
    ) else {
        return Ok(false);
    };
    if op.status != VmChangeStatus::Executed
        || governance.planned_by.trim().is_empty()
        || approval.approved_by.trim().is_empty()
        || governance.planned_by == approval.approved_by
        || governance.plan_digest != approval.plan_digest
        || governance.plan_digest != operation_lock.plan_digest
        || Uuid::parse_str(&operation_lock.lock_id).is_err()
        || operation_lock.locked_by.trim().is_empty()
    {
        return Ok(false);
    }

    let plan_json = serde_json::to_string(op).map_err(|error| {
        sqlx::Error::Protocol(format!("cannot encode VM Day-2 execution: {error}"))
    })?;
    let res = sqlx::query(
        "UPDATE vm_day2_operations SET \
         status = 'Executed', plan_json = $2::jsonb, updated_at = NOW() \
         WHERE id = $1 AND status = 'Locked' \
           AND configuration_item_id = $5 \
           AND target_provenance = 'cmdb-configuration-item' \
           AND plan_json #>> '{target_authority,configuration_item_id}' = \
               configuration_item_id::text \
           AND plan_json #>> '{target_authority,provenance}' = target_provenance \
           AND plan_json #>> '{governance,plan_digest}' = $3 \
           AND plan_json #>> '{governance,planned_by}' = $4 \
           AND plan_json #> '{governance,approval}' = $2::jsonb #> '{governance,approval}' \
           AND plan_json #> '{governance,operation_lock}' = \
               $2::jsonb #> '{governance,operation_lock}' \
           AND (plan_json - 'status' - 'updated_at' - 'metadata' - 'governance') = \
               ($2::jsonb - 'status' - 'updated_at' - 'metadata' - 'governance') \
           AND NULLIF(plan_json #>> '{governance,operation_lock,expires_at}', '')::timestamptz \
               > clock_timestamp()",
    )
    .bind(uid)
    .bind(&plan_json)
    .bind(&governance.plan_digest)
    .bind(&governance.planned_by)
    .bind(configuration_item_id)
    .execute(pool)
    .await?;

    Ok(res.rows_affected() == 1)
}

// Run with: RYUKI_DATABASE_URL=<url> cargo test -p ryuki-api --bins
// vm_day2_target_authority_db_tests -- --test-threads=1
#[cfg(test)]
mod vm_day2_target_authority_db_tests {
    use super::*;
    use crate::database::DB_TEST_SERIAL;
    use serde_json::json;
    use std::time::Duration;

    async fn global_pool() -> Option<&'static PgPool> {
        let url = std::env::var("RYUKI_DATABASE_URL").ok()?;
        if url.is_empty() {
            return None;
        }
        crate::database::try_connect_with_url(&url, 5, 1, 300, 30, 1800).await;
        let pool = crate::database::get_db()?;
        crate::database::run_migrations(pool).await.ok()?;
        Some(pool)
    }

    async fn seed_server(pool: &PgPool, name: &str, owner: &str) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO configuration_items \
             (ci_name, ci_type, criticality, site, environment, owner) \
             VALUES ($1, 'Server', 'High', 'DEFRA', 'production', $2) \
             ON CONFLICT (ci_name) DO UPDATE SET \
                 ci_type = EXCLUDED.ci_type, criticality = EXCLUDED.criticality, \
                 site = EXCLUDED.site, environment = EXCLUDED.environment, \
                 owner = EXCLUDED.owner \
             RETURNING id",
        )
        .bind(name)
        .bind(owner)
        .fetch_one(pool)
        .await
        .expect("seed VM target")
    }

    async fn cleanup(pool: &PgPool, operation_ids: &[Uuid], target_names: &[&str]) {
        for operation_id in operation_ids {
            sqlx::query("DELETE FROM vm_day2_operations WHERE id = $1")
                .bind(operation_id)
                .execute(pool)
                .await
                .ok();
        }
        for target_name in target_names {
            sqlx::query("DELETE FROM configuration_items WHERE ci_name = $1")
                .bind(target_name)
                .execute(pool)
                .await
                .ok();
        }
    }

    async fn plan_and_insert(pool: &PgPool, target_name: &str) -> (Uuid, VmDay2ChangeRequest) {
        let mut tx = pool.begin().await.expect("begin VM planning transaction");
        let target = resolve_authorized_target_for_plan(&mut tx, target_name, &[], &[])
            .await
            .expect("resolve target")
            .expect("authorized target");
        let mut operation = target
            .plan_change(
                VmChangeType::ResizeCpu,
                8,
                "vm-day2-operation-owner",
                "EU-Overnight",
            )
            .expect("plan from target");
        let operation_id = Uuid::new_v4();
        operation.id = operation_id.to_string();
        vm_operations::bind_vm_day2_governance(&mut operation, "vm-day2-test-planner")
            .expect("bind governance");
        insert_authorized(&mut tx, &target, &operation)
            .await
            .expect("insert authorized operation");
        tx.commit().await.expect("commit VM plan");
        (operation_id, operation)
    }

    async fn direct_classified_insert(
        pool: &PgPool,
        operation_id: Uuid,
        configuration_item_id: Uuid,
        target_name: &str,
        site: &str,
        owner: &str,
    ) -> Result<(), sqlx::Error> {
        let plan_json = json!({
            "id": operation_id.to_string(),
            "target_ci_key": target_name,
            "target_authority": {
                "configuration_item_id": configuration_item_id.to_string(),
                "provenance": CMDB_TARGET_PROVENANCE,
            },
            "site": site,
            "environment": "production",
            "owner": owner,
            "status": "Planned",
        });
        sqlx::query(
            "INSERT INTO vm_day2_operations \
             (id, configuration_item_id, target_provenance, target_ci_key, \
              change_type, target_value, site, environment, owner, \
              maintenance_window, status, plan_json) \
             VALUES ($1, $2, 'cmdb-configuration-item', $3, 'resize-cpu', 8, \
                     $4, 'production', $5, 'EU-Overnight', 'Planned', $6)",
        )
        .bind(operation_id)
        .bind(configuration_item_id)
        .bind(target_name)
        .bind(site)
        .bind(owner)
        .bind(plan_json)
        .execute(pool)
        .await
        .map(|_| ())
    }

    #[tokio::test]
    async fn authorized_target_derives_axes_and_persists_uuid_provenance() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set / DB unavailable");
            return;
        };
        let suffix = Uuid::new_v4().simple().to_string();
        let target_name = format!("vm-day2-authority-{suffix}");
        let owner = format!("vm-owner-{suffix}");
        let target_id = seed_server(pool, &target_name, &owner).await;

        let (operation_id, operation) = plan_and_insert(pool, &target_name).await;
        assert_eq!(operation.target_ci_key, target_name);
        assert_eq!(operation.site, "DEFRA");
        assert_eq!(operation.environment, "production");
        assert_eq!(operation.owner, "vm-day2-operation-owner");
        let authority = operation
            .target_authority
            .as_ref()
            .expect("target authority");
        assert_eq!(authority.configuration_item_id, target_id.to_string());
        assert_eq!(
            authority.provenance,
            VmDay2TargetProvenance::CmdbConfigurationItem
        );

        let persisted = get_authorized(pool, &operation_id.to_string(), &[], &[])
            .await
            .expect("read operation")
            .expect("persisted operation");
        assert_eq!(persisted, operation);
        cleanup(pool, &[operation_id], &[&target_name]).await;
    }

    #[tokio::test]
    async fn arbitrary_non_server_and_out_of_scope_targets_are_rejected() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set / DB unavailable");
            return;
        };
        let suffix = Uuid::new_v4().simple().to_string();
        let server_name = format!("vm-day2-scoped-{suffix}");
        let app_name = format!("vm-day2-not-server-{suffix}");
        let unclassified_name = format!("vm-day2-unclassified-{suffix}");
        let inactive_name = format!("vm-day2-inactive-{suffix}");
        seed_server(pool, &server_name, "scope-owner").await;
        seed_server(pool, &unclassified_name, "unclassified-owner").await;
        sqlx::query("UPDATE configuration_items SET environment = NULL WHERE ci_name = $1")
            .bind(&unclassified_name)
            .execute(pool)
            .await
            .expect("clear unclassified environment");
        sqlx::query(
            "INSERT INTO configuration_items \
             (ci_name, ci_type, criticality, site, environment, owner) \
             VALUES ($1, 'Application', 'High', 'DEFRA', 'production', 'app-owner')",
        )
        .bind(&app_name)
        .execute(pool)
        .await
        .expect("seed non-Server CI");
        sqlx::query(
            "INSERT INTO configuration_items \
             (ci_name, ci_type, criticality, site, environment, owner) \
             VALUES ($1, 'Server', 'High', 'DEMUC', 'production', 'inactive-owner')",
        )
        .bind(&inactive_name)
        .execute(pool)
        .await
        .expect("seed inactive-site Server CI");

        let mut tx = pool.begin().await.expect("begin target checks");
        assert!(
            resolve_authorized_target_for_plan(&mut tx, "missing-vm-target", &[], &[])
                .await
                .expect("resolve missing")
                .is_none()
        );
        assert!(
            resolve_authorized_target_for_plan(&mut tx, &app_name, &[], &[])
                .await
                .expect("resolve non-Server")
                .is_none()
        );
        assert!(
            resolve_authorized_target_for_plan(&mut tx, &unclassified_name, &[], &[])
                .await
                .expect("resolve unclassified environment")
                .is_none()
        );
        assert!(
            resolve_authorized_target_for_plan(&mut tx, &inactive_name, &[], &[])
                .await
                .expect("resolve inactive-site target")
                .is_none()
        );
        assert!(resolve_authorized_target_for_plan(
            &mut tx,
            &server_name,
            &["GBLON".to_string()],
            &["production".to_string()],
        )
        .await
        .expect("resolve foreign target")
        .is_none());
        assert!(resolve_authorized_target_for_plan(
            &mut tx,
            &server_name,
            &["DEFRA".to_string()],
            &["development".to_string()],
        )
        .await
        .expect("resolve foreign environment")
        .is_none());
        tx.rollback().await.expect("rollback target checks");
        cleanup(
            pool,
            &[],
            &[&server_name, &app_name, &unclassified_name, &inactive_name],
        )
        .await;
    }

    #[tokio::test]
    async fn planning_lock_serializes_concurrent_cmdb_rebinding() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set / DB unavailable");
            return;
        };
        let suffix = Uuid::new_v4().simple().to_string();
        let target_name = format!("vm-day2-race-{suffix}");
        let target_id = seed_server(pool, &target_name, "race-owner").await;

        let mut planning_tx = pool.begin().await.expect("begin planning transaction");
        let target = resolve_authorized_target_for_plan(&mut planning_tx, &target_name, &[], &[])
            .await
            .expect("resolve target")
            .expect("authorized target");

        let update_pool = pool.clone();
        let mut concurrent_update = tokio::spawn(async move {
            let mut update_tx = update_pool.begin().await.expect("begin CMDB update");
            let result = sqlx::query(
                "UPDATE configuration_items SET environment = 'raced-environment' WHERE id = $1",
            )
            .bind(target_id)
            .execute(&mut *update_tx)
            .await;
            update_tx.rollback().await.expect("rollback CMDB update");
            result
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut concurrent_update)
                .await
                .is_err(),
            "CMDB authority mutation must wait for the planning lock"
        );

        let mut operation = target
            .plan_change(
                VmChangeType::ResizeCpu,
                8,
                "race-operation-owner",
                "EU-Overnight",
            )
            .expect("plan from locked target");
        let operation_id = Uuid::new_v4();
        operation.id = operation_id.to_string();
        vm_operations::bind_vm_day2_governance(&mut operation, "race-planner")
            .expect("bind governance");
        insert_authorized(&mut planning_tx, &target, &operation)
            .await
            .expect("insert while target lock held");
        planning_tx.commit().await.expect("commit plan");

        tokio::time::timeout(Duration::from_secs(5), concurrent_update)
            .await
            .expect("CMDB update unblocked after planning commit")
            .expect("CMDB update task")
            .expect("CMDB update query");
        let persisted = get(pool, &operation_id.to_string())
            .await
            .expect("read planned operation")
            .expect("operation remains authoritative");
        assert_eq!(persisted.owner, "race-operation-owner");
        cleanup(pool, &[operation_id], &[&target_name]).await;
    }

    #[tokio::test]
    async fn lifecycle_transition_rechecks_current_cmdb_authority() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set / DB unavailable");
            return;
        };
        let suffix = Uuid::new_v4().simple().to_string();
        let target_name = format!("vm-day2-drift-{suffix}");
        seed_server(pool, &target_name, "drift-owner").await;
        let (operation_id, mut operation) = plan_and_insert(pool, &target_name).await;

        sqlx::query("UPDATE configuration_items SET environment = 'staging' WHERE ci_name = $1")
            .bind(&target_name)
            .execute(pool)
            .await
            .expect("drift target authority");
        operation.status = VmChangeStatus::Validated;
        let transition = super::transition(pool, "Planned", &operation).await;
        assert!(
            transition.is_err(),
            "a lifecycle write must fail after its CMDB authority tuple drifts"
        );

        sqlx::query("UPDATE configuration_items SET environment = 'production' WHERE ci_name = $1")
            .bind(&target_name)
            .execute(pool)
            .await
            .expect("restore target authority for cleanup");
        let persisted = get(pool, &operation_id.to_string())
            .await
            .expect("read unchanged operation")
            .expect("operation remains present");
        assert_eq!(persisted.status, VmChangeStatus::Planned);
        cleanup(pool, &[operation_id], &[&target_name]).await;
    }

    #[tokio::test]
    async fn database_rejects_direct_arbitrary_binding_and_authority_rebind() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set / DB unavailable");
            return;
        };
        let suffix = Uuid::new_v4().simple().to_string();
        let target_name = format!("vm-day2-direct-{suffix}");
        let other_name = format!("vm-day2-direct-other-{suffix}");
        let app_name = format!("vm-day2-direct-app-{suffix}");
        let inactive_name = format!("vm-day2-direct-inactive-{suffix}");
        let target_id = seed_server(pool, &target_name, "direct-owner").await;
        let other_id = seed_server(pool, &other_name, "other-owner").await;
        let app_id: Uuid = sqlx::query_scalar(
            "INSERT INTO configuration_items \
             (ci_name, ci_type, criticality, site, environment, owner) \
             VALUES ($1, 'Application', 'High', 'DEFRA', 'production', 'app-owner') \
             RETURNING id",
        )
        .bind(&app_name)
        .fetch_one(pool)
        .await
        .expect("seed direct-SQL Application CI");
        let inactive_id: Uuid = sqlx::query_scalar(
            "INSERT INTO configuration_items \
             (ci_name, ci_type, criticality, site, environment, owner) \
             VALUES ($1, 'Server', 'High', 'DEMUC', 'production', 'inactive-owner') \
             RETURNING id",
        )
        .bind(&inactive_name)
        .fetch_one(pool)
        .await
        .expect("seed direct-SQL inactive Server CI");

        let forged_id = Uuid::new_v4();
        let forged_key = format!("attacker-selected-{suffix}");
        let forged = direct_classified_insert(
            pool,
            forged_id,
            target_id,
            &forged_key,
            "DEFRA",
            "direct-owner",
        )
        .await;
        assert!(forged.is_err(), "direct arbitrary target binding must fail");

        let non_server_id = Uuid::new_v4();
        let non_server =
            direct_classified_insert(pool, non_server_id, app_id, &app_name, "DEFRA", "app-owner")
                .await;
        assert!(
            non_server.is_err(),
            "direct binding to a non-Server CI must fail"
        );

        let inactive_operation_id = Uuid::new_v4();
        let inactive = direct_classified_insert(
            pool,
            inactive_operation_id,
            inactive_id,
            &inactive_name,
            "DEMUC",
            "inactive-owner",
        )
        .await;
        assert!(
            inactive.is_err(),
            "direct binding to an inactive-site Server must fail"
        );

        let unresolved_id = Uuid::new_v4();
        let unresolved = sqlx::query(
            "INSERT INTO vm_day2_operations \
             (id, target_ci_key, change_type, target_value, site, environment, \
              owner, maintenance_window, status, plan_json) \
             VALUES ($1, $2, 'resize-cpu', 8, 'DEFRA', 'production', \
                     'direct-owner', 'EU-Overnight', 'Planned', NULL)",
        )
        .bind(unresolved_id)
        .bind(&target_name)
        .execute(pool)
        .await;
        assert!(
            unresolved.is_err(),
            "new unresolved target provenance must fail"
        );

        let (operation_id, _) = plan_and_insert(pool, &target_name).await;
        let rebound =
            sqlx::query("UPDATE vm_day2_operations SET configuration_item_id = $2 WHERE id = $1")
                .bind(operation_id)
                .bind(other_id)
                .execute(pool)
                .await;
        assert!(rebound.is_err(), "persisted CMDB UUID must be immutable");

        cleanup(
            pool,
            &[
                operation_id,
                forged_id,
                non_server_id,
                inactive_operation_id,
                unresolved_id,
            ],
            &[&target_name, &other_name, &app_name, &inactive_name],
        )
        .await;
    }
}
