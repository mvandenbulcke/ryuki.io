//! Repository functions for `patch_waves`.
//!
//! Mutation functions (`insert`, `transition`) accept either a `PgPool`
//! reference (standalone call) or a `&mut PgConnection` (caller-owned tx) so
//! that handlers can compose the repo mutation and an audit row atomically.
//! Read functions (`get`, `list_page`, `count`) remain `&PgPool`-only. Callers
//! are responsible for mapping `sqlx::Error` → 500 and `None` → 404.
//!
//! # Approval provenance
//! `transition` accepts an optional typed checker only for approval. The
//! checker write, status CAS, and handler audit share one transaction.

use ryuki_core::PrincipalId;
use ryuki_engine::models::{PatchSchedule, PatchWave, PatchWaveStatus, RebootPolicy};
use sqlx::{PgConnection, PgPool};
use std::collections::HashMap;
use uuid::Uuid;

// ─── Column list ─────────────────────────────────────────────────────────────

/// SELECT column list. UUID → text so sqlx binds into String; JSONB → text
/// so we can `serde_json::from_str` them.
pub const COLUMNS: &str = "id::text AS id, \
     name, \
     servers::text AS servers, \
     site_scope::text AS site_scope, \
     environment_scope::text AS environment_scope, \
     schedule::text AS schedule, \
     reboot_policy, \
     blackout_dates::text AS blackout_dates, \
     validation_errors::text AS validation_errors, \
     status, \
     metadata::text AS metadata, \
     maker_binding_state, \
     maker_principal_id, \
     approved_by_principal_id";

// ─── Overdue-scan projection (#59) ─────────────────────────────────────────────

/// Minimal projection for `patch_wave_overdue_scan`. A shift item has one typed
/// resource scope, so only waves with exactly one canonical site and zero or one
/// environment are eligible. Multi-scope or malformed waves remain fail-closed
/// instead of being guessed into one site's queue.
#[derive(sqlx::FromRow)]
pub struct ScheduledWaveRow {
    pub id: String,
    pub name: String,
    pub scheduled_start: String,
    pub site: String,
    pub environment: Option<String>,
}

/// Fetch every patch wave in status 'Scheduled' (committed to start at
/// `schedule->>'start'`) for the overdue scan. Only 'Scheduled' waves are considered —
/// a wave that has already moved to 'InProgress'/'Completed'/'Failed' has acted on its
/// window, and Draft/Validated/Approved waves are not yet committed to a start.
pub async fn scheduled_waves_for_overdue_scan(
    executor: impl sqlx::PgExecutor<'_>,
) -> Result<Vec<ScheduledWaveRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT wave.id::text AS id, wave.name, \
                COALESCE(wave.schedule->>'start', '') AS scheduled_start, \
                wave.site_scope->>0 AS site, \
                CASE WHEN jsonb_typeof(wave.environment_scope) = 'array' THEN \
                         CASE WHEN jsonb_array_length(wave.environment_scope) = 1 \
                              THEN wave.environment_scope->>0 ELSE NULL END \
                     ELSE NULL END AS environment \
         FROM patch_waves AS wave \
         INNER JOIN site_registry AS registry \
                 ON registry.unlocode = wave.site_scope->>0 \
                AND registry.active = true \
         WHERE wave.status = 'Scheduled' \
           AND CASE WHEN jsonb_typeof(wave.site_scope) = 'array' \
                    THEN jsonb_array_length(wave.site_scope) = 1 ELSE false END \
           AND jsonb_typeof(wave.site_scope->0) = 'string' \
           AND CASE WHEN jsonb_typeof(wave.environment_scope) = 'array' \
                    THEN jsonb_array_length(wave.environment_scope) <= 1 ELSE false END \
           AND CASE WHEN jsonb_typeof(wave.environment_scope) = 'array' \
                    THEN (jsonb_array_length(wave.environment_scope) = 0 \
                          OR jsonb_typeof(wave.environment_scope->0) = 'string') \
                    ELSE false END \
         ORDER BY wave.id \
         FOR SHARE OF wave, registry",
    )
    .fetch_all(executor)
    .await
}

// ─── Row struct ──────────────────────────────────────────────────────────────

/// The DB-managed `created_at`/`updated_at` columns are not part of the
/// `PatchWave` model, so they are not selected/decoded here. `list_page` still
/// orders by `created_at` in SQL (a column need not be in the SELECT list to be
/// ordered by).
#[derive(sqlx::FromRow)]
pub struct PatchWaveRow {
    pub id: String,
    pub name: String,
    /// Raw JSON text from JSONB::text cast, e.g. `["srv-01","srv-02"]`
    pub servers: String,
    /// Raw JSON text from JSONB::text cast, e.g. `["DEFRA"]`
    pub site_scope: String,
    /// Raw JSON text from JSONB::text cast, e.g. `["production"]`
    pub environment_scope: String,
    /// Raw JSON text from JSONB::text cast (PatchSchedule object)
    pub schedule: String,
    pub reboot_policy: String,
    /// Raw JSON text from JSONB::text cast, e.g. `[]`
    pub blackout_dates: String,
    /// Raw JSON text from JSONB::text cast, e.g. `[]`
    pub validation_errors: String,
    pub status: String,
    /// Raw JSON text from JSONB::text cast, e.g. `{"k":"v"}`
    pub metadata: String,
    pub maker_binding_state: String,
    pub maker_principal_id: Option<Uuid>,
    pub approved_by_principal_id: Option<Uuid>,
}

/// Immutable authorization provenance stored beside the caller-editable wave
/// model. Rows created before migration 205 remain explicitly unresolved and
/// cannot enter the approval transition.
#[derive(Debug)]
pub struct PersistedPatchWave {
    pub wave: PatchWave,
    pub maker_principal_id: Option<PrincipalId>,
    pub approved_by_principal_id: Option<PrincipalId>,
}

impl PatchWaveRow {
    /// Convert a DB row into the engine model.
    ///
    /// JSONB-text and enum-name fields are deserialized via `serde_json`. A
    /// parse failure means the persisted row is corrupt; we surface it as a
    /// decode error (caller → 500) rather than silently substituting defaults —
    /// a subsequent `transition` would otherwise persist those defaults over the
    /// real data, since the CAS only guards `status`, not the other columns.
    pub fn into_record(self) -> Result<PersistedPatchWave, sqlx::Error> {
        fn decode<T: serde::de::DeserializeOwned>(
            raw: &str,
            field: &str,
        ) -> Result<T, sqlx::Error> {
            serde_json::from_str(raw).map_err(|e| {
                sqlx::Error::Decode(
                    format!("patch_waves.{field}: corrupt persisted value: {e}").into(),
                )
            })
        }

        let servers: Vec<String> = decode(&self.servers, "servers")?;
        let site_scope: Vec<String> = decode(&self.site_scope, "site_scope")?;
        let environment_scope: Vec<String> = decode(&self.environment_scope, "environment_scope")?;
        let schedule: PatchSchedule = decode(&self.schedule, "schedule")?;
        let blackout_dates: Vec<String> = decode(&self.blackout_dates, "blackout_dates")?;
        let validation_errors: Vec<String> = decode(&self.validation_errors, "validation_errors")?;
        let metadata: HashMap<String, String> = decode(&self.metadata, "metadata")?;

        // Enum variants are stored as their serde name (e.g. "Draft",
        // "RebootIfRequired"); decode via the engine's Deserialize impl. A DB
        // CHECK constraint (migration 058) keeps these in the legal set.
        let status: PatchWaveStatus = decode(&format!("\"{}\"", self.status), "status")?;
        let reboot_policy: RebootPolicy =
            decode(&format!("\"{}\"", self.reboot_policy), "reboot_policy")?;

        let maker_principal_id = self
            .maker_principal_id
            .map(PrincipalId::from_uuid)
            .transpose()
            .map_err(|e| {
                sqlx::Error::Decode(
                    format!("patch_waves.maker_principal_id: corrupt persisted value: {e}").into(),
                )
            })?;
        let approved_by_principal_id = self
            .approved_by_principal_id
            .map(PrincipalId::from_uuid)
            .transpose()
            .map_err(|e| {
                sqlx::Error::Decode(
                    format!("patch_waves.approved_by_principal_id: corrupt persisted value: {e}")
                        .into(),
                )
            })?;

        let verified_provenance_is_consistent = maker_principal_id.is_some()
            && match &status {
                PatchWaveStatus::Draft | PatchWaveStatus::Validated => {
                    approved_by_principal_id.is_none()
                }
                PatchWaveStatus::Approved
                | PatchWaveStatus::Scheduled
                | PatchWaveStatus::InProgress
                | PatchWaveStatus::Completed
                | PatchWaveStatus::Failed => {
                    approved_by_principal_id.is_some()
                        && approved_by_principal_id != maker_principal_id
                }
            };
        match self.maker_binding_state.as_str() {
            "unresolved-legacy"
                if maker_principal_id.is_none() && approved_by_principal_id.is_none() => {}
            "verified-principal" if verified_provenance_is_consistent => {}
            state => {
                return Err(sqlx::Error::Decode(
                    format!(
                        "patch_waves.maker_binding_state: inconsistent persisted provenance: {state}"
                    )
                    .into(),
                ));
            }
        }

        let wave = PatchWave {
            id: self.id,
            name: self.name,
            servers,
            site_scope,
            environment_scope,
            schedule,
            reboot_policy,
            blackout_dates,
            validation_errors,
            status,
            metadata,
        };

        Ok(PersistedPatchWave {
            wave,
            maker_principal_id,
            approved_by_principal_id,
        })
    }

    pub fn into_model(self) -> Result<PatchWave, sqlx::Error> {
        self.into_record().map(|record| record.wave)
    }
}

// ─── Enum serialisation helpers ───────────────────────────────────────────────

/// Canonical serde variant name for a `PatchWaveStatus` value as stored in the
/// DB (e.g. `"Draft"`, `"Validated"`). `pub` so transition handlers can supply
/// the `expected_status` argument to `transition` without duplicating this table.
pub fn status_str(s: &PatchWaveStatus) -> &'static str {
    match s {
        PatchWaveStatus::Draft => "Draft",
        PatchWaveStatus::Validated => "Validated",
        PatchWaveStatus::Approved => "Approved",
        PatchWaveStatus::Scheduled => "Scheduled",
        PatchWaveStatus::InProgress => "InProgress",
        PatchWaveStatus::Completed => "Completed",
        PatchWaveStatus::Failed => "Failed",
    }
}

/// Canonical serde variant name for a `RebootPolicy` value as stored in the DB
/// (e.g. `"RebootIfRequired"`, `"NoReboot"`).
pub fn reboot_policy_str(p: &RebootPolicy) -> &'static str {
    match p {
        RebootPolicy::RebootIfRequired => "RebootIfRequired",
        RebootPolicy::RebootAlways => "RebootAlways",
        RebootPolicy::NoReboot => "NoReboot",
        RebootPolicy::ScheduleOnly => "ScheduleOnly",
    }
}

// ─── Repository functions ─────────────────────────────────────────────────────

/// Insert a new patch wave. The caller supplies the model with an
/// already-generated UUID string as `id`; we parse it for the PK column.
///
/// The legacy `site` and `os_family` columns (nullable as of migration 058) are
/// derived from the model: `site` from `site_scope.first()` and `os_family` from
/// `metadata["os_family"]`, or NULL when the model carries no such value.
///
/// Accepts any `sqlx::PgExecutor` — pass `pool` for a standalone call, or
/// `&mut *tx` to share a transaction with an audit write.
pub async fn insert(
    executor: impl sqlx::PgExecutor<'_>,
    w: &PatchWave,
    maker_principal_id: PrincipalId,
) -> Result<(), sqlx::Error> {
    let id = Uuid::parse_str(&w.id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

    let servers = serde_json::to_string(&w.servers).unwrap_or_else(|_| "[]".into());
    let site_scope = serde_json::to_string(&w.site_scope).unwrap_or_else(|_| "[]".into());
    let environment_scope =
        serde_json::to_string(&w.environment_scope).unwrap_or_else(|_| "[]".into());
    let schedule = serde_json::to_string(&w.schedule).unwrap_or_else(|_| "{}".into());
    let blackout_dates = serde_json::to_string(&w.blackout_dates).unwrap_or_else(|_| "[]".into());
    let validation_errors =
        serde_json::to_string(&w.validation_errors).unwrap_or_else(|_| "[]".into());
    let meta = serde_json::to_string(&w.metadata).unwrap_or_else(|_| "{}".into());

    // Legacy denormalized columns (nullable as of migration 058): the model's
    // authoritative values live in site_scope / metadata. Record NULL — never an
    // empty string in a would-be-NOT-NULL column — when the model has no value.
    let site = w.site_scope.first().cloned().filter(|s| !s.is_empty());
    let os_family = w
        .metadata
        .get("os_family")
        .cloned()
        .filter(|s| !s.is_empty());

    sqlx::query(
        "INSERT INTO patch_waves \
         (id, site, os_family, name, servers, site_scope, environment_scope, \
          schedule, reboot_policy, blackout_dates, validation_errors, status, metadata, \
          maker_binding_state, maker_principal_id) \
         VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, \
                 $8::jsonb, $9, $10::jsonb, $11::jsonb, $12, $13::jsonb, \
                 'verified-principal', $14)",
    )
    .bind(id)
    .bind(site)
    .bind(os_family)
    .bind(&w.name)
    .bind(&servers)
    .bind(&site_scope)
    .bind(&environment_scope)
    .bind(&schedule)
    .bind(reboot_policy_str(&w.reboot_policy))
    .bind(&blackout_dates)
    .bind(&validation_errors)
    .bind(status_str(&w.status))
    .bind(&meta)
    .bind(maker_principal_id.into_uuid())
    .execute(executor)
    .await?;

    Ok(())
}

/// Fetch one patch wave by string id. A malformed (non-UUID) id is treated as
/// `Ok(None)` (callers map to 404) rather than an error — keeping every
/// handler's not-found behaviour uniform. `Err` is reserved for genuine DB
/// failures (callers map to 500).
pub async fn get(pool: &PgPool, id: &str) -> Result<Option<PatchWave>, sqlx::Error> {
    Ok(get_record(pool, id).await?.map(|record| record.wave))
}

/// Fetch one wave together with immutable maker/checker provenance. Approval
/// callers must use this projection; the compatibility `get` projection is for
/// lifecycle operations that do not consume maker/checker authority.
pub async fn get_record(
    pool: &PgPool,
    id: &str,
) -> Result<Option<PersistedPatchWave>, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(None);
    };

    let row: Option<PatchWaveRow> =
        sqlx::query_as(&format!("SELECT {COLUMNS} FROM patch_waves WHERE id = $1"))
            .bind(uid)
            .fetch_optional(pool)
            .await?;

    row.map(|r| r.into_record()).transpose()
}

/// Build the per-axis TARGET-SET scope predicate (#2/#14) shared by
/// [`list_page`] and [`count`] so a page and its total can never drift apart.
///
/// A wave's `site_scope`/`environment_scope` are JSONB arrays (its targeting),
/// so this is the SQL push-down of the handler's old in-memory
/// `multi_scope_permits` retain: `None` = the principal is unrestricted on
/// that axis → no predicate; `Some(scopes)` = the wave's array on that axis
/// must be NON-EMPTY (an empty target list means "all" and fails closed for a
/// scoped caller) and contained in `scopes`
/// (`jsonb_array_length > 0 AND axis <@ scopes`). Containment compares entries
/// EXACTLY; the handler passes trimmed scope entries, so this only diverges
/// from the in-memory `r.trim()` comparison for a whitespace-padded PERSISTED
/// target entry — never produced by the wave create/validate path and strictly
/// narrower (hides, never leaks) if hand-seeded. Predicates are built PER
/// BRANCH — never a `($n IS NULL OR ...)` over the column (the generic-plan
/// seq-scan trap). Column names are compile-time literals; every value is a
/// bound parameter (injection-safe).
fn scope_preds(sites: Option<&[String]>, environments: Option<&[String]>) -> (String, Vec<String>) {
    let mut preds: Vec<String> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    if let Some(s) = sites {
        binds.push(serde_json::to_string(s).unwrap_or_else(|_| "[]".into()));
        preds.push(format!(
            "(jsonb_array_length(site_scope) > 0 AND site_scope <@ ${}::jsonb)",
            binds.len()
        ));
    }
    if let Some(e) = environments {
        binds.push(serde_json::to_string(e).unwrap_or_else(|_| "[]".into()));
        preds.push(format!(
            "(jsonb_array_length(environment_scope) > 0 AND environment_scope <@ ${}::jsonb)",
            binds.len()
        ));
    }
    let clause = if preds.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", preds.join(" AND "))
    };
    (clause, binds)
}

/// One `LIMIT`/`OFFSET` page of patch waves (#14), creation time descending,
/// with the principal's multi-target scope pushed into SQL — the paged
/// replacement for the old fetch-all `list` + in-memory `multi_scope_permits`
/// retain. `ORDER BY created_at DESC, id DESC` ends in the unique PK, so equal
/// timestamps still yield a stable, non-overlapping page cut.
pub async fn list_page(
    pool: &PgPool,
    sites: Option<&[String]>,
    environments: Option<&[String]>,
    limit: i64,
    offset: i64,
) -> Result<Vec<PatchWave>, sqlx::Error> {
    let (where_clause, binds) = scope_preds(sites, environments);
    let sql = format!(
        "SELECT {COLUMNS} FROM patch_waves{where_clause} \
         ORDER BY created_at DESC, id DESC LIMIT ${} OFFSET ${}",
        binds.len() + 1,
        binds.len() + 2
    );
    let mut q = sqlx::query_as::<_, PatchWaveRow>(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    let rows = q.bind(limit).bind(offset).fetch_all(pool).await?;
    rows.into_iter().map(|r| r.into_model()).collect()
}

/// Count patch waves under the SAME scope predicate as [`list_page`] — the
/// pagination total (`X-Total-Count`).
pub async fn count(
    pool: &PgPool,
    sites: Option<&[String]>,
    environments: Option<&[String]>,
) -> Result<i64, sqlx::Error> {
    let (where_clause, binds) = scope_preds(sites, environments);
    let sql = format!("SELECT COUNT(*) FROM patch_waves{where_clause}");
    let mut q = sqlx::query_scalar::<_, i64>(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    q.fetch_one(pool).await
}

/// Atomically transition a patch wave to its new state IFF its current DB
/// status still equals `expected_status` (optimistic lock). Returns `Ok(false)`
/// when the row is absent or its status had already changed (caller → 409).
/// `Ok(true)` on success.
///
/// The caller opens the tx, passes `conn = &mut *tx`, and commits on success.
/// An `Ok(false)` (CAS miss) returns without mutating — the caller drops the tx
/// (rollback). Only `Ok(true)` callers should commit.
///
/// `approval_principal_id` is `Some(checker)` only for the
/// `Validated -> Approved` transition. The predicate then requires a verified,
/// distinct persisted maker and an unset checker. Migration 205 independently
/// enforces the same invariant and makes both identities immutable.
pub async fn transition(
    conn: &mut PgConnection,
    expected_status: &str,
    w: &PatchWave,
    approval_principal_id: Option<PrincipalId>,
) -> Result<bool, sqlx::Error> {
    let Ok(uid) = Uuid::parse_str(&w.id) else {
        return Ok(false);
    };

    let servers = serde_json::to_string(&w.servers).unwrap_or_else(|_| "[]".into());
    let site_scope = serde_json::to_string(&w.site_scope).unwrap_or_else(|_| "[]".into());
    let environment_scope =
        serde_json::to_string(&w.environment_scope).unwrap_or_else(|_| "[]".into());
    let schedule = serde_json::to_string(&w.schedule).unwrap_or_else(|_| "{}".into());
    let blackout_dates = serde_json::to_string(&w.blackout_dates).unwrap_or_else(|_| "[]".into());
    let validation_errors =
        serde_json::to_string(&w.validation_errors).unwrap_or_else(|_| "[]".into());
    let meta = serde_json::to_string(&w.metadata).unwrap_or_else(|_| "{}".into());

    let res = sqlx::query(
        "UPDATE patch_waves SET \
         name = $2, \
         servers = $3::jsonb, \
         site_scope = $4::jsonb, \
         environment_scope = $5::jsonb, \
         schedule = $6::jsonb, \
         reboot_policy = $7, \
         blackout_dates = $8::jsonb, \
         validation_errors = $9::jsonb, \
         status = $10, \
         metadata = $11::jsonb, \
         approved_by_principal_id = COALESCE($12::uuid, approved_by_principal_id), \
         updated_at = NOW() \
         WHERE id = $1 AND status = $13 \
           AND ( \
                $12::uuid IS NULL \
                OR (maker_binding_state = 'verified-principal' \
                    AND maker_principal_id IS NOT NULL \
                    AND maker_principal_id <> $12::uuid \
                    AND approved_by_principal_id IS NULL) \
           )",
    )
    .bind(uid)
    .bind(&w.name)
    .bind(&servers)
    .bind(&site_scope)
    .bind(&environment_scope)
    .bind(&schedule)
    .bind(reboot_policy_str(&w.reboot_policy))
    .bind(&blackout_dates)
    .bind(&validation_errors)
    .bind(status_str(&w.status))
    .bind(&meta)
    .bind(approval_principal_id.map(PrincipalId::into_uuid))
    .bind(expected_status)
    .execute(&mut *conn)
    .await?;

    Ok(res.rows_affected() > 0)
}

/// Only an UNAPPROVED-draft patch wave (`Draft`|`Validated`) may be DELETED: an
/// `Approved`/`Scheduled` wave is approver-reviewed (deleting it is an approval-tier
/// cancellation, out of scope for the delete slice), and an `InProgress`/`Completed`/
/// `Failed` wave has executed (its run is evidence). SINGLE source of truth for the
/// handler 409 gate AND the repo defense-in-depth guard below.
pub fn patch_wave_status_deletable(status: &PatchWaveStatus) -> bool {
    matches!(status, PatchWaveStatus::Draft | PatchWaveStatus::Validated)
}

/// Outcome of a patch-wave delete attempt (status CAS + deletability guard).
#[derive(Debug, PartialEq, Eq)]
pub enum DeleteOutcome {
    /// The wave row was deleted (its `patch_wave_servers` cascade with it).
    Deleted,
    /// No row with this id (already gone).
    NotFound,
    /// The row's status moved since it was read (CAS miss) — caller reloads.
    StaleStatus,
    /// `expected` is not a deletable status — defense-in-depth if a caller bypassed
    /// the handler's `patch_wave_status_deletable` check.
    BlockedStatus,
}

/// Delete a patch wave IFF it still matches `expected` (status CAS) AND `expected` is
/// a deletable status. `patch_wave_servers` rows are removed by the DB
/// (`ON DELETE CASCADE`, migration 010). On 0 rows we re-read to disambiguate
/// `NotFound` vs `StaleStatus`.
pub async fn delete(
    conn: &mut PgConnection,
    id: &str,
    expected: &PatchWaveStatus,
) -> Result<DeleteOutcome, sqlx::Error> {
    if !patch_wave_status_deletable(expected) {
        return Ok(DeleteOutcome::BlockedStatus);
    }
    let Ok(uid) = Uuid::parse_str(id) else {
        return Ok(DeleteOutcome::NotFound);
    };
    let res = sqlx::query("DELETE FROM patch_waves WHERE id = $1 AND status = $2")
        .bind(uid)
        .bind(status_str(expected))
        .execute(&mut *conn)
        .await?;
    if res.rows_affected() == 1 {
        return Ok(DeleteOutcome::Deleted);
    }
    // 0 rows: the row is gone, or its status moved since the read.
    let current: Option<String> =
        sqlx::query_scalar("SELECT status FROM patch_waves WHERE id = $1")
            .bind(uid)
            .fetch_optional(&mut *conn)
            .await?;
    match current {
        None => Ok(DeleteOutcome::NotFound),
        Some(_) => Ok(DeleteOutcome::StaleStatus),
    }
}
