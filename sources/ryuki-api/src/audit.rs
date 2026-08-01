//! Append-only audit trail recorder for request lifecycle transitions.
//!
//! Every lifecycle transition (create + validate/plan/approve/lock/execute/
//! verify + the new reject/cancel) records ONE `audit_log` row carrying the
//! REAL verified session identity from the `AuthSession` — never a literal,
//! never a client-supplied actor field. This is the single source of
//! attribution truth: `requests` keeps the live status/stage, `audit_log`
//! holds the durable who-did-what-when trail.
//!
//! The table is append-only at the database level (a BEFORE UPDATE OR DELETE
//! trigger raises). This module exposes only INSERT (`record_audit` /
//! `record_audit_tx`) and SELECT (`audit_trail_for_request`) — there is NO
//! edit/delete surface.
//!
//! DRY-RUN / NO-DB MODE: when there is no DB pool, transitions append to a
//! process-local `Mutex<Vec<AuditEntry>>` (mirroring the request_store
//! pattern) and the read endpoint serves it tagged `durable: false`. No schema
//! runs in that mode and no provider calls are ever made.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::{interval, MissedTickBehavior};

use ryuki_core::PrincipalId;
use ryuki_engine::auth::AuthSession;

// ---------------------------------------------------------------------------
// Tamper-evident hash chain (migration 094)
//
// Each chained row carries `entry_hash = sha256(prev_hash ++ canonical(content))`
// linked to its predecessor's entry_hash. Re-verification (POST
// /api/audit/log/verify) detects any altered content OR any insertion / deletion
// / reordering of rows, even by a privileged operator who bypasses the
// append-only trigger or restores a doctored backup. The hash covers the
// app-known CONTENT only — NOT the DB-generated id/occurred_at, which are
// unknown at insert time; the prev→entry link seals ordering.
//
// TRUST BOUNDARY: this is tamper-EVIDENT, not tamper-PROOF. The chain is an
// UNKEYED hash chain, so an attacker with arbitrary write access who can also
// recompute every entry_hash from the tampered row forward can forge a chain
// that re-verifies. It defends against the realistic threats — accidental
// mutation, a doctored-backup restore, and any mutation that does not rebuild
// the whole tail — and lets an external observer who has recorded the latest
// entry_hash detect any rewrite. Stronger guarantees (an HMAC keyed outside
// Postgres, or periodically anchoring the head entry_hash to external storage)
// are a documented hardening follow-up.
//
// LOCK ORDER: migration 187's append_audit_log() takes the audit advisory lock
// only AFTER any `UPDATE requests` row lock its caller already holds (request
// row → audit lock, always), so concurrent transitions cannot deadlock on the
// two. The SECURITY DEFINER writer also owns id allocation and hash generation.
// ---------------------------------------------------------------------------

/// Predecessor hash of the first row in the chain.
const AUDIT_CHAIN_GENESIS: &str = "GENESIS";

/// Deterministic, canonical JSON: object keys are sorted, arrays keep order,
/// scalars use serde's stable encoding. The SAME logical value hashes
/// identically whether it comes from the app at insert time or from a jsonb
/// round-trip at verify time (jsonb does not preserve key order or whitespace).
fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let inner: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    let key = serde_json::to_string(k).unwrap_or_else(|_| "\"\"".to_string());
                    format!("{key}:{}", canonical_json(&map[k]))
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", inner.join(","))
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// The canonical content string an entry's hash is computed over. Built
/// identically at insert (from the session + record) and at verify (from the
/// stored row), so the two must agree field-for-field. `request_id` is the
/// STORED uuid string (not the raw input), matching what verify reads back.
#[allow(clippy::too_many_arguments)]
fn audit_canonical_payload(
    request_id: Option<&str>,
    actor_principal: &str,
    actor_display: &str,
    actor_roles: &[String],
    provider_mode: &str,
    action: &str,
    from_stage: Option<&str>,
    to_stage: &str,
    from_status: Option<&str>,
    to_status: &str,
    detail: &Value,
    outcome: &str,
) -> String {
    canonical_json(&json!({
        "request_id": request_id,
        "actor_principal": actor_principal,
        "actor_display": actor_display,
        "actor_roles": actor_roles,
        "provider_mode": provider_mode,
        "action": action,
        "from_stage": from_stage,
        "to_stage": to_stage,
        "from_status": from_status,
        "to_status": to_status,
        "detail": detail,
        "outcome": outcome,
    }))
}

/// `sha256(hex16(byte_len(prev_hash))‖prev_hash‖hex16(byte_len(payload))‖payload)`,
/// lowercase hex. Migration 187 uses this same SQL-reproducible v2 framing to
/// backfill and append the complete domain. Pure + deterministic.
fn chain_hash(prev_hash: &str, payload: &str) -> String {
    let mut h = Sha256::new();
    h.update(format!("{:016x}", prev_hash.len()).as_bytes());
    h.update(prev_hash.as_bytes());
    h.update(format!("{:016x}", payload.len()).as_bytes());
    h.update(payload.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Process-local audit entry used only in no-DB (dry-run) mode. The durable
/// trail lives in the `audit_log` table; this mirrors it for demo output and
/// is explicitly tagged non-durable when served.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    reservation_id: uuid::Uuid,
    pub occurred_at: String,
    pub request_id: Option<String>,
    pub actor_principal: String,
    pub actor_display: String,
    pub actor_roles: Vec<String>,
    pub provider_mode: String,
    pub action: String,
    pub from_stage: Option<String>,
    pub to_stage: String,
    pub from_status: Option<String>,
    pub to_status: String,
    pub detail: Value,
    pub outcome: String,
}

impl AuditEntry {
    fn to_json(&self) -> Value {
        json!({
            "occurred_at": self.occurred_at,
            "request_id": self.request_id,
            "actor_principal": self.actor_principal,
            "actor_display": self.actor_display,
            "actor_roles": self.actor_roles,
            "provider_mode": self.provider_mode,
            "action": self.action,
            "from_stage": self.from_stage,
            "to_stage": self.to_stage,
            "from_status": self.from_status,
            "to_status": self.to_status,
            "detail": redact_detail(&self.detail),
            "outcome": self.outcome,
        })
    }
}

/// Redacts secret-bearing values in an audit `detail` JSON before it is served.
/// Every READ path (`/api/requests/{id}/audit`, `/api/activity/audit`, and the
/// evidence pack that embeds the trail) must protect both current and historical
/// rows. The shared bounded engine traversal also recognizes structured header
/// maps, named entries, and tuples rather than inspecting only direct strings.
fn redact_detail(value: &Value) -> Value {
    ryuki_engine::evidence_pipeline::redact_json_evidence_value(value)
}

/// Cap on the process-local (no-DB / dry-run) audit store so a long-running
/// instance cannot grow memory without bound. The most recent entries are kept.
const MAX_LOCAL_AUDIT: usize = 10_000;

static AUDIT_STORE: OnceLock<Mutex<Vec<AuditEntry>>> = OnceLock::new();

fn audit_store() -> &'static Mutex<Vec<AuditEntry>> {
    AUDIT_STORE.get_or_init(|| Mutex::new(Vec::new()))
}

/// Inputs for a single audit row. Actor identity is NOT in here — it is taken
/// exclusively from the `AuthSession` by the recorder, so a forged actor field
/// is impossible.
#[allow(clippy::too_many_arguments)]
pub struct AuditRecord<'a> {
    pub action: &'a str,
    pub request_id: Option<&'a str>,
    pub from_status: Option<&'a str>,
    pub to_status: &'a str,
    pub from_stage: Option<&'a str>,
    pub to_stage: &'a str,
    pub detail: Value,
    pub outcome: &'a str,
}

/// Build an [`AuditRecord`] for a privileged SECURITY operation (API token
/// create/revoke, session revoke, secret rotation) rather than a request
/// lifecycle transition. Those operations have no request_id or lifecycle
/// stage, so `request_id`/`from_stage` are `None` and `to_stage` is the fixed
/// `"security"` marker; the real semantics live in `action`, the status pair,
/// and `detail`. `detail` MUST carry only references (ids, names, scopes) —
/// NEVER secret material (token plaintext/hash, secret values).
pub fn security_audit<'a>(
    action: &'a str,
    from_status: Option<&'a str>,
    to_status: &'a str,
    detail: Value,
) -> AuditRecord<'a> {
    AuditRecord {
        action,
        request_id: None,
        from_status,
        to_status,
        from_stage: None,
        to_stage: "security",
        detail,
        outcome: "success",
    }
}

fn entry_from(
    reservation_id: uuid::Uuid,
    actor_principal: PrincipalId,
    session: &AuthSession,
    record: &AuditRecord<'_>,
) -> AuditEntry {
    AuditEntry {
        reservation_id,
        occurred_at: chrono::Utc::now().to_rfc3339(),
        request_id: record.request_id.map(str::to_string),
        // `audit_log.actor_principal` is an immutable legacy TEXT projection.
        // Stringification happens only at this persistence/display seam; the
        // authority input above remains the typed internal principal id.
        actor_principal: actor_principal.to_string(),
        actor_display: session.display_name.clone(),
        actor_roles: session.roles.clone(),
        provider_mode: session.provider_mode.clone(),
        action: record.action.to_string(),
        from_stage: record.from_stage.map(str::to_string),
        to_stage: record.to_stage.to_string(),
        from_status: record.from_status.map(str::to_string),
        to_status: record.to_status.to_string(),
        detail: record.detail.clone(),
        outcome: record.outcome.to_string(),
    }
}

fn required_principal_id(session: &AuthSession) -> Result<PrincipalId, sqlx::Error> {
    session.principal_id.ok_or_else(|| {
        sqlx::Error::Protocol("audit attribution requires an admitted opaque principal".into())
    })
}

/// Insert one audit row inside an EXISTING transaction. The transition's
/// `UPDATE requests` and this INSERT commit atomically, so a row can never
/// transition without its audit entry. Actor attribution is read from
/// `session` only.
pub async fn record_audit_tx(
    tx: &mut Transaction<'_, Postgres>,
    session: &AuthSession,
    record: &AuditRecord<'_>,
) -> Result<ryuki_engine::authorization::AuditReservationEvidence, sqlx::Error> {
    let actor_principal = required_principal_id(session)?;
    let request_uuid = record
        .request_id
        .and_then(|id| uuid::Uuid::parse_str(id).ok());

    // The database writer serializes the chain, allocates the positive id only
    // after acquiring that lock, derives canonical content, and computes both
    // hashes. Runtime code cannot supply ids or chain fields.
    let audit_log_id: i64 = sqlx::query_scalar(
        "SELECT append_audit_log( \
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12 \
         )",
    )
    .bind(request_uuid)
    // The pre-199 audit schema stores immutable actor evidence as TEXT. It is
    // populated only from the typed internal id, never from a provider claim
    // or compatibility display value.
    .bind(actor_principal.to_string())
    .bind(&session.display_name)
    .bind(&session.roles)
    .bind(&session.provider_mode)
    .bind(record.action)
    .bind(record.from_stage)
    .bind(record.to_stage)
    .bind(record.from_status)
    .bind(record.to_status)
    .bind(record.detail.to_string())
    .bind(record.outcome)
    .fetch_one(&mut **tx)
    .await?;
    let audit_log_id = u64::try_from(audit_log_id)
        .expect("append_audit_log enforces a positive BIGINT identifier");
    Ok(
        ryuki_engine::authorization::AuditReservationEvidence::durable(audit_log_id)
            .expect("append_audit_log returned a positive identifier"),
    )
}

/// Standalone audit insert (its own short transaction) for paths that are not
/// already inside one — primarily DENIED (403) attempts, which are recorded
/// best-effort. A `pool` is required; in no-DB mode use [`record_audit_local`].
pub async fn record_audit(
    pool: &PgPool,
    session: &AuthSession,
    record: &AuditRecord<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let _reservation = record_audit_tx(&mut tx, session, record).await?;
    tx.commit().await?;
    Ok(())
}

/// Append to the process-local audit store (no-DB / dry-run mode). Tagged
/// non-durable when served so demo output is never mistaken for a real trail.
/// An unbound compatibility/display identity is rejected before the store is
/// touched.
pub async fn record_audit_local(
    session: &AuthSession,
    record: &AuditRecord<'_>,
) -> Result<ryuki_engine::authorization::AuditReservationEvidence, sqlx::Error> {
    let reservation = reserve_audit_local(session, record).await?;
    let evidence = reservation.evidence().clone();
    reservation.commit();
    Ok(evidence)
}

/// Rollback-capable local audit reservation retained beside an in-memory
/// request lease. Dropping it before the permit sink succeeds removes the
/// entry, mirroring a database transaction rollback.
pub(crate) struct LocalAuditReservation {
    store: tokio::sync::MutexGuard<'static, Vec<AuditEntry>>,
    reservation_id: uuid::Uuid,
    evidence: ryuki_engine::authorization::AuditReservationEvidence,
    committed: bool,
}

impl LocalAuditReservation {
    pub(crate) fn evidence(&self) -> &ryuki_engine::authorization::AuditReservationEvidence {
        &self.evidence
    }

    pub(crate) fn commit(mut self) {
        if self.store.len() > MAX_LOCAL_AUDIT {
            let excess = self.store.len() - MAX_LOCAL_AUDIT;
            self.store.drain(0..excess);
        }
        self.committed = true;
    }
}

impl Drop for LocalAuditReservation {
    fn drop(&mut self) {
        if !self.committed {
            if let Some(index) = self
                .store
                .iter()
                .position(|entry| entry.reservation_id == self.reservation_id)
            {
                self.store.remove(index);
            }
        }
    }
}

pub(crate) async fn reserve_audit_local(
    session: &AuthSession,
    record: &AuditRecord<'_>,
) -> Result<LocalAuditReservation, sqlx::Error> {
    let actor_principal = required_principal_id(session)?;
    let reservation_id = uuid::Uuid::new_v4();
    let mut store = audit_store().lock().await;
    store.push(entry_from(reservation_id, actor_principal, session, record));
    // Capacity trimming is deferred until commit. If permit issuance or its
    // currentness check fails, Drop removes only this reservation and cannot
    // accidentally evict an older committed audit entry.
    Ok(LocalAuditReservation {
        store,
        reservation_id,
        evidence: ryuki_engine::authorization::AuditReservationEvidence::local(reservation_id)
            .expect("generated local audit reservation id is non-nil"),
        committed: false,
    })
}

/// Best-effort audit of a DENIED (403) attempt caught at the HANDLER level
/// (e.g. the cancel requester-or-admin SoD check, or a defense-in-depth
/// permission check). Coarse role-tier denials rejected earlier by the central
/// route gate are intentionally NOT recorded here — auditing every gate-level
/// 403 would let an unauthenticated caller flood the trail with writes. Uses
/// the DB when available, otherwise the process-local store. A failure here
/// NEVER changes the caller's 403 outcome — it is logged and swallowed.
pub async fn record_denied(pool: Option<&PgPool>, session: &AuthSession, record: &AuditRecord<'_>) {
    match pool {
        Some(pool) => {
            if let Err(e) = record_audit(pool, session, record).await {
                tracing::warn!(
                    error = %e,
                    action = record.action,
                    actor_principal = ?session.principal_id,
                    "failed to record denied audit entry (best-effort)"
                );
            }
        }
        None => {
            if let Err(e) = record_audit_local(session, record).await {
                tracing::warn!(
                    error = %e,
                    action = record.action,
                    actor_principal = ?session.principal_id,
                    "failed to record denied local audit entry (best-effort)"
                );
            }
        }
    }
}

/// Read the ordered audit trail for a request. DB-backed when available
/// (durable: true); otherwise serves the process-local store (durable: false).
///
/// A DB read error is PROPAGATED (`Err`), never swallowed into an empty trail:
/// this is a compliance-grade read, so an auditor must see a 5xx on a transient
/// DB failure rather than a `200 {entries: []}` that falsely reads as "no audit
/// records". An unparseable `request_id` is NOT an error — it yields an empty
/// trail (the no-oracle unknown-request shape).
pub async fn audit_trail_for_request(
    pool: Option<&PgPool>,
    request_id: &str,
) -> Result<Value, sqlx::Error> {
    if let Some(pool) = pool {
        let request_uuid = match uuid::Uuid::parse_str(request_id) {
            Ok(uuid) => uuid,
            Err(_) => {
                return Ok(json!({
                    "durable": true,
                    "source": "database",
                    "request_id": request_id,
                    "entries": [],
                }));
            }
        };

        let rows = sqlx::query_as::<_, AuditLogRow>(
            "SELECT id, occurred_at, request_id, actor_principal, actor_display, actor_roles, \
                    provider_mode, action, from_stage, to_stage, from_status, to_status, \
                    detail::text AS detail, outcome \
             FROM audit_log WHERE request_id = $1 ORDER BY occurred_at ASC, id ASC",
        )
        .bind(request_uuid)
        .fetch_all(pool)
        .await?;

        let entries: Vec<Value> = rows.iter().map(AuditLogRow::to_json).collect();
        return Ok(json!({
            "durable": true,
            "source": "database",
            "request_id": request_id,
            "entries": entries,
        }));
    }

    let store = audit_store().lock().await;
    let entries: Vec<Value> = store
        .iter()
        .filter(|e| e.request_id.as_deref() == Some(request_id))
        .map(AuditEntry::to_json)
        .collect();
    Ok(json!({
        "durable": false,
        "source": "dry-run",
        "request_id": request_id,
        "entries": entries,
    }))
}

/// The EMPTY trail shape `audit_trail_for_request` returns for a request with no
/// entries (or an unknown id). Used by the scope guard (#2) so an out-of-scope
/// request's trail is byte-indistinguishable from an unknown one — the by-id
/// audit endpoint must not become a cross-scope existence oracle.
pub fn empty_request_trail(pool: Option<&PgPool>, request_id: &str) -> Value {
    let durable = pool.is_some();
    json!({
        "durable": durable,
        "source": if durable { "database" } else { "dry-run" },
        "request_id": request_id,
        "entries": [],
    })
}

/// Read the global, newest-first audit feed across all requests. DB-backed
/// when available (durable: true); otherwise serves the process-local store
/// (durable: false). `limit` is clamped by the caller. Returns the same entry
/// shape as `audit_trail_for_request` plus pagination + total metadata.
pub async fn audit_feed(
    pool: Option<&PgPool>,
    limit: i64,
    offset: i64,
) -> Result<Value, sqlx::Error> {
    if let Some(pool) = pool {
        // Propagate DB errors (never swallow into an empty feed) — a compliance
        // audit read must surface a 5xx on failure, not a false "no records".
        let rows = sqlx::query_as::<_, AuditLogRow>(
            "SELECT id, occurred_at, request_id, actor_principal, actor_display, actor_roles, \
                    provider_mode, action, from_stage, to_stage, from_status, to_status, \
                    detail::text AS detail, outcome \
             FROM audit_log ORDER BY occurred_at DESC, id DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
            .fetch_one(pool)
            .await?;
        let entries: Vec<Value> = rows.iter().map(AuditLogRow::to_json).collect();
        return Ok(json!({
            "durable": true,
            "source": "database",
            "limit": limit,
            "offset": offset,
            "total": total,
            "entries": entries,
        }));
    }

    // No-DB / dry-run mode: serve the process-local store newest-first.
    let store = audit_store().lock().await;
    let total = store.len();
    let entries: Vec<Value> = store
        .iter()
        .rev()
        .skip(offset.max(0) as usize)
        .take(limit.max(0) as usize)
        .map(AuditEntry::to_json)
        .collect();
    Ok(json!({
        "durable": false,
        "source": "dry-run",
        "limit": limit,
        "offset": offset,
        "total": total,
        "entries": entries,
    }))
}

#[derive(sqlx::FromRow)]
struct AuditLogRow {
    id: i64,
    occurred_at: chrono::DateTime<chrono::Utc>,
    request_id: Option<uuid::Uuid>,
    actor_principal: String,
    actor_display: Option<String>,
    actor_roles: Vec<String>,
    provider_mode: String,
    action: String,
    from_stage: Option<String>,
    to_stage: String,
    from_status: Option<String>,
    to_status: String,
    detail: Option<String>,
    outcome: String,
}

impl AuditLogRow {
    fn to_json(&self) -> Value {
        let detail: Value = self
            .detail
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_else(|| json!({}));
        json!({
            "id": self.id,
            "occurred_at": self.occurred_at.to_rfc3339(),
            "request_id": self.request_id.map(|u| u.to_string()),
            "actor_principal": self.actor_principal,
            "actor_display": self.actor_display,
            "actor_roles": self.actor_roles,
            "provider_mode": self.provider_mode,
            "action": self.action,
            "from_stage": self.from_stage,
            "to_stage": self.to_stage,
            "from_status": self.from_status,
            "to_status": self.to_status,
            "detail": redact_detail(&detail),
            "outcome": self.outcome,
        })
    }
}

/// One audit row for SIEM export — like [`AuditLogRow`] plus the chain
/// `entry_hash` so a SIEM can correlate and verify integrity.
#[derive(sqlx::FromRow)]
struct AuditExportRow {
    id: i64,
    occurred_at: chrono::DateTime<chrono::Utc>,
    request_id: Option<uuid::Uuid>,
    actor_principal: String,
    actor_display: Option<String>,
    actor_roles: Vec<String>,
    provider_mode: String,
    action: String,
    from_stage: Option<String>,
    to_stage: String,
    from_status: Option<String>,
    to_status: String,
    detail: Option<String>,
    outcome: String,
    entry_hash: Option<String>,
}

impl AuditExportRow {
    fn to_json(&self) -> Value {
        let detail: Value = self
            .detail
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_else(|| json!({}));
        json!({
            "id": self.id,
            "occurred_at": self.occurred_at.to_rfc3339(),
            "request_id": self.request_id.map(|u| u.to_string()),
            "actor_principal": self.actor_principal,
            "actor_display": self.actor_display,
            "actor_roles": self.actor_roles,
            "provider_mode": self.provider_mode,
            "action": self.action,
            "from_stage": self.from_stage,
            "to_stage": self.to_stage,
            "from_status": self.from_status,
            "to_status": self.to_status,
            // Redacted (same as the feed) — a SIEM export must never carry a
            // secret that slipped into the detail blob.
            "detail": redact_detail(&detail),
            "outcome": self.outcome,
            "entry_hash": self.entry_hash,
        })
    }
}

/// A page of exported audit entries plus the cursor for the next page.
pub struct AuditExport {
    pub entries: Vec<Value>,
    /// Pass as `after_id` to fetch the next page; `None` when nothing was
    /// returned (the caller has reached the end of the available rows).
    pub next_after_id: Option<i64>,
}

/// Export audit entries for SIEM ingestion: FORWARD (ascending id) from
/// `after_id`, optionally bounded to `[since, until]`, up to `limit` rows.
/// Cursor-based on the monotonic BIGSERIAL id so a SIEM pulls incrementally and
/// never sees a DUPLICATE (`id > after_id`).
///
/// CAVEAT — gaps under concurrency: a BIGSERIAL id is allocated at insert time,
/// not commit time, so a long-running transaction that obtained a LOWER id can
/// commit AFTER a higher id the export already advanced past — that lower row is
/// then skipped (a gap, not a duplicate). Audit inserts run inside short
/// request-transition transactions, so this is rare, but for guaranteed
/// completeness a SIEM should periodically RE-EXPORT a CLOSED time window
/// (`since`+`until` both set, comfortably in the past) and reconcile by id; the
/// chain `entry_hash` verify endpoint independently detects any true tampering.
/// Use the `after_id` cursor with a STABLE window (or id-only, no window) — do
/// NOT advance the cursor while changing the window, or rows below the cursor in
/// the new window are missed.
///
/// The detail is redacted; the chain `entry_hash` is included for integrity.
pub async fn export_audit(
    pool: &PgPool,
    since: Option<chrono::DateTime<chrono::Utc>>,
    until: Option<chrono::DateTime<chrono::Utc>>,
    after_id: i64,
    limit: i64,
) -> Result<AuditExport, sqlx::Error> {
    let rows = sqlx::query_as::<_, AuditExportRow>(
        "SELECT id, occurred_at, request_id, actor_principal, actor_display, actor_roles, \
                provider_mode, action, from_stage, to_stage, from_status, to_status, \
                detail::text AS detail, outcome, entry_hash \
         FROM audit_log \
         WHERE id > $1 \
           AND ($2::timestamptz IS NULL OR occurred_at >= $2) \
           AND ($3::timestamptz IS NULL OR occurred_at <= $3) \
         ORDER BY id ASC LIMIT $4",
    )
    .bind(after_id)
    .bind(since)
    .bind(until)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    let next_after_id = rows.last().map(|r| r.id);
    let entries: Vec<Value> = rows.iter().map(AuditExportRow::to_json).collect();
    Ok(AuditExport {
        entries,
        next_after_id,
    })
}

/// Result of re-verifying the audit hash chain.
#[cfg(test)]
pub struct ChainVerification {
    /// True when every chained row's content hash and prev→entry link are intact.
    pub verified: bool,
    /// Number of chained rows checked.
    pub checked: i64,
    /// The id of the first row where the chain diverged (None when verified).
    pub first_divergent_id: Option<i64>,
    /// A human-readable reason for the divergence (None when verified).
    pub reason: Option<String>,
}

#[derive(sqlx::FromRow)]
struct ChainRow {
    id: i64,
    request_id: Option<uuid::Uuid>,
    actor_principal: String,
    actor_display: Option<String>,
    actor_roles: Vec<String>,
    provider_mode: String,
    action: String,
    from_stage: Option<String>,
    to_stage: String,
    from_status: Option<String>,
    to_status: String,
    detail: Option<String>,
    detail_too_large: bool,
    outcome: String,
    prev_hash: Option<String>,
    entry_hash: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChainRowError {
    DetailTooLarge,
    BrokenLink,
    ContentMismatch,
}

fn verify_chain_row(row: &ChainRow, expected_prev: &str) -> Result<String, ChainRowError> {
    if row.detail_too_large {
        return Err(ChainRowError::DetailTooLarge);
    }
    if row.prev_hash.as_deref() != Some(expected_prev) {
        return Err(ChainRowError::BrokenLink);
    }
    let detail: Value = row
        .detail
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_else(|| json!({}));
    let request_id_str = row.request_id.map(|u| u.to_string());
    let payload = audit_canonical_payload(
        request_id_str.as_deref(),
        &row.actor_principal,
        row.actor_display.as_deref().unwrap_or(""),
        &row.actor_roles,
        &row.provider_mode,
        &row.action,
        row.from_stage.as_deref(),
        &row.to_stage,
        row.from_status.as_deref(),
        &row.to_status,
        &detail,
        &row.outcome,
    );
    let recomputed = chain_hash(expected_prev, &payload);
    if row.entry_hash.as_deref() != Some(recomputed.as_str()) {
        return Err(ChainRowError::ContentMismatch);
    }
    Ok(recomputed)
}

/// Re-verify the complete audit hash chain (id order). Recomputes
/// each row's content hash from its stored columns and checks both the content
/// hash and the prev→entry linkage; reports the first divergent row. A clean
/// chain returns `verified: true`. No row is filtered out: an unhashed row is a
/// divergence, never an invisible legacy exception.
#[cfg(test)]
pub async fn verify_audit_chain(pool: &PgPool) -> Result<ChainVerification, sqlx::Error> {
    let rows = sqlx::query_as::<_, ChainRow>(
        "SELECT id, request_id, actor_principal, actor_display, actor_roles, provider_mode, \
                action, from_stage, to_stage, from_status, to_status, detail::text AS detail, \
                FALSE AS detail_too_large, outcome, prev_hash, entry_hash \
         FROM audit_log ORDER BY id ASC",
    )
    .fetch_all(pool)
    .await?;

    let mut expected_prev = AUDIT_CHAIN_GENESIS.to_string();
    let mut checked = 0i64;
    for row in &rows {
        match verify_chain_row(row, &expected_prev) {
            Ok(recomputed) => {
                expected_prev = recomputed;
                checked += 1;
            }
            Err(error) => {
                let reason = match error {
                    ChainRowError::DetailTooLarge => {
                        "audit row exceeds the verification byte limit"
                    }
                    ChainRowError::BrokenLink => {
                        "broken chain link (prev_hash does not match predecessor)"
                    }
                    ChainRowError::ContentMismatch => "content hash mismatch (row was altered)",
                };
                return Ok(ChainVerification {
                    verified: false,
                    checked,
                    first_divergent_id: Some(row.id),
                    reason: Some(reason.into()),
                });
            }
        }
    }

    Ok(ChainVerification {
        verified: true,
        checked,
        first_divergent_id: None,
        reason: None,
    })
}

// ---------------------------------------------------------------------------
// Durable bounded audit-chain verification (migration 173)
// ---------------------------------------------------------------------------

const AUDIT_VERIFICATION_ENQUEUE_LOCK: i64 = 0x4155_4456_4552; // "AUDVER"
                                                               // Keep one page's worst-case decoded detail envelope at 4 MiB. Four pages per
                                                               // worker slice therefore remain at or below 16 MiB before ordinary row fields,
                                                               // while a single oversized detail fails closed without crossing into Rust.
const AUDIT_VERIFICATION_PAGE_ROWS: i64 = 64;
const AUDIT_VERIFICATION_PAGES_PER_SLICE: usize = 4;
const AUDIT_VERIFICATION_MAX_DETAIL_BYTES: i64 = 65_536;
// Leave room for the one active job that may become terminal after enqueue.
// Each enqueue prunes at most one bounded batch beyond this retained window.
const AUDIT_VERIFICATION_MAX_TERMINAL_JOBS: i64 = 1_000;
const AUDIT_VERIFICATION_PRUNE_BATCH: i64 = 128;
const AUDIT_VERIFICATION_LOOP_NAME: &str = "audit_chain_verification";

const _: () = assert!(
    AUDIT_VERIFICATION_PAGE_ROWS * AUDIT_VERIFICATION_MAX_DETAIL_BYTES <= 4 * 1024 * 1024,
    "one page's worst-case decoded detail envelope must stay at or below 4 MiB"
);
const _: () = assert!(
    AUDIT_VERIFICATION_PAGE_ROWS
        * AUDIT_VERIFICATION_MAX_DETAIL_BYTES
        * AUDIT_VERIFICATION_PAGES_PER_SLICE as i64
        <= 16 * 1024 * 1024,
    "one worker slice's detail envelope must stay at or below 16 MiB"
);

const VERIFICATION_JOB_SAFE_COLUMNS: &str =
    "id, status, requested_at, started_at, updated_at, completed_at, \
     snapshot_tail_id, cursor_id, checked, first_divergent_id, reason_code";

/// Safe job state returned to audit-tier callers. Requester identity, chain
/// hashes, and the expected-predecessor checkpoint never cross the API boundary.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditVerificationJob {
    pub id: uuid::Uuid,
    pub status: String,
    pub requested_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub snapshot_tail_id: Option<i64>,
    pub cursor_id: i64,
    pub checked: i64,
    pub first_divergent_id: Option<i64>,
    pub reason_code: Option<String>,
}

impl AuditVerificationJob {
    pub fn is_terminal(&self) -> bool {
        matches!(self.status.as_str(), "verified" | "divergent" | "failed")
    }
}

async fn prune_terminal_verification_jobs(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<u64, sqlx::Error> {
    let retained_before_active = AUDIT_VERIFICATION_MAX_TERMINAL_JOBS.saturating_sub(1);
    let result = sqlx::query(
        "DELETE FROM audit_chain_verification_jobs WHERE id IN ( \
             SELECT id FROM audit_chain_verification_jobs \
             WHERE status IN ('verified', 'divergent', 'failed') \
             ORDER BY completed_at DESC, id DESC \
             OFFSET $1 LIMIT $2 \
         )",
    )
    .bind(retained_before_active)
    .bind(AUDIT_VERIFICATION_PRUNE_BATCH)
    .execute(&mut **tx)
    .await?;
    Ok(result.rows_affected())
}

/// Join the one active verification, return a very recent completed result, or
/// enqueue a new genesis scan. The short advisory lock serializes the decision
/// across replicas; the partial unique index is the authoritative backstop.
/// This function never reads `audit_log`, so the HTTP request is constant-work.
pub async fn enqueue_or_join_audit_verification(
    pool: &PgPool,
    requested_by: &str,
) -> Result<AuditVerificationJob, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(AUDIT_VERIFICATION_ENQUEUE_LOCK)
        .execute(&mut *tx)
        .await?;

    // The job table is itself attacker-reachable through authenticated POSTs.
    // Prune only a fixed batch under the singleton enqueue lock: this bounds
    // request work and converges an older oversized table without a bulk delete.
    prune_terminal_verification_jobs(&mut tx).await?;

    let active: Option<AuditVerificationJob> = sqlx::query_as(&format!(
        "SELECT {VERIFICATION_JOB_SAFE_COLUMNS} \
         FROM audit_chain_verification_jobs \
         WHERE status IN ('queued', 'running') \
         ORDER BY requested_at ASC LIMIT 1"
    ))
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(job) = active {
        tx.commit().await?;
        return Ok(job);
    }

    // A short cooldown prevents repeated authenticated POSTs from scheduling
    // back-to-back full scans while still making result freshness explicit.
    let recent: Option<AuditVerificationJob> = sqlx::query_as(&format!(
        "SELECT {VERIFICATION_JOB_SAFE_COLUMNS} \
         FROM audit_chain_verification_jobs \
         WHERE status IN ('verified', 'divergent', 'failed') \
           AND completed_at >= NOW() - INTERVAL '60 seconds' \
         ORDER BY completed_at DESC, id DESC LIMIT 1"
    ))
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(job) = recent {
        tx.commit().await?;
        return Ok(job);
    }

    let job: AuditVerificationJob = sqlx::query_as(&format!(
        "INSERT INTO audit_chain_verification_jobs (requested_by) VALUES ($1) \
         RETURNING {VERIFICATION_JOB_SAFE_COLUMNS}"
    ))
    .bind(requested_by)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(job)
}

pub async fn audit_verification_status(
    pool: &PgPool,
    id: &str,
) -> Result<Option<AuditVerificationJob>, sqlx::Error> {
    let Ok(id) = uuid::Uuid::parse_str(id) else {
        return Ok(None);
    };
    sqlx::query_as(&format!(
        "SELECT {VERIFICATION_JOB_SAFE_COLUMNS} \
         FROM audit_chain_verification_jobs WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await
}

#[derive(sqlx::FromRow)]
struct VerificationCheckpoint {
    id: uuid::Uuid,
    status: String,
    snapshot_tail_id: Option<i64>,
    snapshot_tail_hash: Option<String>,
    cursor_id: i64,
    expected_prev_hash: String,
    checked: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationPageResult {
    Idle,
    Advanced,
    Terminal,
}

// These arguments deliberately mirror one atomic terminal-checkpoint UPDATE;
// grouping them would obscure which persisted security field each bind owns.
#[allow(clippy::too_many_arguments)]
async fn finish_verification_job(
    tx: &mut Transaction<'_, Postgres>,
    id: uuid::Uuid,
    status: &str,
    cursor_id: i64,
    expected_prev_hash: &str,
    checked: i64,
    first_divergent_id: Option<i64>,
    reason_code: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE audit_chain_verification_jobs SET status = $2, cursor_id = $3, \
         expected_prev_hash = $4, checked = $5, first_divergent_id = $6, \
         reason_code = $7, updated_at = NOW(), completed_at = NOW() WHERE id = $1",
    )
    .bind(id)
    .bind(status)
    .bind(cursor_id)
    .bind(expected_prev_hash)
    .bind(checked)
    .bind(first_divergent_id)
    .bind(reason_code)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Advance at most one 64-row page under the durable singleton row lock. Each
/// successful page commits its checkpoint, so cancellation or replica loss
/// resumes from the last fully verified predecessor on the next tick.
async fn process_audit_verification_page(
    pool: &PgPool,
) -> Result<VerificationPageResult, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let Some(mut job): Option<VerificationCheckpoint> = sqlx::query_as(
        "SELECT id, status, snapshot_tail_id, snapshot_tail_hash, cursor_id, \
                expected_prev_hash, checked \
         FROM audit_chain_verification_jobs \
         WHERE status IN ('queued', 'running') \
         ORDER BY requested_at ASC LIMIT 1 FOR UPDATE SKIP LOCKED",
    )
    .fetch_optional(&mut *tx)
    .await?
    else {
        tx.rollback().await?;
        return Ok(VerificationPageResult::Idle);
    };

    if job.status == "queued" {
        let tail: Option<(i64, Option<String>)> =
            sqlx::query_as("SELECT id, entry_hash FROM audit_log ORDER BY id DESC LIMIT 1")
                .fetch_optional(&mut *tx)
                .await?;
        let Some((tail_id, tail_hash)) = tail else {
            finish_verification_job(
                &mut tx,
                job.id,
                "verified",
                0,
                AUDIT_CHAIN_GENESIS,
                0,
                None,
                None,
            )
            .await?;
            tx.commit().await?;
            return Ok(VerificationPageResult::Terminal);
        };
        let Some(tail_hash) = tail_hash else {
            finish_verification_job(
                &mut tx,
                job.id,
                "divergent",
                0,
                AUDIT_CHAIN_GENESIS,
                0,
                Some(tail_id),
                Some("unhashed_audit_row"),
            )
            .await?;
            tx.commit().await?;
            return Ok(VerificationPageResult::Terminal);
        };
        sqlx::query(
            "UPDATE audit_chain_verification_jobs SET status = 'running', \
             started_at = NOW(), updated_at = NOW(), snapshot_tail_id = $2, \
             snapshot_tail_hash = $3 WHERE id = $1",
        )
        .bind(job.id)
        .bind(tail_id)
        .bind(&tail_hash)
        .execute(&mut *tx)
        .await?;
        job.snapshot_tail_id = Some(tail_id);
        job.snapshot_tail_hash = Some(tail_hash);
    }

    let (Some(tail_id), Some(tail_hash)) =
        (job.snapshot_tail_id, job.snapshot_tail_hash.as_deref())
    else {
        finish_verification_job(
            &mut tx,
            job.id,
            "failed",
            job.cursor_id,
            &job.expected_prev_hash,
            job.checked,
            None,
            Some("invalid_checkpoint"),
        )
        .await?;
        tx.commit().await?;
        return Ok(VerificationPageResult::Terminal);
    };

    let rows: Vec<ChainRow> = sqlx::query_as(
        "SELECT id, request_id, actor_principal, actor_display, actor_roles, provider_mode, \
                action, from_stage, to_stage, from_status, to_status, \
                CASE WHEN octet_length(COALESCE(detail::text, '')) <= $3 \
                     THEN detail::text ELSE NULL END AS detail, \
                octet_length(COALESCE(detail::text, '')) > $3 AS detail_too_large, \
                outcome, prev_hash, entry_hash \
         FROM audit_log WHERE id > $1 AND id <= $2 \
         ORDER BY id ASC LIMIT $4",
    )
    .bind(job.cursor_id)
    .bind(tail_id)
    .bind(AUDIT_VERIFICATION_MAX_DETAIL_BYTES)
    .bind(AUDIT_VERIFICATION_PAGE_ROWS)
    .fetch_all(&mut *tx)
    .await?;

    if rows.is_empty() {
        finish_verification_job(
            &mut tx,
            job.id,
            "failed",
            job.cursor_id,
            &job.expected_prev_hash,
            job.checked,
            None,
            Some("snapshot_tail_missing"),
        )
        .await?;
        tx.commit().await?;
        return Ok(VerificationPageResult::Terminal);
    }

    let mut expected_prev = job.expected_prev_hash;
    let mut cursor_id = job.cursor_id;
    let mut checked = job.checked;
    for row in &rows {
        match verify_chain_row(row, &expected_prev) {
            Ok(recomputed) => {
                expected_prev = recomputed;
                cursor_id = row.id;
                checked = checked.saturating_add(1);
            }
            Err(ChainRowError::DetailTooLarge) => {
                finish_verification_job(
                    &mut tx,
                    job.id,
                    "failed",
                    cursor_id,
                    &expected_prev,
                    checked,
                    Some(row.id),
                    Some("row_size_limit"),
                )
                .await?;
                tx.commit().await?;
                return Ok(VerificationPageResult::Terminal);
            }
            Err(error) => {
                let reason = match error {
                    ChainRowError::BrokenLink => "broken_chain_link",
                    ChainRowError::ContentMismatch => "content_hash_mismatch",
                    ChainRowError::DetailTooLarge => unreachable!(),
                };
                finish_verification_job(
                    &mut tx,
                    job.id,
                    "divergent",
                    cursor_id,
                    &expected_prev,
                    checked,
                    Some(row.id),
                    Some(reason),
                )
                .await?;
                tx.commit().await?;
                return Ok(VerificationPageResult::Terminal);
            }
        }
    }

    if cursor_id == tail_id {
        let (status, reason) = if expected_prev == tail_hash {
            ("verified", None)
        } else {
            ("failed", Some("snapshot_tail_hash_mismatch"))
        };
        finish_verification_job(
            &mut tx,
            job.id,
            status,
            cursor_id,
            &expected_prev,
            checked,
            None,
            reason,
        )
        .await?;
        tx.commit().await?;
        return Ok(VerificationPageResult::Terminal);
    }

    sqlx::query(
        "UPDATE audit_chain_verification_jobs SET cursor_id = $2, \
         expected_prev_hash = $3, checked = $4, updated_at = NOW() WHERE id = $1",
    )
    .bind(job.id)
    .bind(cursor_id)
    .bind(&expected_prev)
    .bind(checked)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(VerificationPageResult::Advanced)
}

pub async fn process_audit_verification_slice(pool: &PgPool) -> Result<usize, sqlx::Error> {
    let mut pages = 0usize;
    while pages < AUDIT_VERIFICATION_PAGES_PER_SLICE {
        match process_audit_verification_page(pool).await? {
            VerificationPageResult::Idle => break,
            VerificationPageResult::Advanced => pages += 1,
            VerificationPageResult::Terminal => {
                pages += 1;
                break;
            }
        }
    }
    Ok(pages)
}

/// Dedicated write-capable worker for durable verification checkpoints. The
/// database singleton row makes duplicate process spawns harmless.
pub fn spawn_audit_verification_worker(pool: PgPool, interval_secs: u64) {
    tokio::spawn(async move {
        crate::background::register_loop(AUDIT_VERIFICATION_LOOP_NAME, interval_secs);
        let mut ticker = interval(Duration::from_secs(interval_secs));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        ticker.tick().await;
        let mut consecutive_failures = 0u32;
        loop {
            ticker.tick().await;
            match crate::background::run_bounded(
                Duration::from_secs(30),
                process_audit_verification_slice(&pool),
            )
            .await
            {
                Ok(_) => {
                    consecutive_failures = 0;
                    crate::background::record_loop_success(AUDIT_VERIFICATION_LOOP_NAME);
                }
                Err(error) => {
                    let backoff = crate::background::note_failure(&mut consecutive_failures);
                    match error {
                        crate::background::IterError::Failed(error) => tracing::error!(
                            error = %error,
                            consecutive_failures,
                            backoff_intervals = backoff,
                            "audit-chain verification worker failed; backing off"
                        ),
                        crate::background::IterError::TimedOut => tracing::error!(
                            consecutive_failures,
                            backoff_intervals = backoff,
                            "audit-chain verification worker timed out; backing off"
                        ),
                    }
                    tokio::time::sleep(Duration::from_secs(interval_secs.saturating_mul(backoff)))
                        .await;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_attribution_rejects_compatibility_identity_without_internal_principal() {
        let session = AuthSession {
            display_user_id: "provider-subject-that-must-not-be-authority".into(),
            ..AuthSession::default()
        };

        let error = required_principal_id(&session).expect_err("principal binding is required");
        assert!(matches!(&error, sqlx::Error::Protocol(_)));
        assert!(!error.to_string().contains(&session.display_user_id));
    }

    #[test]
    fn canonical_json_is_order_independent_and_deterministic() {
        // Same logical content, different key insertion order → same canonical
        // string (so an app-built value and a jsonb round-trip hash identically).
        let a: Value = serde_json::from_str(r#"{"b":1,"a":{"y":2,"x":3},"c":[1,2]}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"c":[1,2],"a":{"x":3,"y":2},"b":1}"#).unwrap();
        assert_eq!(canonical_json(&a), canonical_json(&b));
        assert_eq!(canonical_json(&a), r#"{"a":{"x":3,"y":2},"b":1,"c":[1,2]}"#);
    }

    #[test]
    fn chain_hash_detects_any_change() {
        let base = audit_canonical_payload(
            Some("r1"),
            "alice",
            "Alice",
            &["approve".into()],
            "entra-id",
            "request.approve",
            Some("plan"),
            "approve",
            Some("planned"),
            "approved",
            &json!({"k": "v"}),
            "applied",
        );
        let h = chain_hash("GENESIS", &base);
        assert_eq!(h, chain_hash("GENESIS", &base), "deterministic");
        assert_eq!(h.len(), 64);
        // A different predecessor (reordering) changes the hash.
        assert_ne!(h, chain_hash("other-prev", &base));
        // A changed content field (the outcome) changes the hash.
        let tampered = audit_canonical_payload(
            Some("r1"),
            "alice",
            "Alice",
            &["approve".into()],
            "entra-id",
            "request.approve",
            Some("plan"),
            "approve",
            Some("planned"),
            "approved",
            &json!({"k": "v"}),
            "denied",
        );
        assert_ne!(h, chain_hash("GENESIS", &tampered));
        // A length-boundary collision is prevented by length-prefixing.
        assert_ne!(chain_hash("ab", "c"), chain_hash("a", "bc"));
    }

    fn clean_chain_row(id: i64, prev_hash: &str) -> ChainRow {
        let detail = json!({"page": id});
        let payload = audit_canonical_payload(
            None,
            "audit-test",
            "Audit Test",
            &["Auditor".into()],
            "local",
            "audit.verify.test",
            None,
            "verify",
            None,
            "recorded",
            &detail,
            "applied",
        );
        ChainRow {
            id,
            request_id: None,
            actor_principal: "audit-test".into(),
            actor_display: Some("Audit Test".into()),
            actor_roles: vec!["Auditor".into()],
            provider_mode: "local".into(),
            action: "audit.verify.test".into(),
            from_stage: None,
            to_stage: "verify".into(),
            from_status: None,
            to_status: "recorded".into(),
            detail: Some(detail.to_string()),
            detail_too_large: false,
            outcome: "applied".into(),
            prev_hash: Some(prev_hash.into()),
            entry_hash: Some(chain_hash(prev_hash, &payload)),
        }
    }

    #[test]
    fn bounded_chain_pages_preserve_predecessor_and_fail_closed() {
        assert_eq!(AUDIT_VERIFICATION_PAGE_ROWS, 64);
        assert_eq!(AUDIT_VERIFICATION_PAGES_PER_SLICE, 4);
        assert_eq!(AUDIT_VERIFICATION_MAX_DETAIL_BYTES, 65_536);

        let first = clean_chain_row(1, AUDIT_CHAIN_GENESIS);
        let first_hash = verify_chain_row(&first, AUDIT_CHAIN_GENESIS).expect("first row");
        let second = clean_chain_row(2, &first_hash);
        assert!(verify_chain_row(&second, &first_hash).is_ok());

        // The first row of a later page still requires the prior page's exact
        // checkpoint hash; a reset-to-genesis bypass is rejected.
        assert_eq!(
            verify_chain_row(&second, AUDIT_CHAIN_GENESIS),
            Err(ChainRowError::BrokenLink)
        );

        let mut altered = second;
        altered.outcome = "denied".into();
        assert_eq!(
            verify_chain_row(&altered, &first_hash),
            Err(ChainRowError::ContentMismatch)
        );

        let mut oversized = clean_chain_row(3, &first_hash);
        oversized.detail = None;
        oversized.detail_too_large = true;
        assert_eq!(
            verify_chain_row(&oversized, &first_hash),
            Err(ChainRowError::DetailTooLarge)
        );
    }

    #[test]
    fn redact_detail_scrubs_secret_bearing_values() {
        let detail = json!({
            "reason": "rotate password: hunter2 before lock",
            "note": "ordinary handover text",
            "nested": {"api_key": "abc123", "ok": "fine"},
        });
        let redacted = redact_detail(&detail);
        // Value pattern (`password:`) redacts a free-text reason.
        assert_eq!(redacted["reason"], "***REDACTED***");
        // Ordinary text is preserved verbatim.
        assert_eq!(redacted["note"], "ordinary handover text");
        // Key-name match (`api_key` contains `key`) redacts regardless of value,
        // recursing into nested objects; sibling non-secret values are kept.
        assert_eq!(redacted["nested"]["api_key"], "***REDACTED***");
        assert_eq!(redacted["nested"]["ok"], "fine");
    }

    #[test]
    fn redact_detail_scrubs_structured_cookie_header_aggregates() {
        let named_marker = "SYNTH-AUDIT-NAMED-COOKIE-CANARY";
        let tuple_marker = "SYNTH-AUDIT-TUPLE-COOKIE-CANARY";
        let detail = json!({
            "transport": {
                "headers": [
                    {
                        "name": "Cookie",
                        "value": format!("session={named_marker}")
                    },
                    [
                        "Set-Cookie",
                        format!("session={tuple_marker}"),
                        {"sensitive": true}
                    ]
                ]
            },
            "note": "ordinary handover text"
        });

        let redacted = redact_detail(&detail);
        let serialized = serde_json::to_string(&redacted).unwrap();
        assert!(!serialized.contains(named_marker));
        assert!(!serialized.contains(tuple_marker));
        assert_eq!(redacted["note"], "ordinary handover text");
    }

    #[test]
    fn redact_detail_scrubs_structured_authorization_header_aggregates() {
        let named_marker = "SYNTH-AUDIT-NAMED-BASIC-CANARY";
        let tuple_marker = "SYNTH-AUDIT-TUPLE-BASIC-CANARY";
        let detail = json!({
            "transport": {
                "headers": [
                    {
                        "header_name": "Authorization",
                        "header_values": [format!("Basic {named_marker}")]
                    },
                    [
                        "authorization",
                        format!("Basic {tuple_marker}")
                    ]
                ]
            },
            "note": "ordinary handover text"
        });

        let redacted = redact_detail(&detail);
        let serialized = serde_json::to_string(&redacted).unwrap();
        assert!(!serialized.contains(named_marker));
        assert!(!serialized.contains(tuple_marker));
        assert_eq!(redacted["transport"]["headers"][0], "***REDACTED***");
        assert_eq!(redacted["transport"]["headers"][1], "***REDACTED***");
        assert_eq!(redacted["note"], "ordinary handover text");
    }

    #[test]
    fn audit_entry_to_json_redacts_detail_reason() {
        let entry = AuditEntry {
            reservation_id: uuid::Uuid::new_v4(),
            occurred_at: "t".into(),
            request_id: Some("r".into()),
            actor_principal: "approver".into(),
            actor_display: "Approver".into(),
            actor_roles: vec!["DatacenterApprover".into()],
            provider_mode: "local".into(),
            action: "request.reject".into(),
            from_stage: Some("plan".into()),
            to_stage: "approve".into(),
            from_status: Some("planned".into()),
            to_status: "rejected".into(),
            detail: json!({"reason": "blocked — secret: topsecret leaked"}),
            outcome: "applied".into(),
        };
        let value = entry.to_json();
        assert_eq!(value["detail"]["reason"], "***REDACTED***");
        // Non-detail attribution is untouched.
        assert_eq!(value["actor_display"], "Approver");
    }
}

// ---------------------------------------------------------------------------
// DB-gated: the insert→verify round trip must agree (this catches any field
// canonicalization mismatch between record_audit_tx and verify_audit_chain).
// SKIPS when RYUKI_DATABASE_URL is unset.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod audit_chain_db_tests {
    use super::*;
    use crate::database::DB_TEST_SERIAL;

    fn new_test_principal() -> PrincipalId {
        PrincipalId::from_uuid(uuid::Uuid::new_v4()).expect("non-nil test principal")
    }

    async fn global_pool() -> Option<&'static PgPool> {
        let url = std::env::var("RYUKI_DATABASE_URL").ok()?;
        crate::database::try_connect_with_url(&url, 5, 1, 300, 30, 1800).await;
        let pool = crate::database::get_db()
            .expect("RYUKI_DATABASE_URL is set but the DB connection failed");
        let _ = crate::database::run_migrations(pool).await;
        Some(pool)
    }

    #[tokio::test]
    async fn record_then_verify_round_trips_clean() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        sqlx::query("DELETE FROM audit_chain_verification_jobs")
            .execute(pool)
            .await
            .expect("reset verification jobs");

        // Authenticated enqueue calls cannot grow the durable job history
        // forever. Seed beyond the retention window, then prove one enqueue
        // performs only the bounded overflow prune and leaves room for the
        // active job to become the 1,000th terminal result.
        sqlx::query(
            "INSERT INTO audit_chain_verification_jobs \
                 (status, requested_by, completed_at) \
             SELECT 'verified', 'retention-fixture', \
                    NOW() - INTERVAL '2 minutes' - (n * INTERVAL '1 second') \
             FROM generate_series(1, $1::bigint) AS n",
        )
        .bind(AUDIT_VERIFICATION_MAX_TERMINAL_JOBS + 5)
        .execute(pool)
        .await
        .expect("seed terminal verification history");
        let retention_job = enqueue_or_join_audit_verification(pool, "retention-auditor")
            .await
            .expect("enqueue after bounded retention prune");
        assert_eq!(retention_job.status, "queued");
        let retained_terminal: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_chain_verification_jobs \
             WHERE status IN ('verified', 'divergent', 'failed')",
        )
        .fetch_one(pool)
        .await
        .expect("count retained terminal jobs");
        assert_eq!(retained_terminal, AUDIT_VERIFICATION_MAX_TERMINAL_JOBS - 1);
        sqlx::query("DELETE FROM audit_chain_verification_jobs")
            .execute(pool)
            .await
            .expect("clear retention fixture");

        // Enqueue is constant-work and must not wait on the audit table itself.
        // Holding an exclusive audit_log lock proves the request path touches
        // only the small verification-job table.
        let mut lock_tx = pool.begin().await.expect("lock transaction");
        sqlx::query("LOCK TABLE audit_log IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *lock_tx)
            .await
            .expect("lock audit log");
        let enqueued_while_locked = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            enqueue_or_join_audit_verification(pool, "lock-proof-auditor"),
        )
        .await
        .expect("enqueue must not wait on audit_log")
        .expect("enqueue while audit_log is locked");
        assert_eq!(enqueued_while_locked.status, "queued");
        lock_tx.rollback().await.expect("release audit log lock");
        sqlx::query("DELETE FROM audit_chain_verification_jobs")
            .execute(pool)
            .await
            .expect("clear lock proof job");

        let actor_principal = new_test_principal();
        let mut session = AuthSession::static_dry_run();
        session.display_user_id = "audit-chain-tester".into();
        session.principal_id = Some(actor_principal);
        session.provider_mode = "entra-id".into();
        session.roles = vec!["approver".into(), "request".into()];

        // Append a few chained rows with varied content (incl. a nested detail,
        // which exercises the jsonb-canonicalization round trip).
        for (i, detail) in [
            json!({"reason": "first", "nested": {"b": 2, "a": 1}}),
            json!({}),
            json!({"note": "third", "list": [1, 2, 3]}),
            // Numeric forms that jsonb might normalize (float, integer, exponent,
            // large decimal) — the round trip must still verify, proving the
            // canonicalization survives jsonb numeric representation.
            json!({"f": 1.0, "i": 1, "exp": 1e3, "big": 1234567890.5, "neg": -2.50}),
        ]
        .into_iter()
        .enumerate()
        {
            record_audit(
                pool,
                &session,
                &AuditRecord {
                    action: "request.approve",
                    request_id: None,
                    from_status: Some("planned"),
                    to_status: "approved",
                    from_stage: Some("plan"),
                    to_stage: "approve",
                    detail,
                    outcome: if i == 1 { "denied" } else { "applied" },
                },
            )
            .await
            .expect("record audit");
        }

        let (complete_domain_rows, excluded_rows): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COUNT(*) FILTER ( \
                 WHERE id <= 0 OR prev_hash IS NULL OR entry_hash IS NULL \
             ) FROM audit_log",
        )
        .fetch_one(pool)
        .await
        .expect("inspect complete audit domain");
        assert_eq!(
            excluded_rows, 0,
            "positive ids and non-null hashes are mandatory for every audit row"
        );

        // Concurrent callers converge on the same durable singleton job.
        let (first, joined) = tokio::join!(
            enqueue_or_join_audit_verification(pool, "auditor-one"),
            enqueue_or_join_audit_verification(pool, "auditor-two")
        );
        let first = first.expect("enqueue first verifier");
        let joined = joined.expect("join verifier");
        assert_eq!(first.id, joined.id);
        assert_eq!(first.status, "queued");

        // One worker transaction advances no more than the fixed page size.
        let first_page = process_audit_verification_page(pool)
            .await
            .expect("first bounded page");
        assert_ne!(first_page, VerificationPageResult::Idle);
        let after_first = audit_verification_status(pool, &first.id.to_string())
            .await
            .expect("status after first page")
            .expect("job exists");
        assert!(after_first.checked <= AUDIT_VERIFICATION_PAGE_ROWS);

        // Continue bounded slices until the captured tail is terminal. Each
        // slice is independently capped at four pages/1,000 rows.
        let mut terminal = after_first;
        for _ in 0..1000 {
            if terminal.is_terminal() {
                break;
            }
            let pages = process_audit_verification_slice(pool)
                .await
                .expect("bounded verification slice");
            assert!(pages <= AUDIT_VERIFICATION_PAGES_PER_SLICE);
            terminal = audit_verification_status(pool, &first.id.to_string())
                .await
                .expect("verification status")
                .expect("job exists");
        }
        assert_eq!(terminal.status, "verified", "terminal job: {terminal:?}");
        assert!(terminal.is_terminal());
        assert!(terminal.completed_at.is_some());
        assert_eq!(
            terminal.checked, complete_domain_rows,
            "verification must include every row in the canonical audit domain"
        );
    }

    #[tokio::test]
    async fn export_audit_paginates_by_cursor() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // audit_log is append-only (DELETE raises), so use a UNIQUE actor per run
        // — our rows are then the newest and isolated, no cleanup needed.
        let actor_principal = new_test_principal();
        let actor = actor_principal.to_string();

        let mut session = AuthSession::static_dry_run();
        session.display_user_id = format!("audit-export-{}", uuid::Uuid::new_v4());
        session.principal_id = Some(actor_principal);
        session.provider_mode = "entra-id".into();
        session.roles = vec!["approver".into()];
        for i in 0..3 {
            record_audit(
                pool,
                &session,
                &AuditRecord {
                    action: "request.approve",
                    request_id: None,
                    from_status: Some("planned"),
                    to_status: "approved",
                    from_stage: Some("plan"),
                    to_stage: "approve",
                    detail: json!({ "n": i }),
                    outcome: "applied",
                },
            )
            .await
            .expect("record");
        }

        // Our three rows are the newest (serial lock), so a cursor just below our
        // MIN(id) yields exactly them in order.
        let min_id: i64 =
            sqlx::query_scalar("SELECT MIN(id) FROM audit_log WHERE actor_principal = $1")
                .bind(&actor)
                .fetch_one(pool)
                .await
                .unwrap();
        let start = min_id - 1;

        // Page 1: 2 of 3, with a forward cursor + chained entry_hash present.
        let p1 = export_audit(pool, None, None, start, 2).await.expect("p1");
        assert_eq!(p1.entries.len(), 2, "first page is limit-bounded");
        assert!(
            p1.entries
                .iter()
                .all(|e| e["actor_principal"] == actor.as_str()),
            "only our rows are in this id window"
        );
        assert!(
            p1.entries.iter().all(|e| e["entry_hash"].is_string()),
            "chained rows carry an entry_hash for integrity"
        );
        let cursor = p1.next_after_id.expect("a next cursor");

        // Page 2: the remaining row, then the cursor is exhausted.
        let p2 = export_audit(pool, None, None, cursor, 2).await.expect("p2");
        assert_eq!(p2.entries.len(), 1, "second page has the last row");
        let end = p2.next_after_id.expect("cursor");
        let p3 = export_audit(pool, None, None, end, 2).await.expect("p3");
        assert!(
            p3.entries.is_empty() && p3.next_after_id.is_none(),
            "exhausted"
        );

        // A time window in the far past returns nothing.
        let past = chrono::DateTime::parse_from_rfc3339("2000-01-01T00:00:00+00:00")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let windowed = export_audit(pool, None, Some(past), start, 100)
            .await
            .expect("windowed");
        assert!(windowed.entries.is_empty(), "no rows before 2000");
    }
}
