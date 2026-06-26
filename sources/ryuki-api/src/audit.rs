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
use tokio::sync::Mutex;

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
// LOCK ORDER: record_audit_tx takes AUDIT_CHAIN_LOCK_KEY only AFTER any
// `UPDATE requests` row lock its caller already holds (request row → audit lock,
// always), so concurrent transitions cannot deadlock on the two.
// ---------------------------------------------------------------------------

/// Predecessor hash of the first row in the chain.
const AUDIT_CHAIN_GENESIS: &str = "GENESIS";

/// Key for the Postgres transaction-scoped advisory lock that serializes chain
/// appends, so two concurrent inserts cannot read the same predecessor and fork
/// the chain. Released automatically on commit/rollback.
const AUDIT_CHAIN_LOCK_KEY: i64 = 0x4155_4449_5400; // "AUDIT\0"

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

/// `sha256(len(prev_hash)‖prev_hash‖len(payload)‖payload)`, lowercase hex. The
/// length prefixes make the encoding unambiguous (no value can forge a field
/// boundary). Pure + deterministic.
fn chain_hash(prev_hash: &str, payload: &str) -> String {
    let mut h = Sha256::new();
    h.update((prev_hash.len() as u64).to_le_bytes());
    h.update(prev_hash.as_bytes());
    h.update((payload.len() as u64).to_le_bytes());
    h.update(payload.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Process-local audit entry used only in no-DB (dry-run) mode. The durable
/// trail lives in the `audit_log` table; this mirrors it for demo output and
/// is explicitly tagged non-durable when served.
#[derive(Debug, Clone)]
pub struct AuditEntry {
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
/// The stored trail is append-only and keeps the real verbatim attribution, but
/// every READ path (`/api/requests/{id}/audit`, `/api/activity/audit`, and the
/// evidence pack that embeds the trail) must never surface a secret a user typed
/// into free-text — e.g. a credential pasted into a reject/cancel reason. Reuses
/// the engine's pure pattern logic so this stays consistent with the evidence
/// pipeline's redaction.
fn redact_detail(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut redacted = serde_json::Map::with_capacity(map.len());
            for (key, child) in map {
                match child {
                    Value::String(text)
                        if ryuki_engine::evidence_pipeline::should_redact(key, text) =>
                    {
                        redacted.insert(key.clone(), Value::String("***REDACTED***".to_string()));
                    }
                    other => {
                        redacted.insert(key.clone(), redact_detail(other));
                    }
                }
            }
            Value::Object(redacted)
        }
        Value::Array(items) => Value::Array(items.iter().map(redact_detail).collect()),
        other => other.clone(),
    }
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

fn entry_from(session: &AuthSession, record: &AuditRecord<'_>) -> AuditEntry {
    AuditEntry {
        occurred_at: chrono::Utc::now().to_rfc3339(),
        request_id: record.request_id.map(str::to_string),
        actor_principal: session.user_id.clone(),
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

/// Insert one audit row inside an EXISTING transaction. The transition's
/// `UPDATE requests` and this INSERT commit atomically, so a row can never
/// transition without its audit entry. Actor attribution is read from
/// `session` only.
pub async fn record_audit_tx(
    tx: &mut Transaction<'_, Postgres>,
    session: &AuthSession,
    record: &AuditRecord<'_>,
) -> Result<(), sqlx::Error> {
    let request_uuid = record
        .request_id
        .and_then(|id| uuid::Uuid::parse_str(id).ok());

    // Serialize chain appends: hold a transaction-scoped advisory lock while we
    // read the predecessor's hash and insert, so two concurrent transitions
    // cannot both chain off the same predecessor and fork the chain.
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(AUDIT_CHAIN_LOCK_KEY)
        .execute(&mut **tx)
        .await?;
    let prev_hash: String = sqlx::query_scalar(
        "SELECT entry_hash FROM audit_log WHERE entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1",
    )
    .fetch_optional(&mut **tx)
    .await?
    .unwrap_or_else(|| AUDIT_CHAIN_GENESIS.to_string());

    let request_id_str = request_uuid.map(|u| u.to_string());
    let payload = audit_canonical_payload(
        request_id_str.as_deref(),
        &session.user_id,
        &session.display_name,
        &session.roles,
        &session.provider_mode,
        record.action,
        record.from_stage,
        record.to_stage,
        record.from_status,
        record.to_status,
        &record.detail,
        record.outcome,
    );
    let entry_hash = chain_hash(&prev_hash, &payload);

    sqlx::query(
        "INSERT INTO audit_log \
            (request_id, actor_principal, actor_display, actor_roles, provider_mode, \
             action, from_stage, to_stage, from_status, to_status, detail, outcome, \
             prev_hash, entry_hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12, $13, $14)",
    )
    .bind(request_uuid)
    .bind(&session.user_id)
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
    .bind(&prev_hash)
    .bind(&entry_hash)
    .execute(&mut **tx)
    .await?;

    Ok(())
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
    record_audit_tx(&mut tx, session, record).await?;
    tx.commit().await?;
    Ok(())
}

/// Append to the process-local audit store (no-DB / dry-run mode). Tagged
/// non-durable when served so demo output is never mistaken for a real trail.
pub async fn record_audit_local(session: &AuthSession, record: &AuditRecord<'_>) {
    let mut store = audit_store().lock().await;
    store.push(entry_from(session, record));
    // Keep only the most recent MAX_LOCAL_AUDIT entries (bounded ring window).
    if store.len() > MAX_LOCAL_AUDIT {
        let excess = store.len() - MAX_LOCAL_AUDIT;
        store.drain(0..excess);
    }
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
                    actor = %session.user_id,
                    "failed to record denied audit entry (best-effort)"
                );
            }
        }
        None => record_audit_local(session, record).await,
    }
}

/// Read the ordered audit trail for a request. DB-backed when available
/// (durable: true); otherwise serves the process-local store (durable: false).
pub async fn audit_trail_for_request(pool: Option<&PgPool>, request_id: &str) -> Value {
    if let Some(pool) = pool {
        let request_uuid = match uuid::Uuid::parse_str(request_id) {
            Ok(uuid) => uuid,
            Err(_) => {
                return json!({
                    "durable": true,
                    "source": "database",
                    "request_id": request_id,
                    "entries": [],
                });
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
        .await
        .unwrap_or_default();

        let entries: Vec<Value> = rows.iter().map(AuditLogRow::to_json).collect();
        return json!({
            "durable": true,
            "source": "database",
            "request_id": request_id,
            "entries": entries,
        });
    }

    let store = audit_store().lock().await;
    let entries: Vec<Value> = store
        .iter()
        .filter(|e| e.request_id.as_deref() == Some(request_id))
        .map(AuditEntry::to_json)
        .collect();
    json!({
        "durable": false,
        "source": "dry-run",
        "request_id": request_id,
        "entries": entries,
    })
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
pub async fn audit_feed(pool: Option<&PgPool>, limit: i64, offset: i64) -> Value {
    if let Some(pool) = pool {
        let rows = sqlx::query_as::<_, AuditLogRow>(
            "SELECT id, occurred_at, request_id, actor_principal, actor_display, actor_roles, \
                    provider_mode, action, from_stage, to_stage, from_status, to_status, \
                    detail::text AS detail, outcome \
             FROM audit_log ORDER BY occurred_at DESC, id DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
        .unwrap_or_default();
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
            .fetch_one(pool)
            .await
            .unwrap_or(0);
        let entries: Vec<Value> = rows.iter().map(AuditLogRow::to_json).collect();
        return json!({
            "durable": true,
            "source": "database",
            "limit": limit,
            "offset": offset,
            "total": total,
            "entries": entries,
        });
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
    json!({
        "durable": false,
        "source": "dry-run",
        "limit": limit,
        "offset": offset,
        "total": total,
        "entries": entries,
    })
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
    outcome: String,
    prev_hash: Option<String>,
    entry_hash: Option<String>,
}

/// Re-verify the audit hash chain over all chained rows (id order). Recomputes
/// each row's content hash from its stored columns and checks both the content
/// hash and the prev→entry linkage; reports the first divergent row. A clean
/// chain returns `verified: true`. Rows written before migration 094 (NULL
/// entry_hash) are not part of the chain and are skipped.
pub async fn verify_audit_chain(pool: &PgPool) -> Result<ChainVerification, sqlx::Error> {
    let rows = sqlx::query_as::<_, ChainRow>(
        "SELECT id, request_id, actor_principal, actor_display, actor_roles, provider_mode, \
                action, from_stage, to_stage, from_status, to_status, detail::text AS detail, \
                outcome, prev_hash, entry_hash \
         FROM audit_log WHERE entry_hash IS NOT NULL ORDER BY id ASC",
    )
    .fetch_all(pool)
    .await?;

    let mut expected_prev = AUDIT_CHAIN_GENESIS.to_string();
    let mut checked = 0i64;
    for row in &rows {
        // Linkage: this row must chain off the predecessor's entry_hash.
        if row.prev_hash.as_deref() != Some(expected_prev.as_str()) {
            return Ok(ChainVerification {
                verified: false,
                checked,
                first_divergent_id: Some(row.id),
                reason: Some("broken chain link (prev_hash does not match predecessor)".into()),
            });
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
        let recomputed = chain_hash(&expected_prev, &payload);
        if row.entry_hash.as_deref() != Some(recomputed.as_str()) {
            return Ok(ChainVerification {
                verified: false,
                checked,
                first_divergent_id: Some(row.id),
                reason: Some("content hash mismatch (row was altered)".into()),
            });
        }
        expected_prev = recomputed;
        checked += 1;
    }

    Ok(ChainVerification {
        verified: true,
        checked,
        first_divergent_id: None,
        reason: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn audit_entry_to_json_redacts_detail_reason() {
        let entry = AuditEntry {
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
        let mut session = AuthSession::static_dry_run();
        session.user_id = "audit-chain-tester".into();
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

        // The whole chain (these rows plus any from earlier transitions) verifies.
        let result = verify_audit_chain(pool).await.expect("verify");
        assert!(
            result.verified,
            "clean chain must verify; first divergence at {:?}: {:?}",
            result.first_divergent_id, result.reason
        );
        assert!(
            result.checked >= 3,
            "at least the three rows just appended are chained (checked={})",
            result.checked
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
        let actor = format!("audit-export-{}", uuid::Uuid::new_v4());
        let actor = actor.as_str();

        let mut session = AuthSession::static_dry_run();
        session.user_id = actor.into();
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
                .bind(actor)
                .fetch_one(pool)
                .await
                .unwrap();
        let start = min_id - 1;

        // Page 1: 2 of 3, with a forward cursor + chained entry_hash present.
        let p1 = export_audit(pool, None, None, start, 2).await.expect("p1");
        assert_eq!(p1.entries.len(), 2, "first page is limit-bounded");
        assert!(
            p1.entries.iter().all(|e| e["actor_principal"] == actor),
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
