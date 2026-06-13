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
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::OnceLock;
use tokio::sync::Mutex;

use ryuki_engine::auth::AuthSession;

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
            "detail": self.detail,
            "outcome": self.outcome,
        })
    }
}

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

    sqlx::query(
        "INSERT INTO audit_log \
            (request_id, actor_principal, actor_display, actor_roles, provider_mode, \
             action, from_stage, to_stage, from_status, to_status, detail, outcome) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12)",
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
    audit_store().lock().await.push(entry_from(session, record));
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
            "detail": detail,
            "outcome": self.outcome,
        })
    }
}
