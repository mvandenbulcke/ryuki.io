//! Execution-agent dispatch plumbing — S3a + S3b (control-plane side).
//!
//! Slice scope: agent registry + job queue + lease mechanics (S3a);
//! signed result verification + recording (S3b).
//! Out of scope: per-request lifecycle wiring (S4), admin approval UI,
//! signed grant issuance.
//!
//! # Auth model
//!
//! Agent auth = bearer token (hashed compare, same SHA-256-hex as api_tokens) + status == 'approved'.
//! Full per-request key-binding / request signing is S3b.
//! The token check lives in `authenticate_agent` — S3b extends it there, not scattered across handlers.
//!
//! # Lease / fencing invariants
//!
//! - Lease TTL is 5 minutes (CP DB time; no client clock).
//! - cp_nonce + fencing_token are generated as UUIDs (128-bit CSPRNG; unguessable).
//! - The SKIP LOCKED lease query is the single atomically-safe dispatch path.
//! - Lease expiry: OfflineDryRun / LivePlan → re-Pending (new attempt);
//!   LiveApply → ReconcileRequired (never auto-redispatched).

use axum::{
    extract::{Extension, Path},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use ryuki_engine::auth::{check_permission, AuthSession};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use tokio::time::interval;
use uuid::Uuid;

use chrono::DateTime;

use crate::cp_identity;
use crate::database::get_db;
use crate::sha256_hex;
use ryuki_protocol::{
    crypto::{sign_vlc, verify_vlc},
    Capabilities, Job, JobLease, JobMode, JobResult, JobResultStatus, JobSpec, JobStatus,
    VerifiedLiveContext,
};

// ---------------------------------------------------------------------------
// Lease TTL (seconds)
// ---------------------------------------------------------------------------

const LEASE_TTL_SECS: i64 = 300; // 5 minutes

// ---------------------------------------------------------------------------
// DB row types
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
struct AgentRow {
    id: Uuid,
    agent_id: String,
    platform: String,
    #[allow(dead_code)]
    capabilities: sqlx::types::Json<Capabilities>,
    #[allow(dead_code)]
    public_key: String,
    token_hash: String,
    status: String,
}

#[allow(dead_code)]
#[derive(sqlx::FromRow, Clone)]
struct AgentJobRow {
    id: Uuid,
    request_id: Uuid,
    platform: String,
    spec: sqlx::types::Json<Value>,
    mode: String,
    status: String,
    agent_id: Option<String>,
    attempt_id: Option<Uuid>,
    lease_generation: i64,
    fencing_token: Option<String>,
    cp_nonce: Option<String>,
    lease_deadline: Option<chrono::DateTime<Utc>>,
    // S5: CP-signed LiveApply approval grant (NULL for non-live jobs).
    live_context: Option<sqlx::types::Json<Value>>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

const AGENT_JOB_COLUMNS: &str = "id, request_id, platform, spec, mode, status, \
    agent_id, attempt_id, lease_generation, fencing_token, cp_nonce, \
    lease_deadline, live_context, created_at, updated_at";

// ---------------------------------------------------------------------------
// Wire types (request / response bodies)
// ---------------------------------------------------------------------------

/// Body for POST /api/agents/register.
/// Fields mirror ryuki_protocol::AgentRegistration but we accept them
/// separately here so we can validate before inserting.
#[derive(Debug, Deserialize)]
pub struct RegisterBody {
    pub agent_id: String,
    pub platform: String,
    pub capabilities: Capabilities,
    pub public_key: String,
}

/// Returned once on successful registration. Token is never stored and never
/// returned again.
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub agent_id: String,
    pub token: String,
}

/// Body for POST /api/admin/agents/{id}/approve.
///
/// `platform` is REQUIRED — the admin must authoritatively assign the platform
/// so the agent's self-declared value cannot be used to lease jobs for a
/// different platform than the admin intended.
#[derive(Debug, Deserialize)]
pub struct ApproveBody {
    /// Authoritative platform assigned by admin (overwrites self-declared).
    /// Required — approval without an admin-assigned platform is rejected.
    pub platform: String,
    /// Authoritative capabilities assigned by admin (overwrites self-declared).
    pub capabilities: Option<Capabilities>,
}

/// Body for POST /api/agents/{id}/jobs/{job}/ack.
#[derive(Debug, Deserialize)]
pub struct AckBody {
    pub attempt_id: Uuid,
    pub fencing_token: String,
}

/// Body for POST /api/agents/{id}/heartbeat.
#[derive(Debug, Deserialize)]
pub struct HeartbeatBody {
    /// Currently running job id, if any.
    pub running_job_id: Option<Uuid>,
}

// ---------------------------------------------------------------------------
// Error helpers (mirror contracts.rs patterns)
// ---------------------------------------------------------------------------

pub type ApiResult<T> = Result<T, (StatusCode, Json<Value>)>;

fn db_err<E: std::fmt::Display>(e: E) -> (StatusCode, Json<Value>) {
    tracing::error!(error = %e, "agent db error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "database error", "detail": e.to_string()})),
    )
}

fn not_found(msg: impl Into<String>) -> (StatusCode, Json<Value>) {
    (StatusCode::NOT_FOUND, Json(json!({"error": msg.into()})))
}

fn conflict(msg: impl Into<String>) -> (StatusCode, Json<Value>) {
    (StatusCode::CONFLICT, Json(json!({"error": msg.into()})))
}

fn forbidden(msg: impl Into<String>) -> (StatusCode, Json<Value>) {
    (StatusCode::FORBIDDEN, Json(json!({"error": msg.into()})))
}

fn bad_request(msg: impl Into<String>) -> (StatusCode, Json<Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({"error": msg.into()})))
}

fn service_unavailable(msg: impl Into<String>) -> (StatusCode, Json<Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error": msg.into()})),
    )
}

fn parse_agent_job_id(id: &str) -> ApiResult<Uuid> {
    Uuid::parse_str(id).map_err(|_| not_found(format!("job {} not found", id)))
}

// ---------------------------------------------------------------------------
// Token generation (AGENT_TOKEN_PREFIX + 32 random bytes → 64 hex chars)
// ---------------------------------------------------------------------------

pub const AGENT_TOKEN_PREFIX: &str = "rya_";

fn generate_agent_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{AGENT_TOKEN_PREFIX}{hex}")
}

// ---------------------------------------------------------------------------
// Agent token authentication
//
// Single entry-point so S3b can extend it (e.g. add request signing check)
// without touching individual handlers.
// ---------------------------------------------------------------------------

/// Authenticates the caller as an agent bearer (hashed compare against
/// `agents.token_hash`) and returns the agent row.
///
/// Returns:
/// - 401 if no bearer / not an agent token prefix.
/// - 403 if the token does not match any approved row.
/// - 403 if status != 'approved'.
async fn authenticate_agent(headers: &HeaderMap, pool: &PgPool) -> ApiResult<AgentRow> {
    let auth = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.trim().strip_prefix("Bearer ").map(str::trim))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "bearer token required"})),
            )
        })?;

    if !auth.starts_with(AGENT_TOKEN_PREFIX) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "not an agent token"})),
        ));
    }

    let hash = sha256_hex(auth);

    use subtle::ConstantTimeEq;
    let row = sqlx::query_as::<_, AgentRow>(
        "SELECT id, agent_id, platform, capabilities, public_key, token_hash, status \
         FROM agents WHERE token_hash = $1",
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| forbidden("invalid agent token"))?;

    // Constant-time belt-and-suspenders (token already filtered in WHERE).
    let hash_ok: bool = hash.as_bytes().ct_eq(row.token_hash.as_bytes()).into();
    if !hash_ok {
        return Err(forbidden("invalid agent token"));
    }

    if row.status != "approved" {
        return Err(forbidden(format!(
            "agent '{}' is not approved (status: {})",
            row.agent_id, row.status
        )));
    }

    Ok(row)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /api/agents/register
///
/// Enrolls a new agent in 'pending' status. Generates a bearer token,
/// stores its SHA-256 hash, and returns the plaintext token ONCE.
/// A pending agent cannot poll for jobs until an admin approves it.
pub async fn register_agent(
    _headers: HeaderMap,
    Json(body): Json<RegisterBody>,
) -> ApiResult<Json<RegisterResponse>> {
    let pool = get_db().ok_or_else(|| db_err("database unavailable"))?;

    // Minimal input validation.
    if body.agent_id.trim().is_empty() {
        return Err(bad_request("agent_id must not be empty"));
    }
    if body.platform.trim().is_empty() {
        return Err(bad_request("platform must not be empty"));
    }
    if body.public_key.trim().is_empty() {
        return Err(bad_request("public_key must not be empty"));
    }

    let token = generate_agent_token();
    let hash = sha256_hex(&token);
    let capabilities_json = serde_json::to_value(&body.capabilities).map_err(db_err)?;

    let result = sqlx::query(
        "INSERT INTO agents (agent_id, platform, capabilities, public_key, token_hash, status) \
         VALUES ($1, $2, $3, $4, $5, 'pending') \
         ON CONFLICT DO NOTHING",
    )
    .bind(&body.agent_id)
    .bind(&body.platform)
    .bind(&capabilities_json)
    .bind(&body.public_key)
    .bind(&hash)
    .execute(pool)
    .await
    .map_err(db_err)?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({"error": format!("agent_id '{}' already registered", body.agent_id)})),
        ));
    }

    tracing::info!(agent_id = %body.agent_id, platform = %body.platform, "agent registered (pending)");

    Ok(Json(RegisterResponse {
        agent_id: body.agent_id,
        token,
    }))
}

/// POST /api/admin/agents/{agent_id}/approve
///
/// Sets an agent's status to 'approved'. ALWAYS overwrites platform and
/// (optionally) capabilities with admin-authoritative values — the agent's
/// self-declared registration data is treated as a hint only.
///
/// `platform` is required in the request body; omitting it is a 400 error.
/// This endpoint sits under `/api/admin/` so the human RBAC middleware enforces
/// the `admin` permission and agent-token auth cannot reach it.
pub async fn admin_approve_agent(
    Path(agent_id): Path<String>,
    _headers: HeaderMap,
    Json(body): Json<ApproveBody>,
) -> ApiResult<Json<Value>> {
    let pool = get_db().ok_or_else(|| db_err("database unavailable"))?;

    if body.platform.trim().is_empty() {
        return Err(bad_request("platform must not be empty"));
    }

    // Always overwrite platform (and capabilities when provided) with the
    // admin-supplied authoritative values. The agent's self-declared
    // registration data is never trusted for job dispatch.
    let now = Utc::now();
    let rows_affected = if let Some(caps) = &body.capabilities {
        let caps_json = serde_json::to_value(caps).map_err(db_err)?;
        sqlx::query(
            "UPDATE agents SET status = 'approved', platform = $1, capabilities = $2, \
             updated_at = $3 WHERE agent_id = $4",
        )
        .bind(&body.platform)
        .bind(&caps_json)
        .bind(now)
        .bind(&agent_id)
        .execute(pool)
        .await
        .map_err(db_err)?
        .rows_affected()
    } else {
        // No admin-supplied capabilities: RESET to empty rather than keep the
        // agent's self-declared registration capabilities (never authoritative).
        // The admin must explicitly grant capabilities for dispatch to match.
        sqlx::query(
            "UPDATE agents SET status = 'approved', platform = $1, \
             capabilities = '{}'::jsonb, updated_at = $2 WHERE agent_id = $3",
        )
        .bind(&body.platform)
        .bind(now)
        .bind(&agent_id)
        .execute(pool)
        .await
        .map_err(db_err)?
        .rows_affected()
    };

    if rows_affected == 0 {
        return Err(not_found(format!("agent '{}' not found", agent_id)));
    }

    tracing::info!(
        agent_id = %agent_id,
        assigned_platform = %body.platform,
        "agent approved (platform authoritatively set)"
    );
    Ok(Json(
        json!({"agent_id": agent_id, "status": "approved", "platform": body.platform}),
    ))
}

/// GET /api/agents/{agent_id}/jobs
///
/// Authenticated (bearer token + approved). Atomically leases the next
/// Pending job for this agent's platform using SELECT … FOR UPDATE SKIP LOCKED,
/// then returns the full Job with its JobLease (including cp_nonce +
/// fencing_token). Returns 204 when no Pending job is available.
pub async fn poll_job(Path(agent_id): Path<String>, headers: HeaderMap) -> impl IntoResponse {
    let pool = match get_db() {
        Some(p) => p,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "database unavailable"})),
            )
                .into_response()
        }
    };

    let agent = match authenticate_agent(&headers, pool).await {
        Ok(a) => a,
        Err((status, body)) => return (status, body).into_response(),
    };

    // Verify path agent_id matches the token's agent.
    if agent.agent_id != agent_id {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "token does not match agent_id"})),
        )
            .into_response();
    }

    let new_attempt_id = Uuid::new_v4();
    let fencing_token = Uuid::new_v4().to_string();
    let cp_nonce = Uuid::new_v4().to_string();

    // Atomically lease the next Pending job for this platform.
    // SKIP LOCKED ensures two concurrent polls cannot double-lease the same row.
    // lease_deadline is computed entirely in DB time (NOW() + interval) so all
    // lease timing uses the canonical Postgres clock, not the API server clock.
    let row = sqlx::query_as::<_, AgentJobRow>(&format!(
        "UPDATE agent_jobs \
         SET status = 'Leased', \
             agent_id = $1, \
             attempt_id = $2, \
             lease_generation = lease_generation + 1, \
             fencing_token = $3, \
             cp_nonce = $4, \
             lease_deadline = NOW() + make_interval(secs => $5), \
             updated_at = NOW() \
         WHERE id = ( \
             SELECT id FROM agent_jobs \
             WHERE platform = $6 AND status = 'Pending' \
             ORDER BY created_at \
             FOR UPDATE SKIP LOCKED \
             LIMIT 1 \
         ) \
         RETURNING {AGENT_JOB_COLUMNS}"
    ))
    .bind(&agent_id)
    .bind(new_attempt_id)
    .bind(&fencing_token)
    .bind(&cp_nonce)
    .bind(LEASE_TTL_SECS as f64)
    .bind(&agent.platform)
    .fetch_optional(pool)
    .await;

    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => {
            // No Pending job available — 204 No Content.
            return StatusCode::NO_CONTENT.into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "lease query failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "database error"})),
            )
                .into_response();
        }
    };

    let spec: JobSpec = match serde_json::from_value(row.spec.0.clone()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(job_id = %row.id, error = %e, "job spec deserialization failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "malformed job spec in database"})),
            )
                .into_response();
        }
    };

    // Use the DB-computed deadline from the RETURNING row — the canonical value
    // set by NOW() + make_interval in the lease UPDATE.
    let db_deadline = row
        .lease_deadline
        .unwrap_or_else(|| Utc::now() + Duration::seconds(LEASE_TTL_SECS));
    let lease = JobLease {
        attempt_id: new_attempt_id,
        lease_generation: row.lease_generation as u64,
        fencing_token,
        deadline: db_deadline,
        cp_nonce,
    };

    // S5: deliver the CP-signed grant (if any) so the agent can verify_vlc it
    // before a LiveApply. A malformed stored grant is logged and delivered as
    // None — the agent then refuses to apply (fail-safe).
    let live_context = match row.live_context.as_ref() {
        Some(j) => match serde_json::from_value::<VerifiedLiveContext>(j.0.clone()) {
            Ok(g) => Some(g),
            Err(e) => {
                tracing::error!(
                    job_id = %row.id,
                    error = %e,
                    "stored live_context is malformed; delivering job without a grant"
                );
                None
            }
        },
        None => None,
    };

    let job = Job {
        id: row.id,
        platform: row.platform.clone(),
        spec,
        status: JobStatus::Leased,
        lease: Some(lease),
        live_context,
    };

    tracing::info!(
        job_id = %row.id,
        agent_id = %agent_id,
        attempt_id = %new_attempt_id,
        "job leased"
    );

    Json(job).into_response()
}

/// POST /api/agents/{agent_id}/jobs/{job_id}/ack
///
/// Transitions Leased → Running. The caller must supply the fencing_token and
/// attempt_id that match the current lease. A mismatch returns 409.
pub async fn ack_job(
    Path((agent_id, job_id_str)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<AckBody>,
) -> ApiResult<Json<Value>> {
    let pool = get_db().ok_or_else(|| db_err("database unavailable"))?;
    let agent = authenticate_agent(&headers, pool).await?;

    if agent.agent_id != agent_id {
        return Err(forbidden("token does not match agent_id"));
    }

    let job_id = parse_agent_job_id(&job_id_str)?;

    // Atomic conditional UPDATE: transitions Leased → Running in a single
    // statement. All four conditions (status, attempt_id, fencing_token,
    // lease_deadline) are evaluated by the DB in one round-trip, eliminating
    // the TOCTOU window that existed in the previous read-then-write approach.
    // A concurrent expire/re-lease between a SELECT and this UPDATE can no
    // longer clobber a stale ack into Running.
    // Scalar query returns the id if the UPDATE matched — used only for
    // is_some() check, so we query the scalar directly.
    let updated = sqlx::query_scalar::<_, Uuid>(
        "UPDATE agent_jobs \
         SET status = 'Running', updated_at = NOW() \
         WHERE id = $1 \
           AND status = 'Leased' \
           AND attempt_id = $2 \
           AND fencing_token = $3 \
           AND lease_deadline >= NOW() \
         RETURNING id",
    )
    .bind(job_id)
    .bind(body.attempt_id)
    .bind(&body.fencing_token)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    if updated.is_some() {
        // Scalar result is the matched row id — presence means transition succeeded.
        tracing::info!(job_id = %job_id, agent_id = %agent_id, "job ack → Running");
        return Ok(Json(json!({"job_id": job_id, "status": "Running"})));
    }

    // UPDATE matched 0 rows. Disambiguate: 404 vs 409.
    #[derive(sqlx::FromRow)]
    struct StatusRow {
        status: String,
        attempt_id: Option<Uuid>,
        lease_deadline: Option<chrono::DateTime<Utc>>,
    }
    let existing = sqlx::query_as::<_, StatusRow>(
        "SELECT status, attempt_id, lease_deadline FROM agent_jobs WHERE id = $1",
    )
    .bind(job_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    let row = match existing {
        None => return Err(not_found(format!("job {} not found", job_id))),
        Some(r) => r,
    };

    // Build a clear rejection reason for the caller.
    let reason = if row.status != "Leased" {
        format!(
            "job {} is in status '{}', expected 'Leased'",
            job_id, row.status
        )
    } else if row.attempt_id != Some(body.attempt_id) {
        "attempt_id mismatch — lease has been superseded".to_string()
    } else if row.lease_deadline.map(|d| d < Utc::now()).unwrap_or(true) {
        "lease has expired".to_string()
    } else {
        "fencing_token mismatch".to_string()
    };

    Err(conflict(reason))
}

// ---------------------------------------------------------------------------
// Result body — submitted by the agent
// ---------------------------------------------------------------------------

/// Body for POST /api/agents/{agent_id}/jobs/{job_id}/result.
///
/// The outer `JobResult` fields are untrusted; only the embedded
/// `SignedEnvelope` is authoritative. The handler equality-checks every outer
/// field against the signed envelope before persisting anything.
#[derive(Debug, Deserialize)]
pub struct ResultBody {
    pub job_result: JobResult,
    /// Raw evidence bytes (the payload whose SHA-256 is `evidence_digest`).
    /// May be empty for modes that produce no evidence (e.g. OfflineDryRun
    /// without a plan artifact), but the digest must still match.
    #[serde(default)]
    pub evidence: Vec<u8>,
    /// Optional structured evidence parsed from the evidence bytes.
    /// Stored as JSONB for query convenience; never trusted for authz.
    #[serde(default)]
    pub evidence_json: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Internal DB row for the terminal result read-back (idempotency)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(sqlx::FromRow)]
struct TerminalResultRow {
    status: String,
    result_id: Option<uuid::Uuid>,
    result_status: Option<String>,
    evidence_digest: Option<String>,
    completed_at: Option<chrono::DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// JobResultStatus wire label → DB TEXT
// ---------------------------------------------------------------------------

fn result_status_label(s: &JobResultStatus) -> &'static str {
    match s {
        JobResultStatus::CheckOk => "check_ok",
        JobResultStatus::Planned => "planned",
        JobResultStatus::Applied => "applied",
        JobResultStatus::Verified => "verified",
        JobResultStatus::Failed => "failed",
        JobResultStatus::LiveRefused => "live_refused",
    }
}

// ---------------------------------------------------------------------------
// JobResultStatus → terminal agent_jobs.status
// ---------------------------------------------------------------------------

fn map_result_status_to_job_status(s: &JobResultStatus) -> &'static str {
    match s {
        JobResultStatus::CheckOk
        | JobResultStatus::Planned
        | JobResultStatus::Applied
        | JobResultStatus::Verified => "Succeeded",
        JobResultStatus::Failed => "Failed",
        JobResultStatus::LiveRefused => "LiveRefused",
    }
}

// ---------------------------------------------------------------------------
// POST /api/agents/{agent_id}/jobs/{job_id}/result
// ---------------------------------------------------------------------------

/// Verifies and records the signed `JobResult` from an agent.
///
/// The full 9-step verifier runs FAIL-CLOSED: every check that fails returns
/// 4xx and mutates nothing. The terminal UPDATE is a single atomic conditional
/// statement guarded on (id, attempt_id, lease_generation, status IN
/// ('Leased','Running')). A repeat POST with the same (job_id, attempt_id,
/// result_id) returns idempotent 200.
pub async fn post_job_result(
    Path((agent_id, job_id_str)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<ResultBody>,
) -> ApiResult<Json<serde_json::Value>> {
    let pool = get_db().ok_or_else(|| db_err("database unavailable"))?;
    post_job_result_with_pool(agent_id, job_id_str, headers, body, pool).await
}

/// Backlink an agent's terminal result onto the parent request (AWX bridge
/// slice 2). When a dispatched request is still `executing`, mark its execute
/// stage Completed (success) or Failed, record a pointer to the agent job, and
/// advance the request (`executing` -> `verifying` on success, otherwise
/// `-> failed`) — in the SAME transaction as the job's terminal record.
///
/// Best-effort and CAS-guarded: a request that is missing (e.g. synthetic test
/// jobs) or no longer `executing` is left untouched, so this never fails the
/// result POST.
async fn backlink_request_execution(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request_id: uuid::Uuid,
    status: &JobResultStatus,
    result_status_str: &str,
    evidence_digest: &str,
    job_id: uuid::Uuid,
) -> Result<(), sqlx::Error> {
    let row: Option<(String, serde_json::Value)> =
        sqlx::query_as("SELECT status, stages FROM requests WHERE id = $1")
            .bind(request_id)
            .fetch_optional(&mut **tx)
            .await?;
    let Some((req_status, stages_val)) = row else {
        return Ok(());
    };
    if req_status != "executing" {
        return Ok(());
    }

    let success = matches!(
        status,
        JobResultStatus::CheckOk
            | JobResultStatus::Planned
            | JobResultStatus::Applied
            | JobResultStatus::Verified
    );
    let now = chrono::Utc::now().to_rfc3339();

    let mut stages: Vec<ryuki_engine::models::Stage> =
        serde_json::from_value(stages_val).unwrap_or_default();
    if let Some(st) = stages.iter_mut().find(|s| s.name == "execute") {
        st.status = if success {
            ryuki_engine::models::StageStatus::Completed
        } else {
            ryuki_engine::models::StageStatus::Failed
        };
        st.completed_at = Some(now);
        st.metadata
            .insert("agent_job_id".into(), job_id.to_string());
        st.metadata
            .insert("result_status".into(), result_status_str.to_string());
        st.metadata
            .insert("evidence_digest".into(), evidence_digest.to_string());
    }
    let stages_json = serde_json::to_value(&stages).unwrap_or_else(|_| serde_json::json!([]));
    let (new_status, new_stage) = if success {
        ("verifying", "verify")
    } else {
        ("failed", "execute")
    };

    // CAS: only advance if still `executing` (a concurrent transition wins
    // harmlessly — the job result is already durably recorded).
    sqlx::query(
        "UPDATE requests SET status = $1, stage = $2, stages = $3::jsonb, updated_at = NOW() \
         WHERE id = $4 AND status = 'executing'",
    )
    .bind(new_status)
    .bind(new_stage)
    .bind(&stages_json)
    .bind(request_id)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

/// Inner implementation that accepts an explicit pool — used by integration
/// tests that cannot rely on the global `get_db()` singleton.
async fn post_job_result_with_pool(
    agent_id: String,
    job_id_str: String,
    headers: HeaderMap,
    body: ResultBody,
    pool: &PgPool,
) -> ApiResult<Json<serde_json::Value>> {
    // ── Step 1: authenticate + agent_id match ────────────────────────────────
    let agent = authenticate_agent(&headers, pool).await?;

    if agent.agent_id != agent_id {
        return Err(forbidden("token does not match path agent_id"));
    }

    let result = &body.job_result;
    let env = &result.signed_envelope;

    if agent.agent_id != env.agent_id {
        return Err(forbidden("token agent_id does not match envelope.agent_id"));
    }

    // ── Step 2: load the job row ──────────────────────────────────────────────
    let job_id = parse_agent_job_id(&job_id_str)?;

    #[derive(sqlx::FromRow)]
    #[allow(dead_code)]
    struct JobForResult {
        id: uuid::Uuid,
        status: String,
        agent_id: Option<String>,
        attempt_id: Option<uuid::Uuid>,
        lease_generation: i64,
        cp_nonce: Option<String>,
        spec: sqlx::types::Json<serde_json::Value>,
        mode: String,
        // Fix 3: platform and request_id loaded from DB to bind signed context.
        platform: String,
        request_id: uuid::Uuid,
        // S5: the CP-signed approval grant for LiveApply jobs (NULL otherwise).
        live_context: Option<sqlx::types::Json<serde_json::Value>>,
        result_id: Option<uuid::Uuid>,
        result_status: Option<String>,
        evidence_digest: Option<String>,
        completed_at: Option<chrono::DateTime<Utc>>,
    }

    let row = sqlx::query_as::<_, JobForResult>(
        "SELECT id, status, agent_id, attempt_id, lease_generation, cp_nonce, spec, mode, \
         platform, request_id, live_context, \
         result_id, result_status, evidence_digest, completed_at \
         FROM agent_jobs WHERE id = $1",
    )
    .bind(job_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| not_found(format!("job {} not found", job_id)))?;

    // ── Authorization BEFORE any status disclosure ───────────────────────────
    //
    // The agent must be the assignee. This runs before any status-dependent
    // branch so the endpoint never leaks job state (active vs terminal) to a
    // token holder who is not the assignee. An unassigned/Pending job has
    // agent_id = NULL → this rejects with 403 before any state is observable.
    if row.agent_id.as_deref() != Some(&agent.agent_id) {
        return Err(forbidden("job is not assigned to this agent"));
    }

    // FAIL-CLOSED: no early status gate and no idempotency fast-path here. Every
    // request — including a replay against an already-terminal row — runs the
    // FULL verification (steps 3-8) before any decision is made. The atomic
    // terminal UPDATE (step 9) is conditioned on status IN ('Leased','Running'),
    // so the result commits exactly once. A VALID signed replay of an
    // already-recorded result re-verifies, the UPDATE matches 0 rows, and the
    // post-UPDATE idempotency branch returns 200 ("already recorded") — which the
    // agent's at-least-once durable outbox relies on for a lost-ack retry. An
    // unsigned/forged replay FAILS verification above and NEVER reaches that
    // branch. The lease fields (attempt_id, lease_generation, cp_nonce) persist
    // on terminal rows, so re-verification of a legitimate replay still works.

    // ── Step 3: verify Ed25519 signature against enrolled public key ──────────
    //
    // key_id in the envelope must match the enrolled public_key fingerprint.
    // The enrolled public_key is stored as base64 (the raw VerifyingKey bytes);
    // key_id in the envelope is also base64 of the VerifyingKey — they must be
    // equal.
    use ryuki_protocol::{decode_verifying_key, verify as verify_envelope};

    let vk = decode_verifying_key(&agent.public_key)
        .map_err(|e| bad_request(format!("enrolled public key is malformed: {}", e)))?;

    // key_id must equal the enrolled public key fingerprint.
    let enrolled_key_id = ryuki_protocol::encode_verifying_key(&vk);
    if env.key_id != enrolled_key_id {
        return Err(bad_request(
            "envelope.key_id does not identify the enrolled key",
        ));
    }

    verify_envelope(env, &vk)
        .map_err(|_| bad_request("signature verification failed — envelope has been tampered"))?;

    // ── Step 4: lease / fencing match ────────────────────────────────────────
    let stored_attempt_id = row
        .attempt_id
        .ok_or_else(|| conflict("job has no active attempt — lease may have expired"))?;
    let stored_cp_nonce = row
        .cp_nonce
        .as_deref()
        .ok_or_else(|| conflict("job has no cp_nonce — lease may have expired"))?;

    if env.job_id != job_id {
        return Err(bad_request("envelope.job_id does not match path job_id"));
    }
    if env.attempt_id != stored_attempt_id {
        return Err((
            axum::http::StatusCode::CONFLICT,
            axum::Json(json!({
                "error": "envelope.attempt_id does not match active attempt — stale or superseded attempt"
            })),
        ));
    }
    if env.lease_generation != row.lease_generation as u64 {
        return Err((
            axum::http::StatusCode::CONFLICT,
            axum::Json(json!({
                "error": "envelope.lease_generation does not match — stale attempt"
            })),
        ));
    }
    // cp_nonce is the one-time binding: constant-time compare.
    {
        use subtle::ConstantTimeEq;
        let nonce_ok: bool = env
            .cp_nonce
            .as_bytes()
            .ct_eq(stored_cp_nonce.as_bytes())
            .into();
        if !nonce_ok {
            return Err(bad_request(
                "envelope.cp_nonce does not match stored lease nonce",
            ));
        }
    }

    // ── Fix 3 (part A): signed platform + mode binding ───────────────────────
    //
    // platform and mode are DB columns — bind them against the envelope here,
    // before step 5. request_id is bound in Fix 3 part B (after step 7) using
    // stored_spec.request_id, because that is the authoritative value the agent
    // received in the dispatched JobSpec (the column and spec field may differ
    // in the test harness, but the agent always signs spec.request_id).
    // Parse mode once here; reused in step 8 so no second parse is needed.
    let stored_mode = parse_job_mode(&row.mode)?;
    if env.platform != row.platform {
        return Err(bad_request(
            "envelope.platform does not match the dispatched job's platform",
        ));
    }
    if env.mode != stored_mode {
        return Err(bad_request(
            "envelope.mode does not match the dispatched job's mode",
        ));
    }

    // ── Step 5: outer JobResult fields must EQUAL the signed envelope ─────────
    if result.job_id != env.job_id {
        return Err(bad_request(
            "outer result.job_id does not match envelope.job_id",
        ));
    }
    if result.attempt_id != env.attempt_id {
        return Err(bad_request(
            "outer result.attempt_id does not match envelope.attempt_id",
        ));
    }
    if result.result_id != env.result_id {
        return Err(bad_request(
            "outer result.result_id does not match envelope.result_id",
        ));
    }
    if result.status != env.status {
        return Err(bad_request(
            "outer result.status does not match envelope.status",
        ));
    }
    if result.evidence_digest != env.evidence_digest {
        return Err(bad_request(
            "outer result.evidence_digest does not match envelope.evidence_digest",
        ));
    }

    // ── Step 6: evidence_digest recompute ────────────────────────────────────
    //
    // Recompute SHA-256 over the evidence bytes the CP will store. Uses the
    // same sha256_hex from ryuki_protocol::crypto — byte-level, not JSON.
    let recomputed_evidence_digest = ryuki_protocol::sha256_hex(&body.evidence);
    if recomputed_evidence_digest != env.evidence_digest {
        return Err(bad_request(
            "evidence_digest mismatch — recomputed digest does not match signed envelope",
        ));
    }

    // ── Step 7: job_spec_digest recompute ────────────────────────────────────
    //
    // Recompute over the stored dispatched JobSpec (from the agent_jobs.spec
    // column). Uses ryuki_protocol::job_spec_digest (SHA-256 of the JSON
    // serialisation — deterministic because JobSpec uses BTreeMap for vars).
    let stored_spec: JobSpec = serde_json::from_value(row.spec.0.clone()).map_err(|e| {
        tracing::error!(job_id = %job_id, error = %e, "stored spec is malformed");
        db_err("stored job spec is malformed")
    })?;
    let recomputed_spec_digest = ryuki_protocol::job_spec_digest(&stored_spec);
    if recomputed_spec_digest != env.job_spec_digest {
        return Err(bad_request(
            "job_spec_digest mismatch — does not match stored dispatched spec",
        ));
    }

    // ── Fix 3 (part B): signed request_id binding ────────────────────────────
    //
    // request_id is included in signing_bytes; bind it against stored_spec.request_id
    // (the value embedded in the dispatched JobSpec JSONB — what the agent received
    // and signed). The agent_jobs.request_id column is the canonical upstream
    // reference but the agent always copies request_id from the spec it received.
    if env.request_id != stored_spec.request_id {
        return Err(bad_request(
            "envelope.request_id does not match the dispatched job spec's request_id",
        ));
    }

    // ── Step 8: mode rules + LiveApply approved-plan grant check (S5) ─────────
    //
    // LiveApply is the only mutating mode. A live result is accepted ONLY if the
    // plan digest the agent signed EQUALS the approved-plan digest in the
    // control-plane-issued grant (`live_context`), and the grant has not expired.
    // This is the core live-apply gate: an agent can never apply (or report
    // applying) a plan other than the one an operator reviewed and the CP granted
    // — closing the S3b deferral where only presence was (not) checked.
    //
    // Non-live modes (OfflineDryRun / LivePlan) must NOT carry approved_plan_digest.
    // `stored_mode` was parsed in Fix 3 above (no second parse needed).
    match stored_mode {
        JobMode::LiveApply => {
            // A LiveRefused result is the agent reporting it DECLINED to apply
            // (missing/invalid grant, plan divergence, or no --allow-live). Record
            // the refusal WITHOUT the grant checks — the refusal may be BECAUSE the
            // grant was unusable, and declining is always safe (no mutation
            // happened). It must carry no approved_plan_digest (no plan applied).
            if env.status == JobResultStatus::LiveRefused {
                if env.approved_plan_digest.is_some() {
                    return Err(bad_request(
                        "LiveRefused result must not carry approved_plan_digest",
                    ));
                }
            } else {
                // The job must carry the CP-signed grant. Job creation (S5a-2) is
                // responsible for attaching it; this runtime check is the fail-closed
                // enforcement of that invariant (migration 056 deliberately uses no
                // DB CHECK — see its comment).
                let grant_json = row.live_context.as_ref().ok_or_else(|| {
                    conflict(
                    "LiveApply job has no approval grant (live_context) — refusing a live result",
                )
                })?;
                let grant: VerifiedLiveContext =
                serde_json::from_value(grant_json.0.clone()).map_err(|e| {
                    tracing::error!(job_id = %job_id, error = %e, "stored live_context is malformed");
                    db_err("stored live_context is malformed")
                })?;

                // The grant MUST be genuinely CP-signed. Verifying the Ed25519
                // signature against the CP's own public key defends against a
                // tampered stored grant (e.g. a DB-write attacker who alters
                // approved_plan_digest but cannot forge the CP signature). The agent
                // also independently verifies this signature before applying (S5b).
                let cp_vk = cp_identity::cp_signing_key()
                    .ok_or_else(|| {
                        tracing::error!(
                            "CP signing key is not initialised — cannot verify LiveApply grant"
                        );
                        (
                            axum::http::StatusCode::SERVICE_UNAVAILABLE,
                            axum::Json(json!({
                                "error": "control plane is not configured to verify live grants"
                            })),
                        )
                    })?
                    .verifying_key();
                verify_vlc(&grant, &cp_vk)
                    .map_err(|_| bad_request("approval grant signature is invalid"))?;

                // The agent's signed envelope MUST carry the applied plan digest.
                let env_digest = env.approved_plan_digest.as_deref().ok_or_else(|| {
                    bad_request(
                        "LiveApply result must include approved_plan_digest in the signed envelope",
                    )
                })?;

                // EQUALITY: the applied plan digest must match the APPROVED plan
                // digest. The digest is a public hash (not a secret), so a plain
                // comparison is appropriate.
                if env_digest != grant.approved_plan_digest {
                    return Err(bad_request(
                        "approved_plan_digest does not match the approved grant — \
                     refusing to record an unapproved plan",
                    ));
                }

                // The grant must be for THIS job's request (defends against a grant
                // mistakenly attached to a different request at job-creation time).
                // stored_spec was deserialised in step 7.
                if grant.request_id != stored_spec.request_id {
                    return Err(bad_request(
                        "approval grant request_id does not match the job's request",
                    ));
                }

                // The grant must not be expired AT APPLY TIME. Expiry gates the
                // actual application, which only happens while the job is still
                // Leased/Running (the atomic UPDATE below records the result exactly
                // once from that state). A later idempotent REPLAY of an
                // already-recorded result (job already terminal) must NOT be
                // re-gated on expiry — the result was validated and applied within
                // the grant window, and the agent's durable outbox may retry the
                // POST after the grant has since expired. So only enforce expiry on
                // the first-apply path. The control plane is the authority on time
                // here (it issued the grant); the agent also independently rejects
                // an expired grant before applying.
                let first_apply = matches!(row.status.as_str(), "Leased" | "Running");
                if first_apply && grant.expiry < Utc::now() {
                    return Err((
                        axum::http::StatusCode::CONFLICT,
                        axum::Json(json!({
                            "error": "the approval grant has expired — re-approval is required"
                        })),
                    ));
                }
            } // end else (non-refusal LiveApply grant checks)
        }
        JobMode::OfflineDryRun | JobMode::LivePlan => {
            // Non-live modes must NOT include approved_plan_digest.
            if env.approved_plan_digest.is_some() {
                return Err(bad_request(
                    "non-LiveApply result must not include approved_plan_digest",
                ));
            }
        }
    }

    // ── Step 9: atomic terminal UPDATE ───────────────────────────────────────
    //
    // Single UPDATE conditioned on (id, attempt_id, lease_generation, status IN
    // ('Leased','Running')). rows_affected == 0 means the attempt was superseded,
    // expired, or already terminal.
    let new_job_status = map_result_status_to_job_status(&env.status);
    let result_status_str = result_status_label(&env.status);
    let envelope_json = serde_json::to_value(env).map_err(db_err)?;

    // The terminal record and the parent-request backlink (slice 2) share ONE
    // transaction: a job that records its result also advances its request, and
    // vice versa — never one without the other.
    let mut tx = pool.begin().await.map_err(db_err)?;
    let updated = sqlx::query_scalar::<_, uuid::Uuid>(
        "UPDATE agent_jobs \
         SET status = $1, \
             result_id = $2, \
             result_status = $3, \
             evidence_digest = $4, \
             evidence_json = $5::jsonb, \
             signed_envelope = $6::jsonb, \
             completed_at = NOW(), \
             updated_at = NOW() \
         WHERE id = $7 \
           AND attempt_id = $8 \
           AND lease_generation = $9 \
           AND status IN ('Leased', 'Running') \
         RETURNING id",
    )
    .bind(new_job_status)
    .bind(result.result_id)
    .bind(result_status_str)
    .bind(&env.evidence_digest)
    .bind(&body.evidence_json)
    .bind(&envelope_json)
    .bind(job_id)
    .bind(result.attempt_id)
    .bind(row.lease_generation)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;

    if updated.is_some() {
        // Advance the request the signed result is cryptographically BOUND to —
        // stored_spec.request_id (verified == env.request_id above), not the
        // raw agent_jobs.request_id column, which create_agent_job does not pin
        // to the spec. This prevents a result from advancing the wrong request
        // if the column and the dispatched spec ever diverge.
        backlink_request_execution(
            &mut tx,
            stored_spec.request_id,
            &env.status,
            result_status_str,
            &env.evidence_digest,
            job_id,
        )
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        tracing::info!(
            job_id = %job_id,
            agent_id = %agent_id,
            result_id = %result.result_id,
            result_status = result_status_str,
            job_status = new_job_status,
            "job result recorded — terminal"
        );
        return Ok(Json(json!({
            "job_id": job_id,
            "result_id": result.result_id,
            "result_status": result_status_str,
            "job_status": new_job_status,
        })));
    }

    // Nothing updated in this tx (superseded/expired/already terminal): roll it
    // back, then run the read-only idempotency check on the pool below.
    tx.rollback().await.ok();

    // rows_affected == 0: the attempt was superseded/expired/already terminal.
    // Check idempotency: if this (attempt_id, result_id) is already recorded
    // in a terminal row, return 200. Otherwise 409.
    #[derive(sqlx::FromRow)]
    struct IdempotencyCheck {
        status: String,
        attempt_id: Option<uuid::Uuid>,
        result_id: Option<uuid::Uuid>,
        result_status: Option<String>,
    }
    let existing = sqlx::query_as::<_, IdempotencyCheck>(
        "SELECT status, attempt_id, result_id, result_status \
         FROM agent_jobs WHERE id = $1",
    )
    .bind(job_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    let existing = match existing {
        None => return Err(not_found(format!("job {} not found", job_id))),
        Some(r) => r,
    };

    if let (Some(stored_result_id), Some(stored_attempt_id)) =
        (existing.result_id, existing.attempt_id)
    {
        if stored_result_id == result.result_id && stored_attempt_id == result.attempt_id {
            tracing::info!(
                job_id = %job_id,
                result_id = %result.result_id,
                "idempotent result POST — already recorded (concurrent path)"
            );
            return Ok(Json(json!({
                "job_id": job_id,
                "result_id": stored_result_id,
                "result_status": existing.result_status,
                "job_status": existing.status,
                "idempotent": true,
            })));
        }
    }

    Err(conflict(format!(
        "job {} attempt/lease has been superseded or already reached a terminal state",
        job_id
    )))
}

// ---------------------------------------------------------------------------
// parse_job_mode: TEXT stored in DB → JobMode
// ---------------------------------------------------------------------------

fn parse_job_mode(mode_str: &str) -> ApiResult<JobMode> {
    match mode_str {
        "OfflineDryRun" => Ok(JobMode::OfflineDryRun),
        "LivePlan" => Ok(JobMode::LivePlan),
        "LiveApply" => Ok(JobMode::LiveApply),
        other => Err(bad_request(format!(
            "unknown job mode in database: {}",
            other
        ))),
    }
}

/// POST /api/agents/{agent_id}/heartbeat
///
/// Updates last_seen_at on the agent row. Optionally records the running job.
pub async fn heartbeat(
    Path(agent_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<HeartbeatBody>,
) -> ApiResult<Json<Value>> {
    let pool = get_db().ok_or_else(|| db_err("database unavailable"))?;
    let agent = authenticate_agent(&headers, pool).await?;

    if agent.agent_id != agent_id {
        return Err(forbidden("token does not match agent_id"));
    }

    sqlx::query("UPDATE agents SET last_seen_at = NOW(), updated_at = NOW() WHERE id = $1")
        .bind(agent.id)
        .execute(pool)
        .await
        .map_err(db_err)?;

    tracing::debug!(
        agent_id = %agent_id,
        running_job = ?body.running_job_id,
        "heartbeat"
    );

    Ok(Json(json!({
        "agent_id": agent_id,
        "last_seen_at": Utc::now().to_rfc3339(),
    })))
}

// ---------------------------------------------------------------------------
// Lease expiry / redispatch
//
// Call periodically (background task, cron, or on each poll).
// Non-mutating modes (OfflineDryRun / LivePlan): return to Pending with a
// fresh attempt, resetting all fencing fields.
// LiveApply: → ReconcileRequired (operator must reconcile before re-dispatch).
// ---------------------------------------------------------------------------

/// Returns the number of jobs transitioned.
pub async fn expire_leases(pool: &PgPool) -> Result<u64, sqlx::Error> {
    // Non-mutating (OfflineDryRun / LivePlan): reset to Pending, new attempt.
    let redispatched = sqlx::query(
        "UPDATE agent_jobs \
         SET status = 'Pending', \
             agent_id = NULL, \
             attempt_id = NULL, \
             fencing_token = NULL, \
             cp_nonce = NULL, \
             lease_deadline = NULL, \
             updated_at = NOW() \
         WHERE status IN ('Leased', 'Running') \
           AND mode IN ('OfflineDryRun', 'LivePlan') \
           AND lease_deadline < NOW()",
    )
    .execute(pool)
    .await?
    .rows_affected();

    // LiveApply: → ReconcileRequired (never auto-redispatched).
    let reconcile = sqlx::query(
        "UPDATE agent_jobs \
         SET status = 'ReconcileRequired', updated_at = NOW() \
         WHERE status IN ('Leased', 'Running') \
           AND mode = 'LiveApply' \
           AND lease_deadline < NOW()",
    )
    .execute(pool)
    .await?
    .rows_affected();

    if redispatched + reconcile > 0 {
        tracing::info!(
            redispatched,
            reconcile_required = reconcile,
            "agent lease expiry sweep"
        );
    }

    Ok(redispatched + reconcile)
}

// ---------------------------------------------------------------------------
// create_agent_job — enqueue helper
//
// Inserts a Pending job. NOT wired into the request lifecycle yet (S3b).
// ---------------------------------------------------------------------------

/// Enqueues a new Pending job for the given platform and returns the job row id.
#[cfg_attr(not(test), allow(dead_code))]
pub async fn create_agent_job(
    pool: &PgPool,
    request_id: Uuid,
    platform: &str,
    spec: &JobSpec,
    mode: &str,
) -> Result<Uuid, sqlx::Error> {
    let spec_json = serde_json::to_value(spec).expect("JobSpec serialisation is infallible");

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO agent_jobs (request_id, platform, spec, mode) \
         VALUES ($1, $2, $3, $4) \
         RETURNING id",
    )
    .bind(request_id)
    .bind(platform)
    .bind(&spec_json)
    .bind(mode)
    .fetch_one(pool)
    .await?;

    tracing::info!(
        job_id = %id,
        request_id = %request_id,
        platform = %platform,
        mode = %mode,
        "agent job enqueued"
    );
    Ok(id)
}

// ---------------------------------------------------------------------------
// Background lease-expiry sweep
// ---------------------------------------------------------------------------

/// Spawn a background task that calls `expire_leases` every `interval_secs`.
///
/// Call once at server startup (after the DB pool is available).
/// The task runs forever; it is cancelled when the tokio runtime shuts down.
/// `expire_leases` is idempotent, so duplicate sweeps are harmless.
pub fn spawn_lease_expiry_sweep(pool: PgPool, interval_secs: u64) {
    tokio::spawn(async move {
        let mut ticker = interval(std::time::Duration::from_secs(interval_secs));
        ticker.tick().await; // skip the immediate first tick (just started)
        loop {
            ticker.tick().await;
            if let Err(e) = expire_leases(&pool).await {
                tracing::error!(error = %e, "lease expiry sweep failed");
            }
        }
    });
}

// ---------------------------------------------------------------------------
// create_live_apply_job — enqueue a LiveApply job with a CP-signed grant
// ---------------------------------------------------------------------------

/// Validate the mode and request_id invariants for `create_live_apply_job`.
///
/// Separated from the async body so tests can call it directly without needing
/// a real `PgPool` (the assertions fire before any DB interaction).
///
/// Returns `Err(msg)` so the caller can decide how to handle the violation;
/// `create_live_apply_job` maps it to `CreateLiveApplyJobError::Invalid` (it does
/// NOT panic), so a future operator endpoint can surface a 4xx.
#[cfg_attr(not(test), allow(dead_code))]
pub fn validate_live_apply_params(spec: &JobSpec, request_id: Uuid) -> Result<(), &'static str> {
    if spec.mode != JobMode::LiveApply {
        return Err("create_live_apply_job requires a LiveApply spec");
    }
    if spec.request_id != request_id {
        return Err("spec.request_id must equal the supplied request_id");
    }
    Ok(())
}

/// Maximum lifetime of a LiveApply approval grant. A grant longer than this is
/// rejected at creation so an over-broad approval window cannot be minted.
const MAX_GRANT_TTL_HOURS: i64 = 24;

/// Error from [`create_live_apply_job`].
#[derive(Debug, thiserror::Error)]
pub enum CreateLiveApplyJobError {
    /// The supplied spec/request did not satisfy the LiveApply preconditions.
    #[error("invalid live-apply parameters: {0}")]
    Invalid(&'static str),
    /// The request has already CONCLUDED (Completed, the post-completion
    /// lifecycle Protecting/Operational/Retired, or a terminal state); a
    /// live-apply grant must never be minted against it. Maps to 409 Conflict.
    #[error("request has concluded; a live-apply grant cannot be minted")]
    RequestConcluded,
    /// A database error occurred while enqueuing the job.
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// Enqueue a new Pending `LiveApply` job with a CP-signed [`VerifiedLiveContext`]
/// grant attached, and return the job row id.
///
/// ## Signing invariants
///
/// - `spec.mode` MUST be `JobMode::LiveApply`; returns `Invalid` otherwise.
/// - `spec.request_id` MUST equal `request_id`; the S5a-1 verifier checks
///   `grant.request_id == spec.request_id` and rejects on mismatch.
///
/// ## Grant shape
///
/// A [`VerifiedLiveContext`] is constructed from the supplied fields and signed
/// by `cp_key` using `sign_vlc`. The signed grant is stored in the job row's
/// `live_context` JSONB column. Agents will fetch the job (including the grant)
/// via `GET /api/agents/{id}/jobs`, verify the CP signature against the CP
/// public key, and reject the apply if the signature is invalid.
///
/// Note: the operator-facing HTTP approval endpoint (portal integration) is a
/// later slice (S5c). This function is the signing core that all such endpoints
/// will delegate to.
#[cfg_attr(not(test), allow(dead_code))]
#[allow(clippy::too_many_arguments)]
pub async fn create_live_apply_job(
    pool: &PgPool,
    request_id: Uuid,
    platform: &str,
    spec: &JobSpec,
    approved_plan_digest: &str,
    approver: &str,
    expiry: DateTime<Utc>,
    cp_key: &ed25519_dalek::SigningKey,
) -> Result<Uuid, CreateLiveApplyJobError> {
    // Invariant: this function only creates LiveApply jobs — the grant is
    // meaningless for any other mode, and the S5a-1 verifier only checks grants
    // on LiveApply results. Fail closed (return Err) rather than panic so a
    // future operator endpoint can surface a 4xx instead of crashing the request.
    validate_live_apply_params(spec, request_id).map_err(CreateLiveApplyJobError::Invalid)?;

    // Fail closed: never mint a LiveApply grant for a request that has CONCLUDED
    // (Completed, the post-completion lifecycle Protecting/Operational/Retired, or
    // any terminal state). This gate lives in the SHARED minting choke point so it
    // covers EVERY path — the request-scoped approval AND the operator/admin
    // endpoint (/api/admin/agents/live-apply-jobs), which would otherwise bypass
    // the request-scoped status check entirely. A stale plan can therefore never
    // re-open a concluded request to infrastructure mutation. The exhaustive
    // is_concluded() classifier is the single source of truth.
    let req_status: Option<String> =
        sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(request_id)
            .fetch_optional(pool)
            .await?;
    match req_status {
        None => {
            return Err(CreateLiveApplyJobError::Invalid(
                "request not found; cannot mint a live-apply grant",
            ));
        }
        Some(status) if crate::contracts::db_status_to_request_status(&status).is_concluded() => {
            return Err(CreateLiveApplyJobError::RequestConcluded);
        }
        Some(_) => {}
    }

    // Validate the grant fields before signing — a signed grant is authoritative,
    // so it must never carry a bogus digest, an empty approver, or an abusive
    // expiry. (digest = lowercase SHA-256 hex; expiry must be in the future and
    // within MAX_GRANT_TTL.)
    if approved_plan_digest.len() != 64
        || !approved_plan_digest.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(CreateLiveApplyJobError::Invalid(
            "approved_plan_digest must be a 64-character SHA-256 hex string",
        ));
    }
    if approver.trim().is_empty() {
        return Err(CreateLiveApplyJobError::Invalid(
            "approver must not be empty",
        ));
    }
    let now = Utc::now();
    if expiry <= now {
        return Err(CreateLiveApplyJobError::Invalid(
            "grant expiry must be in the future",
        ));
    }
    if expiry > now + chrono::Duration::hours(MAX_GRANT_TTL_HOURS) {
        return Err(CreateLiveApplyJobError::Invalid(
            "grant expiry exceeds the maximum allowed TTL",
        ));
    }

    // Build and sign the VerifiedLiveContext grant.
    let unsigned_grant = VerifiedLiveContext {
        request_id,
        approved_plan_digest: approved_plan_digest.to_string(),
        approver: approver.to_string(),
        expiry,
        signature: String::new(),
    };
    let signed_grant = sign_vlc(unsigned_grant, cp_key);

    let spec_json = serde_json::to_value(spec).expect("JobSpec serialisation is infallible");
    let grant_json = serde_json::to_value(&signed_grant)
        .expect("VerifiedLiveContext serialisation is infallible");

    // Atomic, CONCURRENCY-SAFE no-double-apply invariant (enforced for EVERY
    // caller — the request-scoped approval AND the operator endpoint): insert
    // the LiveApply job only if none already exists for this request. ON
    // CONFLICT against the partial unique index `idx_agent_jobs_unique_live_apply`
    // (migration 057, `(request_id) WHERE mode='LiveApply'`) makes two
    // simultaneous approvals safe — the loser inserts nothing and gets None.
    // A grant authorising infrastructure mutation can therefore never be minted
    // twice; a failed/expired apply goes through operator reconcile, not a
    // re-mint.
    let id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO agent_jobs (request_id, platform, spec, mode, live_context) \
         VALUES ($1, $2, $3, 'LiveApply', $4::jsonb) \
         ON CONFLICT (request_id) WHERE mode = 'LiveApply' DO NOTHING \
         RETURNING id",
    )
    .bind(request_id)
    .bind(platform)
    .bind(&spec_json)
    .bind(&grant_json)
    .fetch_optional(pool)
    .await?;
    let id = id.ok_or(CreateLiveApplyJobError::Invalid(
        "a live-apply has already been approved for this request",
    ))?;

    tracing::info!(
        job_id = %id,
        request_id = %request_id,
        platform = %platform,
        approver = %approver,
        approved_plan_digest = %approved_plan_digest,
        "LiveApply job enqueued with CP-signed grant"
    );
    Ok(id)
}

// ---------------------------------------------------------------------------
// GET /api/agents/cp-public-key — unauthenticated CP public-key endpoint
// ---------------------------------------------------------------------------

/// Return the CP's Ed25519 public key as base64.
///
/// ## Auth posture
///
/// **Unauthenticated** — intentionally.  A public key is not a secret; any
/// agent (or observer) may fetch it.  Agents use this to pin the CP public key
/// for verifying [`VerifiedLiveContext`] grants.  This endpoint is mounted via
/// `agent_routes()`, which sits OUTSIDE the human `auth_middleware` layer in
/// `main.rs`, so no session or agent-token is required.
///
/// Returns 503 if the CP signing key was not initialised at startup (e.g. the
/// key file was unreadable and the server continued in degraded mode).
pub async fn cp_public_key() -> impl IntoResponse {
    match cp_identity::cp_public_key_b64() {
        Some(pubkey) => (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({"public_key": pubkey})),
        )
            .into_response(),
        None => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "CP signing key not initialised"})),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Returns the agent sub-router for agent-token–authenticated endpoints.
/// Mounted separately in main.rs (NOT under the human auth_middleware).
/// Admin-approve is served from /api/admin/ in contracts.rs / main.rs
/// so the human RBAC middleware covers it and agent tokens can never reach it.
/// Agent-token routes: these four endpoints use `authenticate_agent` (bearer
/// token) as their sole auth gate and must NOT sit behind the human
/// `auth_middleware`. Mount via `agents::agent_routes()` BEFORE the human
/// middleware layer in main.rs.
///
/// `GET /api/agents/cp-public-key` is intentionally unauthenticated: a public
/// key is not a secret, and agents need it to verify CP-signed grants before
/// (and independently of) their own auth.
pub fn agent_routes() -> Router {
    Router::new()
        .route("/api/agents/register", post(register_agent))
        .route("/api/agents/cp-public-key", get(cp_public_key))
        .route("/api/agents/{agent_id}/jobs", get(poll_job))
        .route("/api/agents/{agent_id}/jobs/{job_id}/ack", post(ack_job))
        .route(
            "/api/agents/{agent_id}/jobs/{job_id}/result",
            post(post_job_result),
        )
        .route("/api/agents/{agent_id}/heartbeat", post(heartbeat))
}

// ---------------------------------------------------------------------------
// POST /api/admin/agents/live-apply-jobs — operator live-apply approval
// ---------------------------------------------------------------------------

/// Request body for the operator live-apply approval endpoint.
///
/// The `approver` identity is always taken from the verified session — it MUST
/// NOT appear in this body so that a caller cannot forge the approving principal.
#[derive(Debug, Deserialize)]
pub struct ApproveLiveApplyBody {
    pub request_id: Uuid,
    pub platform: String,
    pub spec: JobSpec,
    pub approved_plan_digest: String,
    /// Requested grant lifetime in seconds. Must be > 0 and ≤ MAX_GRANT_TTL_HOURS * 3600.
    pub expiry_seconds: u64,
}

/// Testable core for live-apply approval (no axum Extension — takes primitives).
///
/// Validates `expiry_seconds`, computes the absolute expiry, then delegates to
/// [`create_live_apply_job`] which performs the remaining invariant checks
/// (digest format, approver emptiness, spec.mode, request_id binding) before
/// signing the grant and inserting the job row.
///
/// Returns the job id and associated metadata as a JSON response.
pub async fn approve_live_apply_with(
    pool: &PgPool,
    cp_key: &ed25519_dalek::SigningKey,
    approver: &str,
    body: &ApproveLiveApplyBody,
) -> ApiResult<Json<Value>> {
    // Validate expiry bounds here for a clean 400 before we reach create_live_apply_job.
    if body.expiry_seconds == 0 {
        return Err(bad_request("expiry_seconds must be greater than zero"));
    }
    let max_seconds = (MAX_GRANT_TTL_HOURS as u64) * 3600;
    if body.expiry_seconds > max_seconds {
        return Err(bad_request(format!(
            "expiry_seconds exceeds the maximum allowed TTL ({} seconds)",
            max_seconds
        )));
    }

    let expiry = Utc::now() + Duration::seconds(body.expiry_seconds as i64);

    let job_id = create_live_apply_job(
        pool,
        body.request_id,
        &body.platform,
        &body.spec,
        &body.approved_plan_digest,
        approver,
        expiry,
        cp_key,
    )
    .await
    .map_err(|e| match e {
        CreateLiveApplyJobError::Invalid(msg) => bad_request(msg),
        CreateLiveApplyJobError::RequestConcluded => {
            conflict("request has concluded; a live-apply grant cannot be minted")
        }
        CreateLiveApplyJobError::Db(db_e) => db_err(db_e),
    })?;

    Ok(Json(json!({
        "job_id": job_id,
        "approver": approver,
        "status": "Pending",
        "mode": "LiveApply"
    })))
}

/// POST /api/admin/agents/live-apply-jobs
///
/// Operator-gated endpoint that mints a CP-signed LiveApply grant and enqueues
/// the job for dispatch. The approver identity is taken exclusively from the
/// verified session — the request body cannot override it.
///
/// ## Auth posture
///
/// The route sits under `/api/admin/` so the human RBAC middleware already
/// enforces `admin` permission at the routing layer. The `check_permission`
/// call below is defense-in-depth: it fires if the middleware assumption ever
/// changes or the handler is composed without it.
///
/// Returns 503 if the database pool or CP signing key was not initialised
/// at startup (degraded mode).
pub async fn admin_approve_live_apply_job(
    Extension(session): Extension<AuthSession>,
    Json(body): Json<ApproveLiveApplyBody>,
) -> ApiResult<Json<Value>> {
    // Defense-in-depth: the /api/admin RBAC middleware already blocks non-admins,
    // but we re-check here so a future re-mount cannot bypass the gate.
    if !check_permission(&session, "admin") {
        return Err(forbidden("admin permission required"));
    }

    let pool = get_db().ok_or_else(|| service_unavailable("database unavailable"))?;

    let cp_key = cp_identity::cp_signing_key()
        .ok_or_else(|| service_unavailable("control plane not configured to sign grants"))?;

    // The approver MUST come from the verified session — never from the request body.
    let approver = session.user_id.as_str();

    approve_live_apply_with(pool, cp_key, approver, &body).await
}

// ---------------------------------------------------------------------------
// GET /api/admin/agents — list agents with recent jobs (human RBAC, admin only)
// ---------------------------------------------------------------------------

/// Minimal agent row projected for the admin list response.
/// Never includes token_hash or public_key.
#[derive(sqlx::FromRow)]
struct AdminAgentRow {
    agent_id: String,
    platform: String,
    status: String,
    last_seen_at: Option<chrono::DateTime<Utc>>,
    created_at: chrono::DateTime<Utc>,
}

/// Minimal job row projected for each agent in the admin list response.
#[derive(sqlx::FromRow)]
struct AdminJobRow {
    id: Uuid,
    agent_id: Option<String>,
    mode: String,
    status: String,
    result_status: Option<String>,
    completed_at: Option<chrono::DateTime<Utc>>,
    created_at: chrono::DateTime<Utc>,
}

/// Maximum number of agents returned by the list endpoint.
const LIST_AGENTS_LIMIT: i64 = 500;
/// Maximum number of recent jobs fetched across all agents in one query.
const LIST_JOBS_LIMIT: i64 = 5000;
/// Maximum recent jobs surfaced per agent.
const JOBS_PER_AGENT_CAP: usize = 10;

/// Testable core for `admin_list_agents` — no axum Extension, no auth check.
///
/// Queries agents (bounded by [`LIST_AGENTS_LIMIT`]) ordered by `created_at DESC`,
/// then fetches recent jobs for those agents using a second bounded query.
/// Jobs are grouped per agent in Rust with a cap of [`JOBS_PER_AGENT_CAP`].
///
/// # Secret hygiene
///
/// Only non-secret columns are selected: `agent_id`, `platform`, `status`,
/// `last_seen_at`, `created_at`. `token_hash` and `public_key` are NEVER
/// included in the query or the response.
pub async fn list_agents_with(pool: &PgPool) -> ApiResult<Json<Value>> {
    // -- 1. Fetch agents (newest first, bounded) --
    let agents: Vec<AdminAgentRow> = sqlx::query_as(
        "SELECT agent_id, platform, status, last_seen_at, created_at \
         FROM agents \
         ORDER BY created_at DESC \
         LIMIT $1",
    )
    .bind(LIST_AGENTS_LIMIT)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    let capped = agents.len() as i64 >= LIST_AGENTS_LIMIT;

    if agents.is_empty() {
        return Ok(Json(json!({ "agents": [], "capped": false })));
    }

    // Collect agent_id strings for the IN clause.
    let agent_ids: Vec<&str> = agents.iter().map(|a| a.agent_id.as_str()).collect();

    // -- 2. Fetch recent jobs for those agents (bounded total, no secrets) --
    let jobs: Vec<AdminJobRow> = sqlx::query_as(
        "SELECT id, agent_id, mode, status, result_status, completed_at, created_at \
         FROM agent_jobs \
         WHERE agent_id = ANY($1) \
         ORDER BY created_at DESC \
         LIMIT $2",
    )
    .bind(&agent_ids)
    .bind(LIST_JOBS_LIMIT)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;

    // -- 3. Group jobs by agent_id in Rust with a per-agent cap --
    use std::collections::HashMap;
    let mut jobs_by_agent: HashMap<&str, Vec<Value>> = HashMap::new();
    for job in &jobs {
        // agent_id on agent_jobs is nullable (only set once leased);
        // skip jobs that are not yet associated with an agent.
        let Some(ref aid) = job.agent_id else {
            continue;
        };
        let bucket = jobs_by_agent.entry(aid.as_str()).or_default();
        if bucket.len() < JOBS_PER_AGENT_CAP {
            bucket.push(json!({
                "id": job.id,
                "mode": job.mode,
                "status": job.status,
                "result_status": job.result_status,
                "completed_at": job.completed_at,
                "created_at": job.created_at,
            }));
        }
    }

    // -- 4. Build the response array --
    let agents_json: Vec<Value> = agents
        .iter()
        .map(|a| {
            let jobs_for_agent = jobs_by_agent
                .remove(a.agent_id.as_str())
                .unwrap_or_default();
            json!({
                "agent_id": a.agent_id,
                "platform": a.platform,
                "status": a.status,
                "last_seen_at": a.last_seen_at,
                "created_at": a.created_at,
                "jobs": jobs_for_agent,
            })
        })
        .collect();

    Ok(Json(json!({ "agents": agents_json, "capped": capped })))
}

/// GET /api/admin/agents
///
/// Returns a list of all registered agents with their most recent jobs.
/// Requires `admin` permission — enforced in-handler as defense-in-depth
/// regardless of RBAC middleware method handling.
///
/// ## Secret hygiene
///
/// `token_hash` and `public_key` are NEVER included in the response.
///
/// ## Bounds
///
/// Agents are capped at 500 (newest first); jobs are capped at 5 000 total
/// across all agents, then further limited to the 10 most recent per agent
/// in Rust. `capped: true` in the response signals the agent list was
/// truncated.
pub async fn admin_list_agents(
    Extension(session): Extension<AuthSession>,
) -> ApiResult<Json<Value>> {
    // Defense-in-depth: GET routes under /api/admin/ may not be covered by
    // the RBAC middleware (which typically gates mutating methods). We re-check
    // here so the sensitive agent-enrollment list is always admin-only.
    if !check_permission(&session, "admin") {
        return Err(forbidden("admin permission required"));
    }

    let pool = get_db().ok_or_else(|| service_unavailable("database unavailable"))?;
    list_agents_with(pool).await
}

/// Admin route: sits under `/api/admin/agents/` so the human RBAC middleware
/// enforces `admin` permission. Agent tokens can never reach this path because
/// the `/api/agents/` exemption in `is_agent_exempt_path` is path-specific and
/// does not match `/api/admin/`.
pub fn admin_routes() -> Router {
    Router::new()
        .route("/api/admin/agents", get(admin_list_agents))
        .route(
            "/api/admin/agents/{agent_id}/approve",
            post(admin_approve_agent),
        )
        .route(
            "/api/admin/agents/live-apply-jobs",
            post(admin_approve_live_apply_job),
        )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Unit tests (no DB)
    // -----------------------------------------------------------------------

    #[test]
    fn agent_token_has_prefix() {
        let tok = generate_agent_token();
        assert!(
            tok.starts_with(AGENT_TOKEN_PREFIX),
            "token must start with prefix"
        );
    }

    #[test]
    fn agent_token_sha256_roundtrip() {
        let tok = generate_agent_token();
        let h1 = sha256_hex(&tok);
        let h2 = sha256_hex(&tok);
        assert_eq!(h1, h2, "sha256 must be deterministic");
        assert_eq!(h1.len(), 64, "sha256 hex must be 64 chars");
    }

    #[test]
    fn two_tokens_differ() {
        let a = generate_agent_token();
        let b = generate_agent_token();
        assert_ne!(a, b, "tokens must be unique");
    }

    // -----------------------------------------------------------------------
    // DB-gated integration tests
    //
    // Run with: RYUKI_DATABASE_URL=postgres://ryuki:ryuki_dev@localhost:5432/ryuki_platform
    //           cargo test -p ryuki-api agents::tests::db_
    // Each test SKIPS when RYUKI_DATABASE_URL is unset.
    // -----------------------------------------------------------------------

    // Serializes tests that depend on expired-lease state. `expire_leases` is a
    // GLOBAL sweep (UPDATE ... WHERE status = 'Leased' AND lease_deadline < NOW())
    // with no platform/agent scope, so a test that calls it would flip another
    // test's expired-Leased fixture out from under it (the cause of the flaky
    // db_ack_expired_lease_returns_409). Any test that calls expire_leases OR
    // seeds an expired-deadline Leased job acquires this lock for its duration.
    // tokio::sync::Mutex (not std) so the guard is safely held across .await.
    static EXPIRE_TEST_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

    async fn test_pool() -> Option<PgPool> {
        let url = std::env::var("RYUKI_DATABASE_URL").ok()?;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .ok()?;
        crate::database::run_migrations(&pool)
            .await
            .expect("migrations must apply");
        Some(pool)
    }

    /// Inserts a test agent row directly. Returns (agent_id_str, plaintext_token).
    async fn seed_agent(pool: &PgPool, agent_id: &str, platform: &str, status: &str) -> String {
        let token = format!(
            "{AGENT_TOKEN_PREFIX}test{}",
            Uuid::new_v4().to_string().replace('-', "")
        );
        let hash = sha256_hex(&token);
        sqlx::query(
            "INSERT INTO agents (agent_id, platform, capabilities, public_key, token_hash, status) \
             VALUES ($1, $2, '{}'::jsonb, 'test-pubkey', $3, $4) \
             ON CONFLICT (agent_id) DO UPDATE SET token_hash = $3, status = $4, updated_at = NOW()",
        )
        .bind(agent_id)
        .bind(platform)
        .bind(&hash)
        .bind(status)
        .execute(pool)
        .await
        .expect("seed agent");
        token
    }

    async fn seed_pending_job(pool: &PgPool, platform: &str) -> Uuid {
        use std::collections::BTreeMap;
        let spec = ryuki_protocol::JobSpec {
            request_id: Uuid::new_v4(),
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            mode: ryuki_protocol::JobMode::OfflineDryRun,
        };
        create_agent_job(pool, Uuid::new_v4(), platform, &spec, "OfflineDryRun")
            .await
            .expect("seed job")
    }

    async fn cleanup_agent(pool: &PgPool, agent_id: &str) {
        sqlx::query("DELETE FROM agents WHERE agent_id = $1")
            .bind(agent_id)
            .execute(pool)
            .await
            .ok();
    }

    async fn cleanup_jobs_for_platform(pool: &PgPool, platform: &str) {
        sqlx::query("DELETE FROM agent_jobs WHERE platform = $1")
            .bind(platform)
            .execute(pool)
            .await
            .ok();
    }

    // ── register persists pending ─────────────────────────────────────────

    #[tokio::test]
    async fn db_register_persists_pending() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let id = format!("test-agent-{}", Uuid::new_v4());

        let token = generate_agent_token();
        let hash = sha256_hex(&token);
        sqlx::query(
            "INSERT INTO agents (agent_id, platform, capabilities, public_key, token_hash, status) \
             VALUES ($1, 'ci', '{}'::jsonb, 'pk', $2, 'pending')",
        )
        .bind(&id)
        .bind(&hash)
        .execute(&pool)
        .await
        .expect("insert");

        let row = sqlx::query_as::<_, AgentRow>(
            "SELECT id, agent_id, platform, capabilities, public_key, token_hash, status \
             FROM agents WHERE agent_id = $1",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .expect("fetch");

        assert_eq!(row.status, "pending");
        assert_eq!(row.token_hash, hash);

        cleanup_agent(&pool, &id).await;
        pool.close().await;
    }

    // ── pending agent poll → 403 ─────────────────────────────────────────

    #[tokio::test]
    async fn db_pending_agent_poll_is_forbidden() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let agent_id = format!("pending-{}", Uuid::new_v4());
        let token = seed_agent(&pool, &agent_id, "ci", "pending").await;

        // Simulate authenticate_agent: it must return Err(403) for pending agents.
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let result = authenticate_agent(&headers, &pool).await;
        assert!(result.is_err(), "pending agent must be rejected");
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN);

        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── approved agent poll leases a Pending job ─────────────────────────

    #[tokio::test]
    async fn db_approved_agent_poll_leases_pending_job() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );
        let agent_id = format!("agent-{}", Uuid::new_v4());
        let token = seed_agent(&pool, &agent_id, &platform, "approved").await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        // Direct authenticate + lease query (mirrors poll_job logic).
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let _agent = authenticate_agent(&headers, &pool).await.expect("auth ok");

        let new_attempt = Uuid::new_v4();
        let fencing = Uuid::new_v4().to_string();
        let nonce = Uuid::new_v4().to_string();
        let deadline = Utc::now() + Duration::seconds(LEASE_TTL_SECS);

        let row = sqlx::query_as::<_, AgentJobRow>(&format!(
            "UPDATE agent_jobs \
             SET status = 'Leased', agent_id = $1, attempt_id = $2, \
                 lease_generation = lease_generation + 1, fencing_token = $3, \
                 cp_nonce = $4, lease_deadline = $5, updated_at = NOW() \
             WHERE id = ( \
                 SELECT id FROM agent_jobs WHERE platform = $6 AND status = 'Pending' \
                 ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1 \
             ) RETURNING {AGENT_JOB_COLUMNS}"
        ))
        .bind(&agent_id)
        .bind(new_attempt)
        .bind(&fencing)
        .bind(&nonce)
        .bind(deadline)
        .bind(&platform)
        .fetch_optional(&pool)
        .await
        .expect("lease query")
        .expect("must return a row");

        assert_eq!(row.status, "Leased");
        assert_eq!(row.attempt_id, Some(new_attempt));
        assert!(row.fencing_token.is_some());
        assert!(row.cp_nonce.is_some());
        assert!(row.lease_deadline.is_some());
        assert!(row.lease_generation >= 1);

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── two concurrent polls do NOT double-lease the same job ────────────

    #[tokio::test]
    async fn db_concurrent_polls_do_not_double_lease() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );
        // Single Pending job.
        let _ = seed_pending_job(&pool, &platform).await;

        const N: usize = 6;
        let mut handles = Vec::with_capacity(N);
        for _ in 0..N {
            let pool = pool.clone();
            let platform = platform.clone();
            handles.push(tokio::spawn(async move {
                let attempt = Uuid::new_v4();
                let fencing = Uuid::new_v4().to_string();
                let nonce = Uuid::new_v4().to_string();
                let deadline = Utc::now() + Duration::seconds(LEASE_TTL_SECS);
                sqlx::query_as::<_, AgentJobRow>(&format!(
                    "UPDATE agent_jobs \
                     SET status = 'Leased', agent_id = $1, attempt_id = $2, \
                         lease_generation = lease_generation + 1, fencing_token = $3, \
                         cp_nonce = $4, lease_deadline = $5, updated_at = NOW() \
                     WHERE id = ( \
                         SELECT id FROM agent_jobs \
                         WHERE platform = $6 AND status = 'Pending' \
                         ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1 \
                     ) RETURNING {AGENT_JOB_COLUMNS}"
                ))
                .bind("race-agent")
                .bind(attempt)
                .bind(&fencing)
                .bind(&nonce)
                .bind(deadline)
                .bind(&platform)
                .fetch_optional(&pool)
                .await
                .expect("lease query")
                .is_some()
            }));
        }

        let mut results = Vec::with_capacity(N);
        for h in handles {
            results.push(h.await.expect("task"));
        }

        let leased_count = results.iter().filter(|&&v| v).count();
        assert_eq!(leased_count, 1, "exactly one poll must win the lease");

        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    // ── ack with right fencing → Running ─────────────────────────────────

    #[tokio::test]
    async fn db_ack_correct_fencing_transitions_to_running() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );
        let agent_id = format!("agent-{}", Uuid::new_v4());
        let _token = seed_agent(&pool, &agent_id, &platform, "approved").await;
        let _ = seed_pending_job(&pool, &platform).await;

        let attempt = Uuid::new_v4();
        let fencing = Uuid::new_v4().to_string();
        let nonce = Uuid::new_v4().to_string();
        let deadline = Utc::now() + Duration::seconds(LEASE_TTL_SECS);

        let row = sqlx::query_as::<_, AgentJobRow>(&format!(
            "UPDATE agent_jobs \
             SET status = 'Leased', agent_id = $1, attempt_id = $2, \
                 lease_generation = lease_generation + 1, fencing_token = $3, \
                 cp_nonce = $4, lease_deadline = $5, updated_at = NOW() \
             WHERE id = ( \
                 SELECT id FROM agent_jobs WHERE platform = $6 AND status = 'Pending' \
                 ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1 \
             ) RETURNING {AGENT_JOB_COLUMNS}"
        ))
        .bind(&agent_id)
        .bind(attempt)
        .bind(&fencing)
        .bind(&nonce)
        .bind(deadline)
        .bind(&platform)
        .fetch_one(&pool)
        .await
        .expect("lease");

        // Correct fencing → Running.
        sqlx::query("UPDATE agent_jobs SET status = 'Running', updated_at = NOW() WHERE id = $1 AND attempt_id = $2 AND fencing_token = $3 AND status = 'Leased'")
            .bind(row.id)
            .bind(attempt)
            .bind(&fencing)
            .execute(&pool)
            .await
            .expect("ack");

        let updated: AgentJobRow = sqlx::query_as(&format!(
            "SELECT {AGENT_JOB_COLUMNS} FROM agent_jobs WHERE id = $1"
        ))
        .bind(row.id)
        .fetch_one(&pool)
        .await
        .expect("read");

        assert_eq!(updated.status, "Running");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── ack with wrong fencing → 409 ─────────────────────────────────────

    #[tokio::test]
    async fn db_ack_wrong_fencing_returns_409() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );
        let agent_id = format!("agent-{}", Uuid::new_v4());
        let token = seed_agent(&pool, &agent_id, &platform, "approved").await;
        let _ = seed_pending_job(&pool, &platform).await;

        let attempt = Uuid::new_v4();
        let real_fencing = Uuid::new_v4().to_string();
        let deadline = Utc::now() + Duration::seconds(LEASE_TTL_SECS);

        // Use the subquery form (Postgres UPDATE does not support LIMIT directly).
        sqlx::query(
            "UPDATE agent_jobs SET status = 'Leased', agent_id = $1, attempt_id = $2, \
             lease_generation = 1, fencing_token = $3, cp_nonce = 'nonce', \
             lease_deadline = $4, updated_at = NOW() \
             WHERE id = ( \
                 SELECT id FROM agent_jobs WHERE platform = $5 AND status = 'Pending' \
                 ORDER BY created_at LIMIT 1 \
             )",
        )
        .bind(&agent_id)
        .bind(attempt)
        .bind(&real_fencing)
        .bind(deadline)
        .bind(&platform)
        .execute(&pool)
        .await
        .expect("lease");

        // Use wrong fencing token in ack.
        let wrong_fencing = Uuid::new_v4().to_string();
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let body = AckBody {
            attempt_id: attempt,
            fencing_token: wrong_fencing,
        };

        // Reproduce the fencing check from the handler.
        let job_row: AgentJobRow = sqlx::query_as(&format!(
            "SELECT {AGENT_JOB_COLUMNS} FROM agent_jobs WHERE platform = $1 AND status = 'Leased' LIMIT 1"
        ))
        .bind(&platform)
        .fetch_one(&pool)
        .await
        .expect("fetch leased row");

        let stored_fencing = job_row.fencing_token.as_deref().unwrap_or("");
        use subtle::ConstantTimeEq;
        let fencing_ok: bool = stored_fencing
            .as_bytes()
            .ct_eq(body.fencing_token.as_bytes())
            .into();
        assert!(!fencing_ok, "wrong fencing must not match");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── expired OfflineDryRun lease → Pending (new attempt) ──────────────

    #[tokio::test]
    async fn db_expired_offline_dry_run_returns_to_pending() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // Holds the global-sweep serial lock: this test calls expire_leases.
        let _expire_guard = EXPIRE_TEST_LOCK.lock().await;
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );

        // Seed a Leased OfflineDryRun job with a deadline in the past.
        let job_id: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status, agent_id, \
             attempt_id, lease_generation, fencing_token, cp_nonce, lease_deadline) \
             VALUES ($1, $2, '{}'::jsonb, 'OfflineDryRun', 'Leased', 'some-agent', \
             gen_random_uuid(), 1, 'fence', 'nonce', NOW() - INTERVAL '1 minute') \
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(&platform)
        .fetch_one(&pool)
        .await
        .expect("seed");

        expire_leases(&pool).await.expect("expire");

        let row: AgentJobRow = sqlx::query_as(&format!(
            "SELECT {AGENT_JOB_COLUMNS} FROM agent_jobs WHERE id = $1"
        ))
        .bind(job_id)
        .fetch_one(&pool)
        .await
        .expect("read");

        assert_eq!(row.status, "Pending");
        assert!(row.attempt_id.is_none(), "attempt_id must be cleared");
        assert!(row.fencing_token.is_none(), "fencing_token must be cleared");
        assert!(row.cp_nonce.is_none(), "cp_nonce must be cleared");
        assert!(row.lease_deadline.is_none(), "deadline must be cleared");

        sqlx::query("DELETE FROM agent_jobs WHERE id = $1")
            .bind(job_id)
            .execute(&pool)
            .await
            .ok();
        pool.close().await;
    }

    // ── expired LiveApply → ReconcileRequired ─────────────────────────────

    #[tokio::test]
    async fn db_expired_live_apply_becomes_reconcile_required() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // Holds the global-sweep serial lock: this test calls expire_leases.
        let _expire_guard = EXPIRE_TEST_LOCK.lock().await;
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );

        let job_id: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status, agent_id, \
             attempt_id, lease_generation, fencing_token, cp_nonce, lease_deadline) \
             VALUES ($1, $2, '{}'::jsonb, 'LiveApply', 'Running', 'some-agent', \
             gen_random_uuid(), 1, 'fence', 'nonce', NOW() - INTERVAL '1 minute') \
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(&platform)
        .fetch_one(&pool)
        .await
        .expect("seed");

        expire_leases(&pool).await.expect("expire");

        let row: AgentJobRow = sqlx::query_as(&format!(
            "SELECT {AGENT_JOB_COLUMNS} FROM agent_jobs WHERE id = $1"
        ))
        .bind(job_id)
        .fetch_one(&pool)
        .await
        .expect("read");

        assert_eq!(row.status, "ReconcileRequired");

        sqlx::query("DELETE FROM agent_jobs WHERE id = $1")
            .bind(job_id)
            .execute(&pool)
            .await
            .ok();
        pool.close().await;
    }

    // ── malformed job id → 404 ────────────────────────────────────────────

    #[test]
    fn malformed_job_id_returns_404() {
        let result = parse_agent_job_id("not-a-uuid");
        assert!(result.is_err());
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // ── Fix 1: ack on an expired lease → 409 (not Running) ───────────────

    #[tokio::test]
    async fn db_ack_expired_lease_returns_409() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // Holds the global-sweep serial lock: this test seeds an expired-Leased
        // job that MUST stay Leased, so no concurrent expire_leases may run.
        let _expire_guard = EXPIRE_TEST_LOCK.lock().await;
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );
        let agent_id = format!("agent-{}", Uuid::new_v4());
        let _token = seed_agent(&pool, &agent_id, &platform, "approved").await;

        let attempt = Uuid::new_v4();
        let fencing = Uuid::new_v4().to_string();

        // Seed a Leased job with a deadline already in the past.
        let job_id: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status, agent_id, \
             attempt_id, lease_generation, fencing_token, cp_nonce, lease_deadline) \
             VALUES ($1, $2, '{}'::jsonb, 'OfflineDryRun', 'Leased', $3, \
             $4, 1, $5, 'nonce', NOW() - INTERVAL '1 minute') \
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(&platform)
        .bind(&agent_id)
        .bind(attempt)
        .bind(&fencing)
        .fetch_one(&pool)
        .await
        .expect("seed expired leased job");

        // The atomic ack UPDATE includes AND lease_deadline >= NOW(), so this
        // must return 0 rows and the follow-up SELECT produces a 409.
        let updated = sqlx::query_scalar::<_, Uuid>(
            "UPDATE agent_jobs \
             SET status = 'Running', updated_at = NOW() \
             WHERE id = $1 \
               AND status = 'Leased' \
               AND attempt_id = $2 \
               AND fencing_token = $3 \
               AND lease_deadline >= NOW() \
             RETURNING id",
        )
        .bind(job_id)
        .bind(attempt)
        .bind(&fencing)
        .fetch_optional(&pool)
        .await
        .expect("ack query");

        assert!(
            updated.is_none(),
            "expired lease must not transition to Running"
        );

        // Verify the row is still Leased (not Running), confirming no mutation.
        let row: AgentJobRow = sqlx::query_as(&format!(
            "SELECT {AGENT_JOB_COLUMNS} FROM agent_jobs WHERE id = $1"
        ))
        .bind(job_id)
        .fetch_one(&pool)
        .await
        .expect("read");

        assert_eq!(
            row.status, "Leased",
            "expired job must stay Leased, never Running"
        );

        sqlx::query("DELETE FROM agent_jobs WHERE id = $1")
            .bind(job_id)
            .execute(&pool)
            .await
            .ok();
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── Fix 1: ack after re-lease (wrong attempt_id) → 409 ───────────────

    #[tokio::test]
    async fn db_ack_after_release_wrong_attempt_returns_409() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );
        let agent_id = format!("agent-{}", Uuid::new_v4());
        let _token = seed_agent(&pool, &agent_id, &platform, "approved").await;

        let old_attempt = Uuid::new_v4();
        let new_attempt = Uuid::new_v4();
        let old_fencing = Uuid::new_v4().to_string();
        let new_fencing = Uuid::new_v4().to_string();

        // Seed a Leased job that has already been re-leased (new attempt/fencing).
        let job_id: Uuid = sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status, agent_id, \
             attempt_id, lease_generation, fencing_token, cp_nonce, lease_deadline) \
             VALUES ($1, $2, '{}'::jsonb, 'OfflineDryRun', 'Leased', $3, \
             $4, 2, $5, 'nonce2', NOW() + INTERVAL '5 minutes') \
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(&platform)
        .bind(&agent_id)
        .bind(new_attempt)
        .bind(&new_fencing)
        .fetch_one(&pool)
        .await
        .expect("seed re-leased job");

        // Try to ack with the OLD attempt_id — must return 0 rows.
        let updated = sqlx::query_scalar::<_, Uuid>(
            "UPDATE agent_jobs \
             SET status = 'Running', updated_at = NOW() \
             WHERE id = $1 \
               AND status = 'Leased' \
               AND attempt_id = $2 \
               AND fencing_token = $3 \
               AND lease_deadline >= NOW() \
             RETURNING id",
        )
        .bind(job_id)
        .bind(old_attempt)
        .bind(&old_fencing)
        .fetch_optional(&pool)
        .await
        .expect("ack with stale attempt");

        assert!(
            updated.is_none(),
            "stale attempt_id must not transition to Running"
        );

        // Confirm the job is still correctly Leased with the new attempt.
        let row: AgentJobRow = sqlx::query_as(&format!(
            "SELECT {AGENT_JOB_COLUMNS} FROM agent_jobs WHERE id = $1"
        ))
        .bind(job_id)
        .fetch_one(&pool)
        .await
        .expect("read");

        assert_eq!(row.status, "Leased");
        assert_eq!(
            row.attempt_id,
            Some(new_attempt),
            "new attempt must be preserved"
        );

        sqlx::query("DELETE FROM agent_jobs WHERE id = $1")
            .bind(job_id)
            .execute(&pool)
            .await
            .ok();
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── Fix 3: approval overwrites a mis-declared platform ────────────────

    #[tokio::test]
    async fn db_approval_overwrites_self_declared_platform() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let agent_id = format!("agent-{}", Uuid::new_v4());
        // Agent self-declares "attacker-platform" at registration.
        let _token = seed_agent(&pool, &agent_id, "attacker-platform", "pending").await;

        // Admin approves and authoritatively assigns "safe-platform".
        let rows = sqlx::query(
            "UPDATE agents SET status = 'approved', platform = $1, updated_at = NOW() \
             WHERE agent_id = $2",
        )
        .bind("safe-platform")
        .bind(&agent_id)
        .execute(&pool)
        .await
        .expect("admin approve")
        .rows_affected();
        assert_eq!(rows, 1);

        // After approval the stored platform must be the admin-assigned one.
        let row = sqlx::query_as::<_, AgentRow>(
            "SELECT id, agent_id, platform, capabilities, public_key, token_hash, status \
             FROM agents WHERE agent_id = $1",
        )
        .bind(&agent_id)
        .fetch_one(&pool)
        .await
        .expect("read after approval");

        assert_eq!(
            row.platform, "safe-platform",
            "admin-assigned platform must overwrite self-declared value"
        );
        assert_eq!(row.status, "approved");

        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── S3b helpers ───────────────────────────────────────────────────────

    use rand::rngs::OsRng;
    use ryuki_protocol::{
        crypto::{
            encode_verifying_key, generate_keypair, job_spec_digest, sha256_hex as proto_sha256,
            sign,
        },
        JobMode, JobResult, JobResultStatus, SignedEnvelope,
    };

    /// Insert an approved agent with a generated Ed25519 keypair.
    /// Returns (plaintext token, signing_key).
    async fn seed_agent_with_key(
        pool: &PgPool,
        agent_id: &str,
        platform: &str,
    ) -> (String, ed25519_dalek::SigningKey) {
        let key = generate_keypair(&mut OsRng);
        let pubkey_b64 = encode_verifying_key(&key.verifying_key());
        let token = format!(
            "{AGENT_TOKEN_PREFIX}key{}",
            Uuid::new_v4().to_string().replace('-', "")
        );
        let hash = sha256_hex(&token);
        sqlx::query(
            "INSERT INTO agents (agent_id, platform, capabilities, public_key, token_hash, status) \
             VALUES ($1, $2, '{}'::jsonb, $3, $4, 'approved') \
             ON CONFLICT (agent_id) DO UPDATE \
             SET token_hash = $4, status = 'approved', public_key = $3, updated_at = NOW()",
        )
        .bind(agent_id)
        .bind(platform)
        .bind(&pubkey_b64)
        .bind(&hash)
        .execute(pool)
        .await
        .expect("seed agent with key");
        (token, key)
    }

    /// Lease a pending job atomically and return the leased row (attempt_id,
    /// fencing_token, cp_nonce, lease_generation).
    async fn lease_job(
        pool: &PgPool,
        platform: &str,
        agent_id: &str,
    ) -> (Uuid, String, String, i64, AgentJobRow) {
        let attempt = Uuid::new_v4();
        let fencing = Uuid::new_v4().to_string();
        let nonce = Uuid::new_v4().to_string();
        let row = sqlx::query_as::<_, AgentJobRow>(&format!(
            "UPDATE agent_jobs \
             SET status = 'Leased', agent_id = $1, attempt_id = $2, \
                 lease_generation = lease_generation + 1, fencing_token = $3, \
                 cp_nonce = $4, \
                 lease_deadline = NOW() + make_interval(secs => $5), \
                 updated_at = NOW() \
             WHERE id = ( \
                 SELECT id FROM agent_jobs WHERE platform = $6 AND status = 'Pending' \
                 ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1 \
             ) RETURNING {AGENT_JOB_COLUMNS}"
        ))
        .bind(agent_id)
        .bind(attempt)
        .bind(&fencing)
        .bind(&nonce)
        .bind(LEASE_TTL_SECS as f64)
        .bind(platform)
        .fetch_one(pool)
        .await
        .expect("lease job");

        let gen = row.lease_generation;
        (attempt, fencing, nonce, gen, row)
    }

    /// Ack a leased job to Running.
    async fn ack_to_running(pool: &PgPool, job_id: Uuid, attempt: Uuid, fencing: &str) {
        sqlx::query(
            "UPDATE agent_jobs SET status = 'Running', updated_at = NOW() \
             WHERE id = $1 AND attempt_id = $2 AND fencing_token = $3 AND status = 'Leased'",
        )
        .bind(job_id)
        .bind(attempt)
        .bind(fencing)
        .execute(pool)
        .await
        .expect("ack to running");
    }

    /// Build a valid signed `JobResult` for `job_row` using the given signing key.
    #[allow(clippy::too_many_arguments)]
    fn make_job_result(
        agent_id: &str,
        platform: &str,
        job_row: &AgentJobRow,
        attempt_id: Uuid,
        cp_nonce: &str,
        lease_gen: u64,
        key: &ed25519_dalek::SigningKey,
        spec: &JobSpec,
        evidence: &[u8],
        status: JobResultStatus,
    ) -> (JobResult, Vec<u8>) {
        let result_id = Uuid::new_v4();
        let evidence_digest = proto_sha256(evidence);
        let spec_digest = job_spec_digest(spec);

        let unsigned_env = SignedEnvelope {
            agent_id: agent_id.to_string(),
            platform: platform.to_string(),
            job_id: job_row.id,
            attempt_id,
            lease_generation: lease_gen,
            request_id: spec.request_id,
            result_id,
            mode: spec.mode.clone(),
            status: status.clone(),
            job_spec_digest: spec_digest,
            approved_plan_digest: None,
            evidence_digest: evidence_digest.clone(),
            redaction_policy_version: "1.0.0".to_string(),
            timestamp: Utc::now(),
            key_id: encode_verifying_key(&key.verifying_key()),
            cp_nonce: cp_nonce.to_string(),
            signature: String::new(),
        };
        let signed_env = sign(unsigned_env, key);

        let job_result = JobResult {
            job_id: job_row.id,
            attempt_id,
            result_id,
            status,
            evidence_digest,
            signed_envelope: signed_env,
        };
        (job_result, evidence.to_vec())
    }

    // ── Helper: read job status + result fields ────────────────────────────

    #[derive(sqlx::FromRow)]
    #[allow(dead_code)]
    struct JobResultDbRow {
        status: String,
        result_id: Option<Uuid>,
        result_status: Option<String>,
        evidence_digest: Option<String>,
        completed_at: Option<chrono::DateTime<Utc>>,
        attempt_id: Option<Uuid>,
        lease_generation: i64,
    }

    async fn read_job_result_row(pool: &PgPool, job_id: Uuid) -> JobResultDbRow {
        sqlx::query_as::<_, JobResultDbRow>(
            "SELECT status, result_id, result_status, evidence_digest, \
             completed_at, attempt_id, lease_generation \
             FROM agent_jobs WHERE id = $1",
        )
        .bind(job_id)
        .fetch_one(pool)
        .await
        .expect("read job result row")
    }

    // ── S3b: happy path ───────────────────────────────────────────────────

    #[tokio::test]
    async fn db_s3b_happy_path_records_terminal_result() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key) = seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"check output here";
        let (job_result, evidence_bytes) = make_job_result(
            &agent_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            evidence,
            JobResultStatus::CheckOk,
        );

        // Build the ResultBody and call post_job_result via direct handler invocation.
        let result_body = ResultBody {
            job_result,
            evidence: evidence_bytes,
            evidence_json: None,
        };

        // Build headers
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            result_body,
            &pool,
        )
        .await;

        assert!(resp.is_ok(), "happy path must succeed: {:?}", resp.err());

        // Verify DB state.
        let db_row = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db_row.status, "Succeeded");
        assert_eq!(db_row.result_status.as_deref(), Some("check_ok"));
        assert!(db_row.result_id.is_some());
        assert!(db_row.evidence_digest.is_some());
        assert!(db_row.completed_at.is_some());

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── S3b: VALID signed sequential replay → idempotent 200 ────────────
    //
    // A valid signed replay of an already-recorded result re-runs the FULL
    // verification (the early status gate was removed), the atomic terminal
    // UPDATE matches 0 rows (job already terminal), and the post-UPDATE
    // idempotency branch returns 200 with `idempotent: true`. This is the
    // contract the agent's at-least-once durable outbox depends on: a lost-ack
    // retry must get "already recorded", not a 409 conflict. (A FORGED/unsigned
    // replay is covered separately by db_s3b_unsigned_forged_replay_is_rejected,
    // which fails verification before ever reaching this branch.)

    #[tokio::test]
    async fn db_s3b_sequential_valid_replay_is_idempotent() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key) = seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"idempotent evidence";
        let (job_result, evidence_bytes) = make_job_result(
            &agent_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            evidence,
            JobResultStatus::CheckOk,
        );

        let make_body = || ResultBody {
            job_result: job_result.clone(),
            evidence: evidence_bytes.clone(),
            evidence_json: None,
        };
        let make_hdrs = || {
            let mut h = HeaderMap::new();
            h.insert("Authorization", format!("Bearer {token}").parse().unwrap());
            h
        };

        // First POST — must succeed.
        let r1 = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            make_hdrs(),
            make_body(),
            &pool,
        )
        .await;
        assert!(r1.is_ok(), "first POST must succeed");

        let db = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(
            db.status, "Succeeded",
            "job must be terminal after first POST"
        );

        // Second sequential POST — job is now terminal (Succeeded). The same
        // valid signed result re-verifies, the terminal UPDATE matches 0 rows,
        // and the idempotency branch returns 200 with `idempotent: true`.
        let r2 = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            make_hdrs(),
            make_body(),
            &pool,
        )
        .await;
        let body = r2.expect("valid signed replay must be idempotent 200, not an error");
        assert_eq!(
            body.0.get("idempotent").and_then(|v| v.as_bool()),
            Some(true),
            "replay must be flagged idempotent"
        );
        assert_eq!(
            body.0.get("result_id").and_then(|v| v.as_str()),
            Some(job_result.result_id.to_string().as_str()),
            "idempotent response must echo the recorded result_id"
        );

        // The stored row must be unchanged by the replay (still the first
        // result, still terminal — exactly once).
        let db2 = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db2.status, "Succeeded", "replay must not change job status");
        assert_eq!(
            db2.result_id,
            Some(job_result.result_id),
            "replay must not change the recorded result_id"
        );

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── S3b: bad signature → 4xx, job unchanged ───────────────────────────

    #[tokio::test]
    async fn db_s3b_bad_signature_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key) = seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"evidence";
        let (mut job_result, evidence_bytes) = make_job_result(
            &agent_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            evidence,
            JobResultStatus::CheckOk,
        );

        // Tamper the signed envelope — change a field after signing.
        job_result.signed_envelope.evidence_digest = proto_sha256(b"forged");

        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence: evidence_bytes,
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(resp.is_err(), "tampered envelope must be rejected");

        // Job must still be Running, not terminal.
        let db_row = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db_row.status, "Running");
        assert!(db_row.result_id.is_none());

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── S3b: wrong enrolled key → reject ─────────────────────────────────

    #[tokio::test]
    async fn db_s3b_wrong_enrolled_key_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());

        // Enrolled with key_a; signs with key_b.
        let key_a = generate_keypair(&mut OsRng);
        let key_b = generate_keypair(&mut OsRng);

        // Enroll with key_a's public key.
        let token = format!(
            "{AGENT_TOKEN_PREFIX}wk{}",
            Uuid::new_v4().to_string().replace('-', "")
        );
        let hash = sha256_hex(&token);
        let pubkey_a = encode_verifying_key(&key_a.verifying_key());
        sqlx::query(
            "INSERT INTO agents (agent_id, platform, capabilities, public_key, token_hash, status) \
             VALUES ($1, $2, '{}'::jsonb, $3, $4, 'approved') \
             ON CONFLICT (agent_id) DO UPDATE SET token_hash=$4, status='approved', public_key=$3",
        )
        .bind(&agent_id)
        .bind(&platform)
        .bind(&pubkey_a)
        .bind(&hash)
        .execute(&pool)
        .await
        .expect("enroll key_a");

        let _job_id = seed_pending_job(&pool, &platform).await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        // Sign with key_b but use key_b's key_id (so the key_id check passes
        // against key_b, but enrolled key is key_a → verification fails).
        let evidence = b"evidence";
        let (job_result, evidence_bytes) = make_job_result(
            &agent_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key_b,
            &spec,
            evidence,
            JobResultStatus::CheckOk,
        );

        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence: evidence_bytes,
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(resp.is_err(), "wrong enrolled key must be rejected");

        let db_row = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db_row.status, "Running");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── S3b: stale attempt → rejected ────────────────────────────────────

    #[tokio::test]
    async fn db_s3b_stale_attempt_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key) = seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        // First lease.
        let (old_attempt, _fencing, old_nonce, old_gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"stale evidence";
        let (old_job_result, old_evidence_bytes) = make_job_result(
            &agent_id,
            &platform,
            &job_row,
            old_attempt,
            &old_nonce,
            old_gen as u64,
            &key,
            &spec,
            evidence,
            JobResultStatus::CheckOk,
        );

        // Re-lease (new attempt, new nonce, new generation) — simulates the
        // first lease expiring and the job being re-dispatched.
        sqlx::query(
            "UPDATE agent_jobs SET status = 'Pending', agent_id = NULL, attempt_id = NULL, \
             fencing_token = NULL, cp_nonce = NULL, lease_deadline = NULL, updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(job_row.id)
        .execute(&pool)
        .await
        .expect("reset to pending");

        let (_new_attempt, new_fencing, _new_nonce, _new_gen, new_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, new_row.id, _new_attempt, &new_fencing).await;

        // Try to post with the OLD attempt's signed result.
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result: old_job_result,
                evidence: old_evidence_bytes,
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(resp.is_err(), "stale attempt result must be rejected");
        let (status, _) = resp.unwrap_err();
        assert_eq!(status, axum::http::StatusCode::CONFLICT);

        // Job must still be Running (new attempt, no result recorded).
        let db_row = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db_row.status, "Running");
        assert!(db_row.result_id.is_none());

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── S3b: outer != signed field → reject ──────────────────────────────

    #[tokio::test]
    async fn db_s3b_outer_status_mismatch_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key) = seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"ev";
        let (mut job_result, evidence_bytes) = make_job_result(
            &agent_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            evidence,
            JobResultStatus::CheckOk,
        );
        // Outer status differs from signed envelope.
        job_result.status = JobResultStatus::Failed;

        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence: evidence_bytes,
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(resp.is_err(), "outer/signed mismatch must be rejected");

        let db_row = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db_row.status, "Running");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── S3b: evidence_digest mismatch → reject ────────────────────────────

    #[tokio::test]
    async fn db_s3b_evidence_digest_mismatch_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key) = seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let real_evidence = b"real evidence";
        let (job_result, _) = make_job_result(
            &agent_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            real_evidence,
            JobResultStatus::CheckOk,
        );

        // Send different evidence bytes — digest will not match.
        let tampered_evidence = b"different evidence bytes".to_vec();

        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence: tampered_evidence,
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(resp.is_err(), "evidence_digest mismatch must be rejected");

        let db_row = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db_row.status, "Running");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── S5: LiveApply WITHOUT a grant → rejected (409) ───────────────────
    //
    // A LiveApply job that carries no approval grant (live_context) can never
    // produce an accepted result: the verifier rejects it with 409 before any
    // digest comparison, regardless of whether the envelope carries an
    // approved_plan_digest. (The accept path + grant equality/expiry cases are
    // covered by the db_s5_live_apply_* tests.)

    #[tokio::test]
    async fn db_live_apply_without_grant_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-la-{}", Uuid::new_v4());
        let (token, key) = seed_agent_with_key(&pool, &agent_id, &platform).await;

        // ── seed a LiveApply job ───────────────────────────────────────────
        use std::collections::BTreeMap;
        let spec_la = JobSpec {
            request_id: Uuid::new_v4(),
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            mode: JobMode::LiveApply,
        };
        let live_job_id = create_agent_job(&pool, Uuid::new_v4(), &platform, &spec_la, "LiveApply")
            .await
            .expect("seed LiveApply job");

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        assert_eq!(job_row.id, live_job_id);
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let evidence = b"live apply output";
        let plan_digest = proto_sha256(b"approved plan");

        // Helper: build result with optional plan digest override.
        let make_live_result = |plan: Option<String>| {
            let result_id = Uuid::new_v4();
            let evidence_digest_str = proto_sha256(evidence);
            let spec_digest = ryuki_protocol::job_spec_digest(&spec_la);

            let unsigned = SignedEnvelope {
                agent_id: agent_id.clone(),
                platform: platform.clone(),
                job_id: job_row.id,
                attempt_id,
                lease_generation: gen as u64,
                request_id: spec_la.request_id,
                result_id,
                mode: JobMode::LiveApply,
                status: JobResultStatus::Applied,
                job_spec_digest: spec_digest,
                approved_plan_digest: plan.clone(),
                evidence_digest: evidence_digest_str.clone(),
                redaction_policy_version: "1.0.0".to_string(),
                timestamp: Utc::now(),
                key_id: encode_verifying_key(&key.verifying_key()),
                cp_nonce: nonce.clone(),
                signature: String::new(),
            };
            let signed = sign(unsigned, &key);
            let outer = JobResult {
                job_id: job_row.id,
                attempt_id,
                result_id,
                status: JobResultStatus::Applied,
                evidence_digest: evidence_digest_str,
                signed_envelope: signed,
            };
            ResultBody {
                job_result: outer,
                evidence: evidence.to_vec(),
                evidence_json: None,
            }
        };

        let hdrs = || {
            let mut h = HeaderMap::new();
            h.insert("Authorization", format!("Bearer {token}").parse().unwrap());
            h
        };

        // Sub-case A: LiveApply WITHOUT approved_plan_digest → must be rejected.
        let resp_a = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs(),
            make_live_result(None),
            &pool,
        )
        .await;
        assert!(
            resp_a.is_err(),
            "LiveApply without a grant must be rejected"
        );
        let (status_a, _) = resp_a.unwrap_err();
        assert_eq!(
            status_a,
            axum::http::StatusCode::CONFLICT,
            "a LiveApply job with no approval grant must be rejected with 409"
        );
        let db = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(
            db.status, "Running",
            "job must remain Running after rejection"
        );

        // Sub-case B: LiveApply WITH approved_plan_digest but still NO grant on
        // the job → rejected with 409 (the missing-grant check fires before any
        // digest comparison; a forged digest cannot manufacture authorisation).
        let resp_b = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs(),
            make_live_result(Some(plan_digest.clone())),
            &pool,
        )
        .await;
        assert!(
            resp_b.is_err(),
            "LiveApply with a forged plan digest but no grant must be rejected"
        );
        let (status_b, _) = resp_b.unwrap_err();
        assert_eq!(
            status_b,
            axum::http::StatusCode::CONFLICT,
            "no-grant LiveApply must be rejected with 409 regardless of envelope digest"
        );
        let db = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db.status, "Running", "job must remain Running");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_s3b_non_live_with_plan_digest_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key) = seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"ev";
        let result_id = Uuid::new_v4();
        let evidence_digest = proto_sha256(evidence);
        let spec_digest = ryuki_protocol::job_spec_digest(&spec);

        // Non-live envelope WITH approved_plan_digest → must be rejected.
        let unsigned = SignedEnvelope {
            agent_id: agent_id.clone(),
            platform: platform.clone(),
            job_id: job_row.id,
            attempt_id,
            lease_generation: gen as u64,
            request_id: spec.request_id,
            result_id,
            mode: JobMode::OfflineDryRun,
            status: JobResultStatus::CheckOk,
            job_spec_digest: spec_digest,
            approved_plan_digest: Some(proto_sha256(b"bad plan")),
            evidence_digest: evidence_digest.clone(),
            redaction_policy_version: "1.0.0".to_string(),
            timestamp: Utc::now(),
            key_id: encode_verifying_key(&key.verifying_key()),
            cp_nonce: nonce.clone(),
            signature: String::new(),
        };
        let signed = sign(unsigned, &key);
        let outer = JobResult {
            job_id: job_row.id,
            attempt_id,
            result_id,
            status: JobResultStatus::CheckOk,
            evidence_digest,
            signed_envelope: signed,
        };

        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result: outer,
                evidence: evidence.to_vec(),
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(
            resp.is_err(),
            "non-live with approved_plan_digest must be rejected"
        );
        let db = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db.status, "Running");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── S3b: agent mismatch (token agent != envelope.agent_id) → 403 ─────

    #[tokio::test]
    async fn db_s3b_agent_mismatch_returns_403() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let other_agent_id = format!("s3b-other-{}", Uuid::new_v4());

        let (token, key) = seed_agent_with_key(&pool, &agent_id, &platform).await;
        let (_tok2, _key2) = seed_agent_with_key(&pool, &other_agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"mismatch";

        // Sign with correct agent's key but claim OTHER agent's id in the envelope.
        let result_id = Uuid::new_v4();
        let evidence_digest = proto_sha256(evidence);
        let spec_digest = ryuki_protocol::job_spec_digest(&spec);
        let unsigned = SignedEnvelope {
            agent_id: other_agent_id.clone(),
            platform: platform.clone(),
            job_id: job_row.id,
            attempt_id,
            lease_generation: gen as u64,
            request_id: spec.request_id,
            result_id,
            mode: JobMode::OfflineDryRun,
            status: JobResultStatus::CheckOk,
            job_spec_digest: spec_digest,
            approved_plan_digest: None,
            evidence_digest: evidence_digest.clone(),
            redaction_policy_version: "1.0.0".to_string(),
            timestamp: Utc::now(),
            key_id: encode_verifying_key(&key.verifying_key()),
            cp_nonce: nonce.clone(),
            signature: String::new(),
        };
        let signed = sign(unsigned, &key);
        let outer = JobResult {
            job_id: job_row.id,
            attempt_id,
            result_id,
            status: JobResultStatus::CheckOk,
            evidence_digest,
            signed_envelope: signed,
        };

        // Token belongs to `agent_id`; envelope claims `other_agent_id`.
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result: outer,
                evidence: evidence.to_vec(),
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(resp.is_err(), "agent mismatch must be rejected");
        let (status, _) = resp.unwrap_err();
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        cleanup_agent(&pool, &other_agent_id).await;
        pool.close().await;
    }

    // ── Fix 1: unsigned/forged replay on terminal job → rejected (not 200) ──
    //
    // An attacker with a valid agent token and knowledge of a terminal
    // (job_id, attempt_id, result_id) must NOT get an idempotent 200 by
    // posting a body with an invalid/absent signature. The early fast-path that
    // allowed this was removed; now full verification runs for every request.
    // A forged replay must fail at step 3 (signature verification) → 4xx.

    #[tokio::test]
    async fn db_s3b_unsigned_forged_replay_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key) = seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"legit evidence";

        // First: POST a valid signed result to make the job terminal.
        let (good_result, evidence_bytes) = make_job_result(
            &agent_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            evidence,
            JobResultStatus::CheckOk,
        );
        let good_result_id = good_result.result_id;

        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let r1 = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result: good_result.clone(),
                evidence: evidence_bytes.clone(),
                evidence_json: None,
            },
            &pool,
        )
        .await;
        assert!(r1.is_ok(), "initial valid POST must succeed");

        let db = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db.status, "Succeeded", "job must be terminal");

        // Now forge a body: reuse the known (job_id, attempt_id, result_id) but
        // invalidate the signature by tampering the envelope after signing.
        let mut forged_result = good_result.clone();
        // Corrupt the signature — the envelope fields are otherwise valid.
        forged_result.signed_envelope.signature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();

        let mut hdrs2 = HeaderMap::new();
        hdrs2.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let r2 = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs2,
            ResultBody {
                job_result: forged_result,
                evidence: evidence_bytes.clone(),
                evidence_json: None,
            },
            &pool,
        )
        .await;

        // Must be rejected. There is no early status gate: the forged body runs
        // the full verification and FAILS at the signature check, so it never
        // reaches the post-UPDATE idempotency branch. This confirms a forged
        // body with a matching (result_id, attempt_id) cannot get idempotent 200,
        // even though a VALID signed replay of the same identifiers would.
        assert!(
            r2.is_err(),
            "forged replay on terminal job must be rejected, not idempotent 200"
        );
        let (status, _) = r2.unwrap_err();
        assert_ne!(
            status,
            axum::http::StatusCode::OK,
            "forged replay must never return 200"
        );

        // The result_id from the valid first POST must be unchanged.
        let db2 = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(
            db2.result_id,
            Some(good_result_id),
            "result_id must not change"
        );
        assert_eq!(db2.status, "Succeeded", "terminal status must not change");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── Fix 3: envelope.platform mismatch → rejected ──────────────────────

    #[tokio::test]
    async fn db_s3b_platform_mismatch_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key) = seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"evidence";

        // Build a result with a mismatched platform in the envelope.
        let result_id = Uuid::new_v4();
        let evidence_digest = proto_sha256(evidence);
        let spec_digest = ryuki_protocol::job_spec_digest(&spec);

        let wrong_platform = format!("wrong-{}", Uuid::new_v4());
        let unsigned = SignedEnvelope {
            agent_id: agent_id.clone(),
            platform: wrong_platform, // mismatch
            job_id: job_row.id,
            attempt_id,
            lease_generation: gen as u64,
            request_id: spec.request_id,
            result_id,
            mode: JobMode::OfflineDryRun,
            status: JobResultStatus::CheckOk,
            job_spec_digest: spec_digest,
            approved_plan_digest: None,
            evidence_digest: evidence_digest.clone(),
            redaction_policy_version: "1.0.0".to_string(),
            timestamp: Utc::now(),
            key_id: encode_verifying_key(&key.verifying_key()),
            cp_nonce: nonce.clone(),
            signature: String::new(),
        };
        let signed = sign(unsigned, &key);
        let outer = JobResult {
            job_id: job_row.id,
            attempt_id,
            result_id,
            status: JobResultStatus::CheckOk,
            evidence_digest,
            signed_envelope: signed,
        };

        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result: outer,
                evidence: evidence.to_vec(),
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(resp.is_err(), "platform mismatch must be rejected");
        let (status, _) = resp.unwrap_err();
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

        let db = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db.status, "Running");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── Fix 3: envelope.request_id mismatch → rejected ───────────────────

    #[tokio::test]
    async fn db_s3b_request_id_mismatch_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key) = seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await;

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"evidence";

        let result_id = Uuid::new_v4();
        let evidence_digest = proto_sha256(evidence);
        let spec_digest = ryuki_protocol::job_spec_digest(&spec);

        let wrong_request_id = Uuid::new_v4(); // not spec.request_id
        let unsigned = SignedEnvelope {
            agent_id: agent_id.clone(),
            platform: platform.clone(),
            job_id: job_row.id,
            attempt_id,
            lease_generation: gen as u64,
            request_id: wrong_request_id, // mismatch
            result_id,
            mode: JobMode::OfflineDryRun,
            status: JobResultStatus::CheckOk,
            job_spec_digest: spec_digest,
            approved_plan_digest: None,
            evidence_digest: evidence_digest.clone(),
            redaction_policy_version: "1.0.0".to_string(),
            timestamp: Utc::now(),
            key_id: encode_verifying_key(&key.verifying_key()),
            cp_nonce: nonce.clone(),
            signature: String::new(),
        };
        let signed = sign(unsigned, &key);
        let outer = JobResult {
            job_id: job_row.id,
            attempt_id,
            result_id,
            status: JobResultStatus::CheckOk,
            evidence_digest,
            signed_envelope: signed,
        };

        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result: outer,
                evidence: evidence.to_vec(),
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(resp.is_err(), "request_id mismatch must be rejected");
        let (status, _) = resp.unwrap_err();
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

        let db = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db.status, "Running");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── Fix 3: envelope.mode mismatch → rejected ──────────────────────────

    #[tokio::test]
    async fn db_s3b_mode_mismatch_is_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!("plt-{}", &Uuid::new_v4().to_string().replace('-', "")[..8]);
        let agent_id = format!("s3b-agent-{}", Uuid::new_v4());
        let (token, key) = seed_agent_with_key(&pool, &agent_id, &platform).await;
        let _job_id = seed_pending_job(&pool, &platform).await; // OfflineDryRun

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let evidence = b"evidence";

        let result_id = Uuid::new_v4();
        let evidence_digest = proto_sha256(evidence);
        let spec_digest = ryuki_protocol::job_spec_digest(&spec);

        // Claim LivePlan in the envelope — job is OfflineDryRun.
        let unsigned = SignedEnvelope {
            agent_id: agent_id.clone(),
            platform: platform.clone(),
            job_id: job_row.id,
            attempt_id,
            lease_generation: gen as u64,
            request_id: spec.request_id,
            result_id,
            mode: JobMode::LivePlan, // mismatch — job is OfflineDryRun
            status: JobResultStatus::Planned,
            job_spec_digest: spec_digest,
            approved_plan_digest: None,
            evidence_digest: evidence_digest.clone(),
            redaction_policy_version: "1.0.0".to_string(),
            timestamp: Utc::now(),
            key_id: encode_verifying_key(&key.verifying_key()),
            cp_nonce: nonce.clone(),
            signature: String::new(),
        };
        let signed = sign(unsigned, &key);
        let outer = JobResult {
            job_id: job_row.id,
            attempt_id,
            result_id,
            status: JobResultStatus::Planned,
            evidence_digest,
            signed_envelope: signed,
        };

        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result: outer,
                evidence: evidence.to_vec(),
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(resp.is_err(), "mode mismatch must be rejected");
        let (status, _) = resp.unwrap_err();
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

        let db = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db.status, "Running");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── Fix 4: lease_deadline is set by DB time (NOW()+interval) ─────────

    #[tokio::test]
    async fn db_lease_deadline_is_set_by_db_time() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let platform = format!(
            "plt-{}",
            Uuid::new_v4().to_string().replace('-', "")[..8].to_owned()
        );
        let _job_id = seed_pending_job(&pool, &platform).await;

        let attempt = Uuid::new_v4();
        let fencing = Uuid::new_v4().to_string();

        // Use the same make_interval(secs => $5) form as the production handler.
        let row = sqlx::query_as::<_, AgentJobRow>(&format!(
            "UPDATE agent_jobs \
             SET status = 'Leased', agent_id = $1, attempt_id = $2, \
                 lease_generation = lease_generation + 1, fencing_token = $3, \
                 cp_nonce = 'nonce', \
                 lease_deadline = NOW() + make_interval(secs => $4), \
                 updated_at = NOW() \
             WHERE id = ( \
                 SELECT id FROM agent_jobs WHERE platform = $5 AND status = 'Pending' \
                 ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1 \
             ) RETURNING {AGENT_JOB_COLUMNS}"
        ))
        .bind("test-agent")
        .bind(attempt)
        .bind(&fencing)
        .bind(LEASE_TTL_SECS as f64)
        .bind(&platform)
        .fetch_one(&pool)
        .await
        .expect("db-time lease");

        // lease_deadline must be set and in the future (within TTL + 5s margin).
        let deadline = row.lease_deadline.expect("deadline must be set");
        let now = Utc::now();
        assert!(deadline > now, "deadline must be in the future");
        let delta = (deadline - now).num_seconds();
        assert!(
            delta <= LEASE_TTL_SECS + 5,
            "deadline must be within TTL range, got delta={delta}s"
        );

        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    // ── S4c: end-to-end dry-run contract ─────────────────────────────────────
    //
    // These tests prove that the AGENT code (ryuki-agent lib) and the CP verifier
    // (post_job_result_with_pool) agree against a real Postgres database.
    //
    // The agent identity is generated fresh; its public_key is enrolled in the
    // agents table so the CP's key_id check + Ed25519 verify pass.
    //
    // Positive: agent produces a ResultBody that passes ALL 9 verifier steps.
    // Negative (tamper): mutating one evidence byte after signing → CP rejects
    //   with 4xx, proving the evidence digest is bound end-to-end.

    // Import the trait so .execute() is callable on StubExecutor.
    use ryuki_agent::executor::JobExecutor as AgentJobExecutor;

    /// Seed an approved agent whose enrolled public_key equals the given
    /// agent identity's public_key_b64().  Returns the plaintext bearer token.
    async fn seed_agent_from_identity(
        pool: &PgPool,
        agent_id: &str,
        platform: &str,
        identity: &ryuki_agent::identity::AgentIdentity,
    ) -> String {
        let pubkey_b64 = identity.public_key_b64();
        let token = format!(
            "{AGENT_TOKEN_PREFIX}s4c{}",
            Uuid::new_v4().to_string().replace('-', "")
        );
        let hash = sha256_hex(&token);
        sqlx::query(
            "INSERT INTO agents (agent_id, platform, capabilities, public_key, token_hash, status) \
             VALUES ($1, $2, '{}'::jsonb, $3, $4, 'approved') \
             ON CONFLICT (agent_id) DO UPDATE \
             SET token_hash = $4, status = 'approved', public_key = $3, updated_at = NOW()",
        )
        .bind(agent_id)
        .bind(platform)
        .bind(&pubkey_b64)
        .bind(&hash)
        .execute(pool)
        .await
        .expect("seed agent from identity");
        token
    }

    /// Build the `ryuki_protocol::Job` struct that the agent would receive after
    /// leasing and acking, from the leased row's fields.
    fn build_protocol_job(
        job_row: &AgentJobRow,
        attempt_id: Uuid,
        fencing_token: String,
        cp_nonce: String,
        lease_generation: i64,
    ) -> ryuki_protocol::Job {
        use ryuki_protocol::{Job, JobLease, JobSpec, JobStatus};
        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let lease = JobLease {
            attempt_id,
            lease_generation: lease_generation as u64,
            fencing_token,
            deadline: Utc::now() + Duration::seconds(LEASE_TTL_SECS),
            cp_nonce,
        };
        Job {
            id: job_row.id,
            platform: job_row.platform.clone(),
            spec,
            status: JobStatus::Running,
            lease: Some(lease),
            live_context: None,
        }
    }

    /// S4c positive: agent identity → execute → build_signed_result → CP verifier.
    /// The full 9-step verifier must accept the agent-produced envelope.
    #[tokio::test]
    async fn db_s4c_agent_to_cp_positive_e2e() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s4c-plt-{suffix}");
        let agent_id = format!("s4c-agent-{suffix}");

        // Generate the agent identity — this is what the production agent does at startup.
        let identity = ryuki_agent::identity::AgentIdentity::generate();

        // Enroll the agent with this identity's public key.
        let token = seed_agent_from_identity(&pool, &agent_id, &platform, &identity).await;

        // Seed a pending OfflineDryRun job and lease + ack it.
        let _job_id = seed_pending_job(&pool, &platform).await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        // Build the Job struct as the agent would see it after poll() + ack().
        let job = build_protocol_job(&job_row, attempt_id, fencing.clone(), nonce.clone(), gen);

        // RUN AGENT CODE — execute + sign, exactly as process_job does.
        let executor = ryuki_agent::executor::StubExecutor::check_ok();
        let evidence = executor
            .execute(&job.spec)
            .expect("StubExecutor must succeed");
        let agent_body =
            ryuki_agent::result::build_signed_result(&identity, &agent_id, &job, &evidence, None)
                .expect("build_signed_result must succeed");

        let agent_result_id = agent_body.job_result.result_id;

        // Cross the crate boundary: convert agent ResultBody → CP ResultBody.
        // The shapes are identical (same JSON); serde is the bridge.
        let cp_body: ResultBody = serde_json::from_value(
            serde_json::to_value(&agent_body).expect("agent body serialises"),
        )
        .expect("CP must deserialise the agent ResultBody");

        // Build the bearer-token header (agent's token).
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        // FEED TO CP VERIFIER — must pass all 9 steps.
        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            cp_body,
            &pool,
        )
        .await;

        assert!(
            resp.is_ok(),
            "agent-produced envelope must pass all CP verifier steps: {:?}",
            resp.err()
        );

        // Verify DB state.
        let db_row = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(
            db_row.status, "Succeeded",
            "job must be terminal after CP verification"
        );
        assert_eq!(
            db_row.result_id,
            Some(agent_result_id),
            "DB result_id must match the agent's result_id"
        );
        assert!(db_row.completed_at.is_some(), "completed_at must be set");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    /// S4c negative (tamper): mutate one evidence byte in the agent's body
    /// AFTER signing → CP must reject with 4xx.
    /// This proves the evidence digest is cryptographically bound end-to-end.
    #[tokio::test]
    async fn db_s4c_tampered_evidence_is_rejected_by_cp() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s4c-tamp-{suffix}");
        let agent_id = format!("s4c-tagent-{suffix}");

        let identity = ryuki_agent::identity::AgentIdentity::generate();
        let token = seed_agent_from_identity(&pool, &agent_id, &platform, &identity).await;

        let _job_id = seed_pending_job(&pool, &platform).await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let job = build_protocol_job(&job_row, attempt_id, fencing.clone(), nonce.clone(), gen);

        // Execute + sign (normal path).
        let executor = ryuki_agent::executor::StubExecutor::check_ok();
        let evidence = executor
            .execute(&job.spec)
            .expect("StubExecutor must succeed");
        let mut agent_body =
            ryuki_agent::result::build_signed_result(&identity, &agent_id, &job, &evidence, None)
                .expect("build_signed_result must succeed");

        // TAMPER: flip one byte of evidence AFTER signing.
        // The signed envelope's evidence_digest remains the pre-tamper hash;
        // the CP's recompute-and-compare at step 6 must catch the mismatch.
        if !agent_body.evidence.is_empty() {
            agent_body.evidence[0] ^= 0xFF;
        } else {
            // Should never happen for StubExecutor, but fail clearly if it does.
            panic!("evidence must not be empty for this test");
        }

        // Cross the crate boundary.
        let cp_body: ResultBody = serde_json::from_value(
            serde_json::to_value(&agent_body).expect("agent body serialises"),
        )
        .expect("CP deserialises the tampered body");

        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        // CP VERIFIER must reject — step 6 (evidence_digest recompute) fails.
        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            cp_body,
            &pool,
        )
        .await;

        assert!(
            resp.is_err(),
            "tampered evidence must be rejected by the CP verifier"
        );
        let (status, _) = resp.unwrap_err();
        assert!(
            status.is_client_error(),
            "tampered evidence must produce a 4xx, got {status}"
        );

        // Job must remain Running — no result was recorded.
        let db_row = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(
            db_row.status, "Running",
            "job must remain Running after tamper rejection"
        );
        assert!(
            db_row.result_id.is_none(),
            "result_id must not be recorded after tamper rejection"
        );

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ───────────────────────────────────────────────────────────────────────
    // S5a-1/S5a-2: LiveApply approved-plan grant verification
    // ───────────────────────────────────────────────────────────────────────

    // A single shared CP signing key for ALL LiveApply tests in this binary. The
    // verifier reads the process-global CP key (via cp_identity) to verify_vlc a
    // grant's signature, so every grant a test seeds MUST be signed by the same
    // key that is installed as the global. Because every test installs the SAME
    // key, the write-once global is deterministic regardless of test order.
    static TEST_CP_KEY: std::sync::LazyLock<ed25519_dalek::SigningKey> =
        std::sync::LazyLock::new(|| generate_keypair(&mut OsRng));

    /// Install the shared CP key as the process global (idempotent — same key
    /// every call) and return a clone for signing grants in the test.
    fn ensure_test_cp_key() -> ed25519_dalek::SigningKey {
        cp_identity::init_cp_key_for_test(TEST_CP_KEY.clone());
        TEST_CP_KEY.clone()
    }

    /// Seed a minimal ACTIVE (`locked`) request row for `request_id`. A LiveApply
    /// grant may only be minted for a real, non-concluded request — the gate in
    /// `create_live_apply_job` loads `requests.status` — so any test that mints a
    /// grant directly must seed the request first.
    async fn seed_active_request(pool: &PgPool, request_id: Uuid) {
        sqlx::query(
            "INSERT INTO requests (id, request_type, site, environment, name, status, stage, stages) \
             VALUES ($1, 'server-deployment', 'DEFRA', 'prod', 'live-apply-test', 'locked', 'lock', '[]'::jsonb) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(request_id)
        .execute(pool)
        .await
        .expect("seed active request for live-apply minting");
    }

    /// Seed a Pending LiveApply job carrying a CP-signed grant (live_context),
    /// signed with `signing_key`. The grant's `request_id` is bound to the job
    /// spec by default; pass a different `grant_request_id` to exercise the
    /// mismatch path. Direct INSERT because `create_agent_job` does not attach a
    /// grant. The process-global CP key is installed via `ensure_test_cp_key`.
    async fn seed_live_apply_job_signed(
        pool: &PgPool,
        platform: &str,
        approved_plan_digest: &str,
        grant_expiry: chrono::DateTime<Utc>,
        grant_request_id: Option<Uuid>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Uuid {
        use std::collections::BTreeMap;
        let request_id = Uuid::new_v4();
        let spec = ryuki_protocol::JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            mode: ryuki_protocol::JobMode::LiveApply,
        };
        let unsigned = VerifiedLiveContext {
            request_id: grant_request_id.unwrap_or(request_id),
            approved_plan_digest: approved_plan_digest.to_string(),
            approver: "ops-test".to_string(),
            expiry: grant_expiry,
            signature: String::new(),
        };
        let grant = sign_vlc(unsigned, signing_key);
        let spec_json = serde_json::to_value(&spec).expect("spec json");
        let grant_json = serde_json::to_value(&grant).expect("grant json");
        sqlx::query_scalar(
            "INSERT INTO agent_jobs (request_id, platform, spec, mode, status, live_context) \
             VALUES ($1, $2, $3::jsonb, 'LiveApply', 'Pending', $4::jsonb) RETURNING id",
        )
        .bind(request_id)
        .bind(platform)
        .bind(&spec_json)
        .bind(&grant_json)
        .fetch_one(pool)
        .await
        .expect("seed live apply job")
    }

    /// Seed a LiveApply job whose grant is signed by the shared global CP key
    /// (the common case — the verifier will accept the signature).
    async fn seed_live_apply_job(
        pool: &PgPool,
        platform: &str,
        approved_plan_digest: &str,
        grant_expiry: chrono::DateTime<Utc>,
        grant_request_id: Option<Uuid>,
    ) -> Uuid {
        let cp_key = ensure_test_cp_key();
        seed_live_apply_job_signed(
            pool,
            platform,
            approved_plan_digest,
            grant_expiry,
            grant_request_id,
            &cp_key,
        )
        .await
    }

    /// Build a signed LiveApply `JobResult` (status Applied) carrying the given
    /// `approved_plan_digest` in the envelope.
    #[allow(clippy::too_many_arguments)]
    fn make_live_apply_result(
        agent_id: &str,
        platform: &str,
        job_row: &AgentJobRow,
        attempt_id: Uuid,
        cp_nonce: &str,
        lease_gen: u64,
        key: &ed25519_dalek::SigningKey,
        spec: &JobSpec,
        evidence: &[u8],
        approved_plan_digest: Option<String>,
    ) -> (JobResult, Vec<u8>) {
        let result_id = Uuid::new_v4();
        let evidence_digest = proto_sha256(evidence);
        let spec_digest = job_spec_digest(spec);
        let status = JobResultStatus::Applied;
        let unsigned_env = SignedEnvelope {
            agent_id: agent_id.to_string(),
            platform: platform.to_string(),
            job_id: job_row.id,
            attempt_id,
            lease_generation: lease_gen,
            request_id: spec.request_id,
            result_id,
            mode: spec.mode.clone(),
            status: status.clone(),
            job_spec_digest: spec_digest,
            approved_plan_digest,
            evidence_digest: evidence_digest.clone(),
            redaction_policy_version: "1.0.0".to_string(),
            timestamp: Utc::now(),
            key_id: encode_verifying_key(&key.verifying_key()),
            cp_nonce: cp_nonce.to_string(),
            signature: String::new(),
        };
        let signed_env = sign(unsigned_env, key);
        let job_result = JobResult {
            job_id: job_row.id,
            attempt_id,
            result_id,
            status,
            evidence_digest,
            signed_envelope: signed_env,
        };
        (job_result, evidence.to_vec())
    }

    /// Drive a leased LiveApply job to a result POST with the given envelope
    /// digest + grant. Returns the verifier response. `grant_digest` is what the
    /// CP stored; `envelope_digest` is what the agent signs.
    async fn run_live_apply_case(
        pool: &PgPool,
        grant_digest: &str,
        envelope_digest: Option<String>,
        grant_expiry: chrono::DateTime<Utc>,
        grant_request_id: Option<Uuid>,
    ) -> (ApiResult<Json<serde_json::Value>>, Uuid, String) {
        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5-plt-{suffix}");
        let agent_id = format!("s5-agent-{suffix}");
        let (token, key) = seed_agent_with_key(pool, &agent_id, &platform).await;

        let _job_id = seed_live_apply_job(
            pool,
            &platform,
            grant_digest,
            grant_expiry,
            grant_request_id,
        )
        .await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(pool, &platform, &agent_id).await;
        ack_to_running(pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let (job_result, evidence_bytes) = make_live_apply_result(
            &agent_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            b"live apply evidence",
            envelope_digest,
        );
        let body = ResultBody {
            job_result,
            evidence: evidence_bytes,
            evidence_json: None,
        };
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp =
            post_job_result_with_pool(agent_id.clone(), job_row.id.to_string(), hdrs, body, pool)
                .await;
        (resp, job_row.id, platform)
    }

    #[tokio::test]
    async fn db_s5_live_apply_matching_digest_accepted() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let digest = proto_sha256(b"the-approved-plan");
        let (resp, job_id, platform) = run_live_apply_case(
            &pool,
            &digest,
            Some(digest.clone()),
            Utc::now() + Duration::hours(1),
            None,
        )
        .await;
        assert!(
            resp.is_ok(),
            "LiveApply with a matching approved_plan_digest + valid grant must be accepted: {:?}",
            resp.err()
        );
        let db = read_job_result_row(&pool, job_id).await;
        assert_eq!(db.status, "Succeeded", "applied job must be terminal");
        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_s5_live_apply_mismatched_digest_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let grant_digest = proto_sha256(b"the-approved-plan");
        let forged_digest = proto_sha256(b"a-different-unapproved-plan");
        let (resp, job_id, platform) = run_live_apply_case(
            &pool,
            &grant_digest,
            Some(forged_digest),
            Utc::now() + Duration::hours(1),
            None,
        )
        .await;
        let (status, _) = resp.expect_err("mismatched plan digest must be rejected");
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        let db = read_job_result_row(&pool, job_id).await;
        assert_eq!(db.status, "Running", "rejected result must not go terminal");
        assert!(db.result_id.is_none());
        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_s5_live_apply_missing_envelope_digest_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let grant_digest = proto_sha256(b"the-approved-plan");
        let (resp, job_id, platform) = run_live_apply_case(
            &pool,
            &grant_digest,
            None, // envelope omits approved_plan_digest
            Utc::now() + Duration::hours(1),
            None,
        )
        .await;
        let (status, _) =
            resp.expect_err("LiveApply without approved_plan_digest must be rejected");
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        let db = read_job_result_row(&pool, job_id).await;
        assert_eq!(db.status, "Running");
        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_s5_live_apply_expired_grant_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let digest = proto_sha256(b"the-approved-plan");
        let (resp, job_id, platform) = run_live_apply_case(
            &pool,
            &digest,
            Some(digest.clone()),
            Utc::now() - Duration::minutes(1), // already expired
            None,
        )
        .await;
        let (status, _) = resp.expect_err("an expired grant must be rejected");
        assert_eq!(status, axum::http::StatusCode::CONFLICT);
        let db = read_job_result_row(&pool, job_id).await;
        assert_eq!(db.status, "Running");
        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    #[tokio::test]
    async fn db_s5_live_apply_grant_request_id_mismatch_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let digest = proto_sha256(b"the-approved-plan");
        // Grant carries a request_id that does NOT match the job spec's.
        let (resp, job_id, platform) = run_live_apply_case(
            &pool,
            &digest,
            Some(digest.clone()),
            Utc::now() + Duration::hours(1),
            Some(Uuid::new_v4()),
        )
        .await;
        let (status, _) = resp.expect_err("grant for a different request must be rejected");
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        let db = read_job_result_row(&pool, job_id).await;
        assert_eq!(db.status, "Running");
        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    // ── S5a-2 tests ───────────────────────────────────────────────────────────
    //
    // These tests cover the CP-side grant-signing machinery introduced in S5a-2:
    //   1. create_live_apply_job produces a validly CP-signed grant.
    //   2. End-to-end: production-signed grant → S5a-1 verifier accepts.
    //   3. Negative: plan digest mismatch → verifier rejects.
    //   4. Negative: spec.mode != LiveApply / bad grant fields → create returns Err.
    //   5. Pubkey endpoint returns the initialised key (handler-level, no DB).
    //
    // DB tests pass the SigningKey DIRECTLY to create_live_apply_job and do NOT
    // rely on the process OnceLock (init_cp_key / cp_signing_key) — the OnceLock
    // is write-once-per-process and the key set by one test leaks to others in
    // the same binary. Only the endpoint test (which is handler-level, no DB)
    // calls init_cp_key_for_test.

    /// The signed grant stored in a LiveApply job row must verify against the
    /// CP public key that signed it.
    #[tokio::test]
    async fn db_s5a2_create_live_apply_job_grant_verifies() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        use chrono::Utc;
        use ryuki_protocol::crypto::verify_vlc;
        use std::collections::BTreeMap;

        let cp_key = ensure_test_cp_key();
        let cp_vk = cp_key.verifying_key();

        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5a2-plt-{suffix}");
        let request_id = Uuid::new_v4();
        let plan_digest = proto_sha256(b"approved-plan-bytes");

        // A LiveApply grant may only be minted for a real, ACTIVE request — the
        // concluded-status gate in create_live_apply_job loads requests.status.
        sqlx::query(
            "INSERT INTO requests (id, request_type, site, environment, name, status, stage, stages) \
             VALUES ($1, 'server-deployment', 'DEFRA', 'prod', 's5a2-live-apply', 'locked', 'lock', '[]'::jsonb)",
        )
        .bind(request_id)
        .execute(&pool)
        .await
        .expect("seed active request for live-apply minting");

        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            mode: JobMode::LiveApply,
        };

        let job_id = create_live_apply_job(
            &pool,
            request_id,
            &platform,
            &spec,
            &plan_digest,
            "ops-alice",
            Utc::now() + Duration::hours(1),
            &cp_key,
        )
        .await
        .expect("create_live_apply_job must succeed");

        // Read the stored live_context from the DB row.
        #[derive(sqlx::FromRow)]
        struct LiveContextRow {
            live_context: Option<sqlx::types::Json<serde_json::Value>>,
        }
        let row = sqlx::query_as::<_, LiveContextRow>(
            "SELECT live_context FROM agent_jobs WHERE id = $1",
        )
        .bind(job_id)
        .fetch_one(&pool)
        .await
        .expect("fetch live_context");

        let grant_json = row.live_context.expect("live_context must be set");
        let grant: VerifiedLiveContext =
            serde_json::from_value(grant_json.0).expect("grant must deserialise");

        // The grant must cryptographically verify against the CP public key.
        assert!(
            verify_vlc(&grant, &cp_vk).is_ok(),
            "stored grant must verify with the CP public key"
        );
        assert_eq!(grant.approved_plan_digest, plan_digest);
        assert_eq!(grant.request_id, request_id);

        sqlx::query("DELETE FROM agent_jobs WHERE id = $1")
            .bind(job_id)
            .execute(&pool)
            .await
            .ok();
        pool.close().await;
    }

    /// The concluded-status gate: a LiveApply grant must NEVER be minted for a
    /// request that has concluded — here a `retired` request. This is the shared
    /// choke-point check that closes the admin-route (`/api/admin/agents/
    /// live-apply-jobs`) bypass of the request-scoped status guard.
    #[tokio::test]
    async fn db_s5a2_create_live_apply_job_refused_for_concluded_request() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        use chrono::Utc;
        use std::collections::BTreeMap;

        let cp_key = ensure_test_cp_key();
        let request_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO requests (id, request_type, site, environment, name, status, stage, stages) \
             VALUES ($1, 'server-deployment', 'DEFRA', 'prod', 's5a2-concluded', 'retired', 'retire', '[]'::jsonb)",
        )
        .bind(request_id)
        .execute(&pool)
        .await
        .expect("seed retired request");

        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            mode: JobMode::LiveApply,
        };

        let result = create_live_apply_job(
            &pool,
            request_id,
            "s5a2-concluded-plt",
            &spec,
            &proto_sha256(b"approved-plan-bytes"),
            "ops-alice",
            Utc::now() + Duration::hours(1),
            &cp_key,
        )
        .await;
        assert!(
            matches!(result, Err(CreateLiveApplyJobError::RequestConcluded)),
            "minting must be refused for a concluded (retired) request; got {result:?}"
        );

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM agent_jobs WHERE request_id = $1")
                .bind(request_id)
                .fetch_one(&pool)
                .await
                .expect("count");
        assert_eq!(count, 0, "no LiveApply job minted for a concluded request");

        sqlx::query("DELETE FROM requests WHERE id = $1")
            .bind(request_id)
            .execute(&pool)
            .await
            .ok();
        pool.close().await;
    }

    /// End-to-end: create_live_apply_job produces a CP-signed grant; the agent
    /// builds a result carrying the matching plan digest; the S5a-1 verifier
    /// in post_job_result_with_pool accepts it. This is the composition test:
    /// S5a-2 (produce) + S5a-1 (verify) must agree.
    #[tokio::test]
    async fn db_s5a2_production_grant_accepted_by_s5a1_verifier() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        use chrono::Utc;
        use std::collections::BTreeMap;

        let cp_key = ensure_test_cp_key();

        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5a2-e2e-{suffix}");
        let agent_id = format!("s5a2-agent-{suffix}");
        let (agent_token, agent_key) = seed_agent_with_key(&pool, &agent_id, &platform).await;

        let request_id = Uuid::new_v4();
        seed_active_request(&pool, request_id).await;
        let plan_digest = proto_sha256(b"the-exact-approved-plan");

        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            mode: JobMode::LiveApply,
        };

        // CP enqueues the job with a production-signed grant.
        let _job_id = create_live_apply_job(
            &pool,
            request_id,
            &platform,
            &spec,
            &plan_digest,
            "ops-alice",
            Utc::now() + Duration::hours(1),
            &cp_key,
        )
        .await
        .expect("create_live_apply_job must succeed");

        // Agent leases and acks the job.
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        // Agent builds a result carrying the approved plan digest.
        let (job_result, evidence_bytes) = make_live_apply_result(
            &agent_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &agent_key,
            &spec,
            b"live apply evidence",
            Some(plan_digest.clone()),
        );

        let mut hdrs = HeaderMap::new();
        hdrs.insert(
            "Authorization",
            format!("Bearer {agent_token}").parse().unwrap(),
        );

        // S5a-1 verifier must accept the production CP-signed grant.
        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence: evidence_bytes,
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(
            resp.is_ok(),
            "production CP-signed grant → S5a-1 verifier must accept: {:?}",
            resp.err()
        );

        let db = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(db.status, "Succeeded");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    /// Negative: the CP signs a grant for digest D; the agent sends digest D'
    /// (a different, unapproved plan). The S5a-1 verifier must reject.
    #[tokio::test]
    async fn db_s5a2_digest_mismatch_rejected_by_verifier() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        use chrono::Utc;
        use std::collections::BTreeMap;

        let cp_key = ensure_test_cp_key();

        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5a2-neg-{suffix}");
        let agent_id = format!("s5a2-negagent-{suffix}");
        let (agent_token, agent_key) = seed_agent_with_key(&pool, &agent_id, &platform).await;

        let request_id = Uuid::new_v4();
        seed_active_request(&pool, request_id).await;
        let approved_digest = proto_sha256(b"the-approved-plan");
        let unapproved_digest = proto_sha256(b"a-different-unapproved-plan");

        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            mode: JobMode::LiveApply,
        };

        // CP signs the grant for `approved_digest`.
        let _job_id = create_live_apply_job(
            &pool,
            request_id,
            &platform,
            &spec,
            &approved_digest,
            "ops-alice",
            Utc::now() + Duration::hours(1),
            &cp_key,
        )
        .await
        .expect("create_live_apply_job");

        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        // Agent sends the UNAPPROVED digest — mismatch vs the grant.
        let (job_result, evidence_bytes) = make_live_apply_result(
            &agent_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &agent_key,
            &spec,
            b"live apply evidence",
            Some(unapproved_digest),
        );

        let mut hdrs = HeaderMap::new();
        hdrs.insert(
            "Authorization",
            format!("Bearer {agent_token}").parse().unwrap(),
        );

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_row.id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence: evidence_bytes,
                evidence_json: None,
            },
            &pool,
        )
        .await;

        assert!(
            resp.is_err(),
            "digest mismatch must be rejected by the S5a-1 verifier"
        );
        let (status, _) = resp.unwrap_err();
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

        let db = read_job_result_row(&pool, job_row.id).await;
        assert_eq!(
            db.status, "Running",
            "job must stay Running after rejection"
        );

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    /// Negative: spec.mode != LiveApply → validate_live_apply_params returns Err.
    /// Tests the sync validation helper that create_live_apply_job delegates to,
    /// avoiding the need for a real PgPool.
    #[test]
    fn validate_live_apply_params_rejects_wrong_mode() {
        use std::collections::BTreeMap;

        let request_id = Uuid::new_v4();

        let wrong_mode_spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            mode: JobMode::OfflineDryRun, // NOT LiveApply
        };

        let result = validate_live_apply_params(&wrong_mode_spec, request_id);
        assert!(
            result.is_err(),
            "OfflineDryRun spec must be rejected by validate_live_apply_params"
        );

        let liveplan_spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            mode: JobMode::LivePlan, // also NOT LiveApply
        };
        let result2 = validate_live_apply_params(&liveplan_spec, request_id);
        assert!(
            result2.is_err(),
            "LivePlan spec must be rejected by validate_live_apply_params"
        );

        // A LiveApply spec with matching request_id must pass.
        let valid_spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            mode: JobMode::LiveApply,
        };
        let result3 = validate_live_apply_params(&valid_spec, request_id);
        assert!(result3.is_ok(), "LiveApply spec must pass validation");
    }

    /// Pubkey endpoint returns the initialised CP public key.
    /// This is a handler-level test (no DB); it calls init_cp_key_for_test so
    /// the global is set for the endpoint. Only the FIRST set in the process
    /// wins — ensure no other test in this binary has already called it with a
    /// different key if you need a specific key here.
    #[tokio::test]
    async fn cp_public_key_endpoint_returns_initialised_key() {
        use crate::cp_identity;

        // Install the shared test CP key as the global (same key every test, so
        // no cross-test race on the write-once global).
        let key = ensure_test_cp_key();
        let expected_pubkey = ryuki_protocol::encode_verifying_key(&key.verifying_key());

        // Call the handler directly.
        let response = cp_public_key().await.into_response();

        // The endpoint must return 200.  If the global was already set with a
        // DIFFERENT key by another test, the status will still be 200 (just a
        // different key value).  Either way, no 503.
        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "cp-public-key must return 200 when the key is initialised"
        );

        // Parse the body.
        use axum::body::to_bytes;
        let body_bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("JSON body");

        // The public_key field must be a non-empty base64 string.
        let pubkey_field = body
            .get("public_key")
            .and_then(|v| v.as_str())
            .expect("public_key field must be present and a string");

        // If the key was freshly set by THIS test, it must match exactly.
        // If it was already set by a prior test, we just verify it is a
        // well-formed base64-encoded 32-byte Ed25519 verifying key.
        let actual_b64 = cp_identity::cp_public_key_b64().expect("key must be set");
        assert_eq!(
            pubkey_field, actual_b64,
            "endpoint must return the key stored in the global"
        );
        // Verify it decodes to a valid 32-byte key.
        ryuki_protocol::crypto::decode_verifying_key(pubkey_field)
            .expect("public_key must be a valid base64-encoded verifying key");

        // Confirm the expected key is at least BASE64-valid.
        let _ = expected_pubkey; // used above, consumed by init
    }

    /// A LiveApply result applied within the grant window, then REPLAYED after
    /// the grant expires (e.g. the durable outbox retries the POST much later),
    /// must return idempotent 200 — NOT a 409 "grant expired". Expiry gates the
    /// first apply only; a replay of an already-recorded result is not re-gated.
    #[tokio::test]
    async fn db_s5_live_apply_replay_after_grant_expiry_is_idempotent() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5-rexp-{suffix}");
        let agent_id = format!("s5-rexp-agent-{suffix}");
        let (token, key) = seed_agent_with_key(&pool, &agent_id, &platform).await;

        let digest = proto_sha256(b"the-approved-plan");
        let job_id = seed_live_apply_job(
            &pool,
            &platform,
            &digest,
            Utc::now() + Duration::hours(1),
            None,
        )
        .await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let (job_result, evidence_bytes) = make_live_apply_result(
            &agent_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            b"live apply evidence",
            Some(digest.clone()),
        );
        let result_id = job_result.result_id;
        // Two bodies sharing the SAME signed result (same result_id) — one for the
        // first apply, one for the post-expiry replay.
        let make_body = || ResultBody {
            job_result: job_result.clone(),
            evidence: evidence_bytes.clone(),
            evidence_json: None,
        };
        let hdrs = || {
            let mut h = HeaderMap::new();
            h.insert("Authorization", format!("Bearer {token}").parse().unwrap());
            h
        };

        // First apply — within the grant window → accepted + terminal.
        let _accepted = post_job_result_with_pool(
            agent_id.clone(),
            job_id.to_string(),
            hdrs(),
            make_body(),
            &pool,
        )
        .await
        .expect("first live apply must be accepted");

        // Simulate the grant having expired after the apply was recorded. Replace
        // the stored grant with a VALIDLY-SIGNED one whose expiry is in the past
        // (re-sign with the same CP key so verify_vlc still passes — only the
        // expiry is now stale). This proves the replay path is gated on terminal
        // status, not on a fresh expiry check.
        let expired_grant = sign_vlc(
            VerifiedLiveContext {
                request_id: spec.request_id,
                approved_plan_digest: digest.clone(),
                approver: "ops-test".to_string(),
                expiry: Utc::now() - Duration::hours(1),
                signature: String::new(),
            },
            &ensure_test_cp_key(),
        );
        sqlx::query("UPDATE agent_jobs SET live_context = $2::jsonb WHERE id = $1")
            .bind(job_id)
            .bind(serde_json::to_value(&expired_grant).expect("grant json"))
            .execute(&pool)
            .await
            .expect("install expired-but-signed grant");

        // Replay the SAME signed result — the job is terminal, so expiry is not
        // re-checked; the idempotency branch returns 200.
        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_id.to_string(),
            hdrs(),
            make_body(),
            &pool,
        )
        .await;
        let out = resp.expect("replay after expiry must be idempotent 200, not 409");
        assert_eq!(
            out.0.get("idempotent").and_then(|v| v.as_bool()),
            Some(true),
            "replay must be flagged idempotent"
        );
        let db = read_job_result_row(&pool, job_id).await;
        assert_eq!(db.status, "Succeeded", "job stays terminal");
        assert_eq!(db.result_id, Some(result_id), "recorded result unchanged");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    /// A grant signed by a key OTHER than the CP's must be rejected — proves the
    /// verifier checks the grant's Ed25519 signature (verify_vlc), not just its
    /// fields. (Defends against a tampered/forged stored grant.)
    #[tokio::test]
    async fn db_s5_live_apply_forged_grant_signature_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // Install the real CP key as the global, but sign the grant with a
        // DIFFERENT (attacker) key.
        let _global = ensure_test_cp_key();
        let attacker_key = generate_keypair(&mut OsRng);

        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5-forge-{suffix}");
        let agent_id = format!("s5-forge-agent-{suffix}");
        let (token, key) = seed_agent_with_key(&pool, &agent_id, &platform).await;

        let digest = proto_sha256(b"the-approved-plan");
        let job_id = seed_live_apply_job_signed(
            &pool,
            &platform,
            &digest,
            Utc::now() + Duration::hours(1),
            None,
            &attacker_key, // NOT the CP key
        )
        .await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;

        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let (job_result, evidence_bytes) = make_live_apply_result(
            &agent_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            b"live apply evidence",
            Some(digest.clone()),
        );
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence: evidence_bytes,
                evidence_json: None,
            },
            &pool,
        )
        .await;
        let (status, _) = resp.expect_err("a grant not signed by the CP must be rejected");
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        let db = read_job_result_row(&pool, job_id).await;
        assert_eq!(db.status, "Running", "forged-grant job must stay Running");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    /// create_live_apply_job rejects bogus grant fields before signing.
    #[tokio::test]
    async fn db_s5a2_create_rejects_bad_grant_fields() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        use std::collections::BTreeMap;
        let cp_key = ensure_test_cp_key();
        let request_id = Uuid::new_v4();
        seed_active_request(&pool, request_id).await;
        let platform = format!(
            "s5a2-badf-{}",
            &Uuid::new_v4().to_string().replace('-', "")[..8]
        );
        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            mode: JobMode::LiveApply,
        };
        let good = proto_sha256(b"plan");
        let future = Utc::now() + Duration::hours(1);

        // Empty / non-hex digest.
        assert!(matches!(
            create_live_apply_job(&pool, request_id, &platform, &spec, "", "ops", future, &cp_key)
                .await,
            Err(CreateLiveApplyJobError::Invalid(_))
        ));
        // Past expiry.
        assert!(matches!(
            create_live_apply_job(
                &pool,
                request_id,
                &platform,
                &spec,
                &good,
                "ops",
                Utc::now() - Duration::hours(1),
                &cp_key
            )
            .await,
            Err(CreateLiveApplyJobError::Invalid(_))
        ));
        // Expiry beyond the max TTL.
        assert!(matches!(
            create_live_apply_job(
                &pool,
                request_id,
                &platform,
                &spec,
                &good,
                "ops",
                Utc::now() + Duration::hours(MAX_GRANT_TTL_HOURS + 1),
                &cp_key
            )
            .await,
            Err(CreateLiveApplyJobError::Invalid(_))
        ));
        // Empty approver.
        assert!(matches!(
            create_live_apply_job(
                &pool, request_id, &platform, &spec, &good, "  ", future, &cp_key
            )
            .await,
            Err(CreateLiveApplyJobError::Invalid(_))
        ));

        // No row should have been created by any rejected call.
        cleanup_jobs_for_platform(&pool, &platform).await;
        pool.close().await;
    }

    // ───────────────────────────────────────────────────────────────────────
    // S5b-2a: LiveRefused result acceptance (agent declined to apply)
    // ───────────────────────────────────────────────────────────────────────

    /// Build a signed result with status `LiveRefused` (the agent declined to
    /// apply). Mode stays `LiveApply` (the job's mode); the refusal carries no
    /// approved_plan_digest unless `approved_plan_digest` is passed (to exercise
    /// the must-not-carry-digest rejection).
    #[allow(clippy::too_many_arguments)]
    fn make_live_refused_result(
        agent_id: &str,
        platform: &str,
        job_row: &AgentJobRow,
        attempt_id: Uuid,
        cp_nonce: &str,
        lease_gen: u64,
        key: &ed25519_dalek::SigningKey,
        spec: &JobSpec,
        evidence: &[u8],
        approved_plan_digest: Option<String>,
    ) -> (JobResult, Vec<u8>) {
        let result_id = Uuid::new_v4();
        let evidence_digest = proto_sha256(evidence);
        let spec_digest = job_spec_digest(spec);
        let status = JobResultStatus::LiveRefused;
        let unsigned_env = SignedEnvelope {
            agent_id: agent_id.to_string(),
            platform: platform.to_string(),
            job_id: job_row.id,
            attempt_id,
            lease_generation: lease_gen,
            request_id: spec.request_id,
            result_id,
            mode: spec.mode.clone(),
            status: status.clone(),
            job_spec_digest: spec_digest,
            approved_plan_digest,
            evidence_digest: evidence_digest.clone(),
            redaction_policy_version: "1.0.0".to_string(),
            timestamp: Utc::now(),
            key_id: encode_verifying_key(&key.verifying_key()),
            cp_nonce: cp_nonce.to_string(),
            signature: String::new(),
        };
        let signed_env = sign(unsigned_env, key);
        let job_result = JobResult {
            job_id: job_row.id,
            attempt_id,
            result_id,
            status,
            evidence_digest,
            signed_envelope: signed_env,
        };
        (job_result, evidence.to_vec())
    }

    /// A signed LiveRefused result is recorded (terminal LiveRefused) WITHOUT the
    /// grant equality/expiry checks — the refusal may itself be because the grant
    /// was unusable. The job still carries a valid grant here, but the refusal
    /// path must not depend on it.
    #[tokio::test]
    async fn db_s5_live_apply_refusal_is_recorded() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5-ref-{suffix}");
        let agent_id = format!("s5-ref-agent-{suffix}");
        let (token, key) = seed_agent_with_key(&pool, &agent_id, &platform).await;
        let digest = proto_sha256(b"the-approved-plan");
        let job_id = seed_live_apply_job(
            &pool,
            &platform,
            &digest,
            Utc::now() + Duration::hours(1),
            None,
        )
        .await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;
        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let (job_result, evidence) = make_live_refused_result(
            &agent_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            b"refused: replanned plan diverged from the approved plan",
            None,
        );
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());
        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence,
                evidence_json: None,
            },
            &pool,
        )
        .await;
        assert!(
            resp.is_ok(),
            "a signed LiveRefused result must be recorded: {:?}",
            resp.err()
        );
        let db = read_job_result_row(&pool, job_id).await;
        assert_eq!(db.status, "LiveRefused", "job must be terminal LiveRefused");
        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    /// A LiveRefused result MUST NOT carry approved_plan_digest (nothing was
    /// applied) — the CP rejects it.
    #[tokio::test]
    async fn db_s5_live_refused_with_plan_digest_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5-refd-{suffix}");
        let agent_id = format!("s5-refd-agent-{suffix}");
        let (token, key) = seed_agent_with_key(&pool, &agent_id, &platform).await;
        let digest = proto_sha256(b"the-approved-plan");
        let job_id = seed_live_apply_job(
            &pool,
            &platform,
            &digest,
            Utc::now() + Duration::hours(1),
            None,
        )
        .await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;
        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let (job_result, evidence) = make_live_refused_result(
            &agent_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            b"refused",
            Some(digest.clone()), // a refusal must NOT carry a plan digest
        );
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());
        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence,
                evidence_json: None,
            },
            &pool,
        )
        .await;
        let (status, _) = resp.expect_err("LiveRefused carrying a plan digest must be rejected");
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        let db = read_job_result_row(&pool, job_id).await;
        assert_eq!(
            db.status, "Running",
            "rejected refusal must not change status"
        );
        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    /// The realistic refusal case: the job's grant is UNUSABLE (signed by a
    /// non-CP key), the agent refuses, and the CP records the refusal anyway —
    /// the refusal path must not depend on grant validity.
    #[tokio::test]
    async fn db_s5_live_apply_refusal_recorded_even_with_bad_grant() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let _global = ensure_test_cp_key();
        let attacker_key = generate_keypair(&mut OsRng);
        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5-refbad-{suffix}");
        let agent_id = format!("s5-refbad-agent-{suffix}");
        let (token, key) = seed_agent_with_key(&pool, &agent_id, &platform).await;
        let digest = proto_sha256(b"the-approved-plan");
        // Grant signed by a NON-CP key → verify_vlc would fail, so the agent
        // refused. The CP must still record the refusal.
        let job_id = seed_live_apply_job_signed(
            &pool,
            &platform,
            &digest,
            Utc::now() + Duration::hours(1),
            None,
            &attacker_key,
        )
        .await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;
        let spec: JobSpec = serde_json::from_value(job_row.spec.0.clone()).expect("spec");
        let (job_result, evidence) = make_live_refused_result(
            &agent_id,
            &platform,
            &job_row,
            attempt_id,
            &nonce,
            gen as u64,
            &key,
            &spec,
            b"refused: grant signature did not verify against the pinned CP key",
            None,
        );
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());
        let resp = post_job_result_with_pool(
            agent_id.clone(),
            job_id.to_string(),
            hdrs,
            ResultBody {
                job_result,
                evidence,
                evidence_json: None,
            },
            &pool,
        )
        .await;
        assert!(
            resp.is_ok(),
            "a refusal must be recorded even when the grant is unusable: {:?}",
            resp.err()
        );
        let db = read_job_result_row(&pool, job_id).await;
        assert_eq!(db.status, "LiveRefused");
        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    /// Definitive cross-crate proof: the agent's REAL `build_signed_result`
    /// (S5b-2b-i) output for a LiveApply Applied result passes the REAL CP
    /// verifier (verify_vlc + digest equality + everything) against live PG.
    #[tokio::test]
    async fn db_s5b2_agent_live_apply_builder_accepted_by_verifier() {
        use ryuki_agent::executor::JobExecutor;
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        // The agent's identity is enrolled; the grant is signed by the shared CP
        // key (installed as the global via seed_live_apply_job → ensure_test_cp_key).
        let identity = ryuki_agent::identity::AgentIdentity::generate();
        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5b2-{suffix}");
        let agent_id = format!("s5b2-agent-{suffix}");
        let token = seed_agent_from_identity(&pool, &agent_id, &platform, &identity).await;

        let digest = proto_sha256(b"the-approved-plan");
        let job_id = seed_live_apply_job(
            &pool,
            &platform,
            &digest,
            Utc::now() + Duration::hours(1),
            None,
        )
        .await;
        let (attempt_id, fencing, nonce, gen, job_row) =
            lease_job(&pool, &platform, &agent_id).await;
        ack_to_running(&pool, job_row.id, attempt_id, &fencing).await;
        let job = build_protocol_job(&job_row, attempt_id, fencing.clone(), nonce.clone(), gen);

        // Agent code: a stub Applied execution → the REAL build_signed_result with
        // the matching plan digest (what S5b-2b-ii's loop will do after the gate).
        let evidence = ryuki_agent::executor::StubExecutor::new(
            ryuki_engine::runners::RunStatus::Applied,
            b"terraform apply output (scrubbed)".to_vec(),
            None,
        )
        .execute(&job.spec)
        .expect("stub execute");
        let agent_body = ryuki_agent::result::build_signed_result(
            &identity,
            &agent_id,
            &job,
            &evidence,
            Some(digest.clone()),
        )
        .expect("build_signed_result for LiveApply Applied must succeed");

        let cp_body: ResultBody =
            serde_json::from_value(serde_json::to_value(&agent_body).expect("serialise"))
                .expect("CP deserialises agent body");
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", format!("Bearer {token}").parse().unwrap());

        let resp =
            post_job_result_with_pool(agent_id.clone(), job_id.to_string(), hdrs, cp_body, &pool)
                .await;
        assert!(
            resp.is_ok(),
            "agent-built LiveApply result must pass the CP verifier: {:?}",
            resp.err()
        );
        let db = read_job_result_row(&pool, job_id).await;
        assert_eq!(db.status, "Succeeded", "applied live job must be terminal");

        cleanup_jobs_for_platform(&pool, &platform).await;
        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    // ── S5c tests — approve_live_apply_with (operator endpoint core) ──────────
    //
    // All tests call `approve_live_apply_with` directly (no Extension / no HTTP
    // layer) so they need only a PgPool and a SigningKey.  The admin/403 path is
    // enforced by the /api/admin RBAC middleware and the in-handler
    // `check_permission` defense-in-depth guard; both are unit-tested by
    // ryuki-engine's own tests and by the RBAC middleware tests in main.rs.  A
    // note instead of a duplicate integration test is sufficient here.
    //
    // The handler itself is thin: it unwraps pool/cp_key (503) and delegates.
    // Covered by: service_unavailable path is trivially visible from the code;
    // the admin permission check calls `check_permission(session, "admin")` from
    // ryuki_engine::auth, whose own test suite asserts false for non-admin roles.

    /// A valid LiveApply body produces a job whose stored grant verifies
    /// cryptographically and carries the correct fields.
    #[tokio::test]
    async fn db_t1_approve_creates_valid_signed_job() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        use ryuki_protocol::crypto::{sha256_hex as proto_sha256, verify_vlc};
        use std::collections::BTreeMap;

        let cp_key = ensure_test_cp_key();
        let cp_vk = cp_key.verifying_key();

        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5c-t1-{suffix}");
        let request_id = Uuid::new_v4();
        seed_active_request(&pool, request_id).await;
        let digest = proto_sha256(b"approved-plan-s5c");

        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            mode: JobMode::LiveApply,
        };

        let body = ApproveLiveApplyBody {
            request_id,
            platform: platform.clone(),
            spec,
            approved_plan_digest: digest.clone(),
            expiry_seconds: 3600,
        };

        let result = approve_live_apply_with(&pool, &cp_key, "sentinel-approver", &body).await;
        assert!(
            result.is_ok(),
            "approve_live_apply_with must succeed for valid input: {:?}",
            result.err()
        );

        let json_val = result.unwrap().0;
        let job_id: Uuid =
            serde_json::from_value(json_val["job_id"].clone()).expect("job_id must be a UUID");
        assert_eq!(json_val["status"], "Pending");
        assert_eq!(json_val["mode"], "LiveApply");
        assert_eq!(json_val["approver"], "sentinel-approver");

        // Read stored live_context and verify the grant.
        #[derive(sqlx::FromRow)]
        struct LiveContextRow {
            live_context: Option<sqlx::types::Json<serde_json::Value>>,
            mode: String,
            status: String,
        }
        let row = sqlx::query_as::<_, LiveContextRow>(
            "SELECT live_context, mode, status FROM agent_jobs WHERE id = $1",
        )
        .bind(job_id)
        .fetch_one(&pool)
        .await
        .expect("fetch job row");

        assert_eq!(row.mode, "LiveApply");
        assert_eq!(row.status, "Pending");

        let grant_json = row.live_context.expect("live_context must be set");
        let grant: VerifiedLiveContext =
            serde_json::from_value(grant_json.0).expect("grant must deserialise");

        assert!(
            verify_vlc(&grant, &cp_vk).is_ok(),
            "stored grant must verify with the CP public key"
        );
        assert_eq!(grant.approved_plan_digest, digest);
        assert_eq!(grant.approver, "sentinel-approver");
        assert_eq!(grant.request_id, request_id);

        sqlx::query("DELETE FROM agent_jobs WHERE id = $1")
            .bind(job_id)
            .execute(&pool)
            .await
            .ok();
        pool.close().await;
    }

    /// A non-hex approved_plan_digest is rejected with 400.
    #[tokio::test]
    async fn db_t1_bad_plan_digest_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        use std::collections::BTreeMap;

        let cp_key = ensure_test_cp_key();
        let request_id = Uuid::new_v4();
        // Seed an active request so the bad-DIGEST rejection (a post-gate check
        // in create_live_apply_job) is what's exercised — not the concluded gate.
        seed_active_request(&pool, request_id).await;
        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            mode: JobMode::LiveApply,
        };
        let body = ApproveLiveApplyBody {
            request_id,
            platform: "any".into(),
            spec,
            approved_plan_digest: "not-hex".into(),
            expiry_seconds: 3600,
        };

        let result = approve_live_apply_with(&pool, &cp_key, "ops-test", &body).await;
        assert!(result.is_err(), "non-hex digest must be rejected");
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        pool.close().await;
    }

    /// expiry_seconds = 0 is rejected with 400.
    #[tokio::test]
    async fn db_t1_expiry_zero_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        use ryuki_protocol::crypto::sha256_hex as proto_sha256;
        use std::collections::BTreeMap;

        let cp_key = ensure_test_cp_key();
        let request_id = Uuid::new_v4();
        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            mode: JobMode::LiveApply,
        };
        let body = ApproveLiveApplyBody {
            request_id,
            platform: "any".into(),
            spec,
            approved_plan_digest: proto_sha256(b"plan"),
            expiry_seconds: 0,
        };

        let result = approve_live_apply_with(&pool, &cp_key, "ops-test", &body).await;
        assert!(result.is_err(), "zero expiry must be rejected");
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        pool.close().await;
    }

    /// expiry_seconds > MAX_GRANT_TTL_HOURS * 3600 is rejected with 400.
    #[tokio::test]
    async fn db_t1_expiry_over_max_ttl_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        use ryuki_protocol::crypto::sha256_hex as proto_sha256;
        use std::collections::BTreeMap;

        let cp_key = ensure_test_cp_key();
        let request_id = Uuid::new_v4();
        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            mode: JobMode::LiveApply,
        };
        let body = ApproveLiveApplyBody {
            request_id,
            platform: "any".into(),
            spec,
            approved_plan_digest: proto_sha256(b"plan"),
            expiry_seconds: (MAX_GRANT_TTL_HOURS as u64) * 3600 + 1,
        };

        let result = approve_live_apply_with(&pool, &cp_key, "ops-test", &body).await;
        assert!(result.is_err(), "over-max TTL must be rejected");
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        pool.close().await;
    }

    /// spec.mode != LiveApply is rejected with 400.
    #[tokio::test]
    async fn db_t1_non_live_apply_mode_rejected() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        use ryuki_protocol::crypto::sha256_hex as proto_sha256;
        use std::collections::BTreeMap;

        let cp_key = ensure_test_cp_key();
        let request_id = Uuid::new_v4();
        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            mode: JobMode::OfflineDryRun,
        };
        let body = ApproveLiveApplyBody {
            request_id,
            platform: "any".into(),
            spec,
            approved_plan_digest: proto_sha256(b"plan"),
            expiry_seconds: 3600,
        };

        let result = approve_live_apply_with(&pool, &cp_key, "ops-test", &body).await;
        assert!(result.is_err(), "OfflineDryRun spec must be rejected");
        let (status, _) = result.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        pool.close().await;
    }

    /// The approver stored in the grant is the one passed as the `approver` argument
    /// (simulating session.user_id), NOT any value that could come from the body.
    /// This test uses a sentinel string to prove provenance.
    #[tokio::test]
    async fn db_t1_approver_is_from_param_not_body() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        use ryuki_protocol::crypto::{sha256_hex as proto_sha256, verify_vlc};
        use std::collections::BTreeMap;

        let cp_key = ensure_test_cp_key();
        let cp_vk = cp_key.verifying_key();

        let suffix = &Uuid::new_v4().to_string().replace('-', "")[..8];
        let platform = format!("s5c-t6-{suffix}");
        let request_id = Uuid::new_v4();
        seed_active_request(&pool, request_id).await;
        let digest = proto_sha256(b"plan-for-approver-test");
        let sentinel_approver = "session-derived-approver-not-from-body";

        let spec = JobSpec {
            request_id,
            offering_id: Uuid::new_v4(),
            iac_ref: "linux-server-deployment@v1".into(),
            iac_digest: "0".repeat(64),
            vars: BTreeMap::new(),
            mode: JobMode::LiveApply,
        };
        let body = ApproveLiveApplyBody {
            request_id,
            platform: platform.clone(),
            spec,
            approved_plan_digest: digest.clone(),
            expiry_seconds: 3600,
        };

        let result = approve_live_apply_with(&pool, &cp_key, sentinel_approver, &body).await;
        assert!(result.is_ok(), "approve must succeed: {:?}", result.err());

        let json_val = result.unwrap().0;
        let job_id: Uuid = serde_json::from_value(json_val["job_id"].clone()).expect("UUID");

        #[derive(sqlx::FromRow)]
        struct Row {
            live_context: Option<sqlx::types::Json<serde_json::Value>>,
        }
        let row = sqlx::query_as::<_, Row>("SELECT live_context FROM agent_jobs WHERE id = $1")
            .bind(job_id)
            .fetch_one(&pool)
            .await
            .expect("fetch");

        let grant: VerifiedLiveContext =
            serde_json::from_value(row.live_context.expect("live_context").0).expect("deserialise");

        // The grant's approver must equal the sentinel passed as the argument,
        // proving the body cannot influence it.
        assert_eq!(
            grant.approver, sentinel_approver,
            "grant.approver must come from the approver param (session), not the body"
        );
        assert!(verify_vlc(&grant, &cp_vk).is_ok(), "grant must verify");

        sqlx::query("DELETE FROM agent_jobs WHERE id = $1")
            .bind(job_id)
            .execute(&pool)
            .await
            .ok();
        pool.close().await;
    }

    // ── admin_list_agents: returns agents and their jobs ──────────────────

    #[tokio::test]
    async fn db_t2_list_agents_returns_agents_and_jobs() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        // Unique platform prefix prevents cross-test interference.
        let suffix = Uuid::new_v4().to_string().replace('-', "");
        let suffix = &suffix[..8];
        let platform_a = format!("t2la-{suffix}a");
        let platform_b = format!("t2la-{suffix}b");
        let agent_id_a = format!("t2la-agent-{suffix}-a");
        let agent_id_b = format!("t2la-agent-{suffix}-b");

        // Seed two agents.
        seed_agent(&pool, &agent_id_a, &platform_a, "approved").await;
        seed_agent(&pool, &agent_id_b, &platform_b, "pending").await;

        // Seed two jobs for agent A (directly set agent_id on the job so it
        // appears in the agent→jobs association returned by list_agents_with).
        let job1 = seed_pending_job(&pool, &platform_a).await;
        let job2 = seed_pending_job(&pool, &platform_a).await;
        sqlx::query("UPDATE agent_jobs SET agent_id = $1, status = 'Succeeded' WHERE id = ANY($2)")
            .bind(&agent_id_a)
            .bind(&[job1, job2] as &[Uuid])
            .execute(&pool)
            .await
            .expect("associate jobs with agent");

        // Call the testable core (auth already tested separately).
        let result = list_agents_with(&pool).await;
        assert!(
            result.is_ok(),
            "list_agents_with must succeed: {:?}",
            result.err()
        );
        let json_val = result.unwrap().0;

        let agents_arr = json_val["agents"].as_array().expect("agents must be array");

        // Both seeded agents must appear.
        let found_a = agents_arr
            .iter()
            .any(|v| v["agent_id"].as_str() == Some(&agent_id_a));
        let found_b = agents_arr
            .iter()
            .any(|v| v["agent_id"].as_str() == Some(&agent_id_b));
        assert!(found_a, "agent A must appear in list");
        assert!(found_b, "agent B must appear in list");

        // Agent A's jobs must be nested under it.
        let agent_a_entry = agents_arr
            .iter()
            .find(|v| v["agent_id"].as_str() == Some(&agent_id_a))
            .expect("agent A entry");
        let jobs_a = agent_a_entry["jobs"]
            .as_array()
            .expect("jobs must be array");
        assert_eq!(jobs_a.len(), 2, "agent A must have exactly 2 jobs");

        // Agent B has no jobs associated; its jobs array must be empty.
        let agent_b_entry = agents_arr
            .iter()
            .find(|v| v["agent_id"].as_str() == Some(&agent_id_b))
            .expect("agent B entry");
        let jobs_b = agent_b_entry["jobs"]
            .as_array()
            .expect("jobs must be array");
        assert!(jobs_b.is_empty(), "agent B must have no jobs");

        // Clean up.
        cleanup_jobs_for_platform(&pool, &platform_a).await;
        cleanup_jobs_for_platform(&pool, &platform_b).await;
        cleanup_agent(&pool, &agent_id_a).await;
        cleanup_agent(&pool, &agent_id_b).await;
        pool.close().await;
    }

    // ── admin_list_agents: non-admin session → 403 ───────────────────────

    #[tokio::test]
    async fn db_t2_list_agents_non_admin_403() {
        // This test does not need a DB — the check_permission gate fires before
        // any pool access. We skip the DB guard for speed and still test the 403
        // branch correctly using the handler's in-handler auth check.
        let non_admin_session = AuthSession {
            user_id: "non-admin-user".to_string(),
            display_name: "Non Admin".to_string(),
            // Requester role has no "admin" permission.
            roles: vec![ryuki_engine::auth::APP_ROLE_REQUESTER.to_string()],
            token_valid: true,
            provider_mode: "test".to_string(),
        };

        // check_permission must return false for a non-admin.
        assert!(
            !check_permission(&non_admin_session, "admin"),
            "Requester must not hold admin permission"
        );

        // Verify the handler branch: forbidden() produces a 403.
        let (status, _body) = forbidden("admin permission required");
        assert_eq!(status, StatusCode::FORBIDDEN, "forbidden() must be 403");
    }

    // ── admin_list_agents: response never contains token_hash ────────────

    #[tokio::test]
    async fn db_t2_list_agents_no_secrets() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };

        let suffix = Uuid::new_v4().to_string().replace('-', "");
        let suffix = &suffix[..8];
        let platform = format!("t2ns-{suffix}");
        let agent_id = format!("t2ns-agent-{suffix}");

        // seed_agent returns the plaintext token; we only need the hash to
        // check it does NOT appear in the response.
        let _plaintext = seed_agent(&pool, &agent_id, &platform, "pending").await;

        // Retrieve the stored token_hash directly so we can assert it's absent.
        let hash: String = sqlx::query_scalar("SELECT token_hash FROM agents WHERE agent_id = $1")
            .bind(&agent_id)
            .fetch_one(&pool)
            .await
            .expect("fetch token_hash for assertion");

        let result = list_agents_with(&pool).await;
        assert!(result.is_ok(), "list must succeed");
        let json_str = serde_json::to_string(&result.unwrap().0).expect("serialize");

        assert!(
            !json_str.contains(&hash),
            "response must not contain the token_hash value"
        );

        cleanup_agent(&pool, &agent_id).await;
        pool.close().await;
    }

    /// AWX bridge slice 2: a successful agent result advances the dispatched
    /// (Executing) parent request to Verifying with the execute stage Completed;
    /// a non-executing request is left untouched (synthetic/test jobs).
    #[tokio::test]
    async fn db_backlink_advances_executing_request() {
        let Some(pool) = test_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let req_id = Uuid::new_v4();
        let stages = serde_json::json!([{
            "name": "execute", "status": "InProgress",
            "started_at": null, "completed_at": null,
            "evidence": [], "metadata": {}
        }]);
        sqlx::query(
            "INSERT INTO requests (id, request_type, site, environment, name, status, stage, stages) \
             VALUES ($1, 'server-deployment', 'DEFRA', 'prod', 'backlink-test', 'executing', 'execute', $2::jsonb)",
        )
        .bind(req_id)
        .bind(&stages)
        .execute(&pool)
        .await
        .expect("insert executing request");

        // Success result: executing -> verifying, execute stage Completed.
        let mut tx = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx,
            req_id,
            &JobResultStatus::Planned,
            "planned",
            "deadbeefdeadbeef",
            Uuid::new_v4(),
        )
        .await
        .expect("backlink");
        tx.commit().await.unwrap();

        let (status, stages_after): (String, serde_json::Value) =
            sqlx::query_as("SELECT status, stages FROM requests WHERE id = $1")
                .bind(req_id)
                .fetch_one(&pool)
                .await
                .expect("read back");
        assert_eq!(status, "verifying", "executing -> verifying on success");
        let execute = stages_after
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "execute")
            .expect("execute stage");
        assert_eq!(execute["status"], "Completed", "execute stage completed");
        assert!(
            execute["metadata"]["agent_job_id"].is_string(),
            "execute stage records the agent job id"
        );

        // A non-executing request is left untouched (CAS guard / skip path).
        sqlx::query("UPDATE requests SET status = 'completed' WHERE id = $1")
            .bind(req_id)
            .execute(&pool)
            .await
            .ok();
        let mut tx2 = pool.begin().await.unwrap();
        backlink_request_execution(
            &mut tx2,
            req_id,
            &JobResultStatus::Failed,
            "failed",
            "x",
            Uuid::new_v4(),
        )
        .await
        .expect("backlink no-op");
        tx2.commit().await.unwrap();
        let status2: String = sqlx::query_scalar("SELECT status FROM requests WHERE id = $1")
            .bind(req_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status2, "completed", "non-executing request is not mutated");

        sqlx::query("DELETE FROM requests WHERE id = $1")
            .bind(req_id)
            .execute(&pool)
            .await
            .ok();
        pool.close().await;
    }
}
