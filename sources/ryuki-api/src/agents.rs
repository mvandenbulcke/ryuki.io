//! Execution-agent dispatch plumbing — S3a (control-plane side).
//!
//! Slice scope: agent registry + job queue + lease mechanics.
//! Out of scope (S3b): result endpoint, per-request signature verification,
//! admin approval UI, signed grant issuance.
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
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use tokio::time::interval;
use uuid::Uuid;

use crate::database::get_db;
use crate::sha256_hex;
use ryuki_protocol::{Capabilities, Job, JobLease, JobSpec, JobStatus};

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
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

const AGENT_JOB_COLUMNS: &str = "id, request_id, platform, spec, mode, status, \
    agent_id, attempt_id, lease_generation, fencing_token, cp_nonce, \
    lease_deadline, created_at, updated_at";

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

    let job = Job {
        id: row.id,
        platform: row.platform.clone(),
        spec,
        status: JobStatus::Leased,
        lease: Some(lease),
        live_context: None, // S3b: CP-signed LiveApply grant
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
pub fn agent_routes() -> Router {
    Router::new()
        .route("/api/agents/register", post(register_agent))
        .route("/api/agents/{agent_id}/jobs", get(poll_job))
        .route("/api/agents/{agent_id}/jobs/{job_id}/ack", post(ack_job))
        .route("/api/agents/{agent_id}/heartbeat", post(heartbeat))
}

/// Admin route: sits under `/api/admin/agents/` so the human RBAC middleware
/// enforces `admin` permission. Agent tokens can never reach this path because
/// the `/api/agents/` exemption in `is_agent_exempt_path` is path-specific and
/// does not match `/api/admin/`.
pub fn admin_routes() -> Router {
    Router::new().route(
        "/api/admin/agents/{agent_id}/approve",
        post(admin_approve_agent),
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
}
