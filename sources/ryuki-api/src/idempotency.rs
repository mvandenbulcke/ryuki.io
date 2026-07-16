//! HTTP idempotency-key middleware.
//!
//! A client that wants at-most-once create semantics sends an `Idempotency-Key`
//! header (an unguessable UUID). The first request for a key runs the handler
//! and its `(status, body)` is stored; a retry **replays** that stored response
//! instead of re-creating the resource. See `docs/design/idempotency.md`.
//!
//! Pass-through (zero behavior change) when: the method is not mutating, there
//! is no `Idempotency-Key` header, or no database is configured.

use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderMap, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use ryuki_engine::auth::AuthSession;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use tokio::time::interval;

use crate::database::get_db;

/// Cap on the request/response body we will buffer for fingerprinting/replay.
/// Create payloads and their JSON responses are well under this.
const MAX_IDEMPOTENT_BODY: usize = 1 << 20; // 1 MiB

/// Hard fair-share ceilings for one authenticated principal inside the replay
/// retention window. A live in-flight claim reserves the full per-response cap
/// until it is sealed, so every admitted mutation can persist its replayable
/// result without oversubscribing the byte budget.
const MAX_IDEMPOTENCY_ROWS_PER_PRINCIPAL: i64 = 10_000;
const MAX_IDEMPOTENCY_RESPONSE_BYTES_PER_PRINCIPAL: i64 = 64 << 20; // 64 MiB

#[derive(Clone, Copy)]
struct PrincipalBudget {
    max_rows: i64,
    max_response_bytes: i64,
    in_flight_response_reservation: i64,
}

const PRINCIPAL_BUDGET: PrincipalBudget = PrincipalBudget {
    max_rows: MAX_IDEMPOTENCY_ROWS_PER_PRINCIPAL,
    max_response_bytes: MAX_IDEMPOTENCY_RESPONSE_BYTES_PER_PRINCIPAL,
    in_flight_response_reservation: MAX_IDEMPOTENT_BODY as i64,
};

const _: () = assert!(
    PRINCIPAL_BUDGET.max_rows > 0,
    "the principal row budget must admit at least one request"
);
const _: () = assert!(
    PRINCIPAL_BUDGET.max_response_bytes >= PRINCIPAL_BUDGET.in_flight_response_reservation,
    "an admitted handler must always be able to seal a maximum-size response"
);

/// Migration 162's trigger admits idempotency INSERT/UPDATE statements only
/// from the writer contract that both holds the matching principal advisory
/// lock and marks the transaction locally. This prevents a pre-budget replica
/// from writing unaccounted records if a deployment accidentally overlaps
/// versions. The production deployment still uses a non-overlapping Recreate
/// cutover because the pre-162 middleware failed open on a rejected DB claim.
const IDEMPOTENCY_WRITER_CONTRACT_VERSION: &str = "2";

async fn lock_idempotency_principal_and_mark_writer(
    tx: &mut Transaction<'_, Postgres>,
    user_scope: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "SELECT pg_advisory_xact_lock( \
             hashtextextended( \
                 'ryuki:idempotency:principal:'::TEXT || $1::TEXT, 0 \
             ) \
         )",
    )
    .bind(user_scope)
    .execute(&mut **tx)
    .await?;
    sqlx::query("SELECT set_config('ryuki.idempotency_writer_contract', $1, TRUE)")
        .bind(IDEMPOTENCY_WRITER_CONTRACT_VERSION)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// A claimed-but-unfinished record older than this is presumed abandoned (the
/// claiming request crashed or was cancelled) and is reclaimed, so a key can
/// never lock out permanently. Far longer than any create handler runs.
const IN_FLIGHT_TTL_SECS: f64 = 300.0; // 5 minutes

/// Canonical fingerprint of a mutating request: `sha256(method ++ "\n" ++
/// path-and-query ++ "\n" ++ body)`, lowercase hex. The full request target
/// (path AND query) is included so the same path with different query params is
/// a different request; a key reused with a DIFFERENT request produces a
/// different fingerprint and is rejected (422).
pub fn request_fingerprint(method: &str, target: &str, body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(b"\n");
    hasher.update(target.as_bytes());
    hasher.update(b"\n");
    hasher.update(body);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Stable digest of the authority that admitted the current request. Object-
/// level handlers may be skipped on replay, so a response is reusable only
/// while the principal's provider, actor class, roles, and resource scopes are
/// identical. Sorting makes the digest independent of claim/list ordering.
fn authorization_context_digest(session: &AuthSession) -> String {
    fn add_set(hasher: &mut Sha256, values: &[String]) {
        let mut values = values.to_vec();
        values.sort_unstable();
        values.dedup();
        hasher.update((values.len() as u64).to_be_bytes());
        for value in values {
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        }
    }

    let mut hasher = Sha256::new();
    for value in [&session.user_id, &session.provider_mode] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    let actor_class = session.actor_class.as_str();
    hasher.update((actor_class.len() as u64).to_be_bytes());
    hasher.update(actor_class.as_bytes());
    hasher.update([u8::from(session.token_valid)]);
    add_set(&mut hasher, &session.roles);
    add_set(&mut hasher, &session.site_scope);
    add_set(&mut hasher, &session.environment_scope);
    format!("{:x}", hasher.finalize())
}

fn authorized_request_fingerprint(
    session: &AuthSession,
    method: &str,
    target: &str,
    body: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(authorization_context_digest(session).as_bytes());
    hasher.update(b"\n");
    hasher.update(request_fingerprint(method, target, body).as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Outcome of looking up an existing idempotency record on the conflict path.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// Same request, response already stored — replay it verbatim.
    Replay { status: u16, body: String },
    /// Same key, DIFFERENT request — reject (422).
    Conflict,
    /// Same request, but the first call has not finished yet — tell the client
    /// to retry (409).
    InFlight,
}

#[derive(Debug, PartialEq, Eq)]
enum ClaimOutcome {
    Claimed,
    Existing {
        fingerprint: String,
        status: Option<i32>,
        body: Option<String>,
    },
    BudgetExceeded,
}

/// Pure decision for the conflict path: an existing record was found for the key
/// and we must decide how to respond to the new request. `new_fingerprint` is
/// the fingerprint of the incoming request.
pub fn decide(
    record_fingerprint: &str,
    record_status: Option<i32>,
    record_body: Option<String>,
    new_fingerprint: &str,
) -> Decision {
    if record_fingerprint != new_fingerprint {
        return Decision::Conflict;
    }
    match (record_status, record_body) {
        (Some(status), Some(body)) => Decision::Replay {
            // status was an HTTP status code when stored; clamp defensively.
            status: u16::try_from(status).unwrap_or(200),
            body,
        },
        _ => Decision::InFlight,
    }
}

fn is_mutating(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// The usable `Idempotency-Key` on a request: present, non-empty, and at most
/// 200 bytes. Shared by the dedup middleware and the [`require_idempotency_key`]
/// guard so the two can never drift on what counts as a valid key.
pub fn usable_idempotency_key(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
        .filter(|k| !k.is_empty() && k.len() <= 200)
}

fn conflict_response() -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        axum::Json(serde_json::json!({
            "error": "Idempotency-Key was reused with a different request"
        })),
    )
        .into_response()
}

fn in_flight_response() -> Response {
    (
        StatusCode::CONFLICT,
        axum::Json(serde_json::json!({
            "error": "a request with this Idempotency-Key is already in progress; retry shortly"
        })),
    )
        .into_response()
}

fn principal_budget_response() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        axum::Json(serde_json::json!({
            "error": "IDEMPOTENCY_BUDGET_EXHAUSTED",
            "message": "idempotency budget exhausted; retry an existing key or wait for expiry"
        })),
    )
        .into_response()
}

fn idempotency_store_unavailable_response() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(serde_json::json!({
            "error": "IDEMPOTENCY_STORE_UNAVAILABLE",
            "message": "the idempotency store could not safely admit this request; retry later"
        })),
    )
        .into_response()
}

/// Claim one key while holding a transaction-scoped lock for the principal's
/// aggregate budget. The separate lock statement is intentional: at READ
/// COMMITTED, the following statement receives a fresh snapshot after a
/// contending claimant commits, so concurrent fresh keys cannot both admit
/// themselves against the same stale count.
async fn claim_key_with_budget(
    pool: &PgPool,
    user_scope: &str,
    key: &str,
    fingerprint: &str,
    claim_id: &str,
    budget: PrincipalBudget,
) -> Result<ClaimOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;
    lock_idempotency_principal_and_mark_writer(&mut tx, user_scope).await?;

    // Lock an existing row before deciding that this is not fresh. Besides
    // preserving replay/conflict/takeover at quota, the row lock prevents the
    // expiry sweep from deleting a small completed row between the exemption
    // check and its replacement with a full-size in-flight reservation.
    let existing_key = sqlx::query(
        "SELECT 1 FROM idempotency_records \
         WHERE user_scope = $1 AND key = $2 FOR UPDATE",
    )
    .bind(user_scope)
    .bind(key)
    .fetch_optional(&mut *tx)
    .await?
    .is_some();

    if !existing_key {
        // Incomplete rows reserve the maximum response size. Completed rows
        // contribute exact UTF-8 octets via migration 162's generated column.
        let (rows, reserved_response_bytes): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*)::BIGINT, COALESCE(SUM( \
                 CASE \
                   WHEN response_status IS NULL OR response_body IS NULL \
                     THEN GREATEST(response_bytes, $2) \
                   ELSE response_bytes \
                 END \
               ), 0)::BIGINT \
             FROM idempotency_records WHERE user_scope = $1",
        )
        .bind(user_scope)
        .bind(budget.in_flight_response_reservation)
        .fetch_one(&mut *tx)
        .await?;
        let byte_headroom = budget
            .max_response_bytes
            .saturating_sub(budget.in_flight_response_reservation);
        if rows >= budget.max_rows || reserved_response_bytes > byte_headroom {
            tx.commit().await?;
            return Ok(ClaimOutcome::BudgetExceeded);
        }
    }

    // Existing keys bypass fresh-key admission. That preserves replay,
    // different-request conflict, and stale same-request takeover even while a
    // principal is exactly at its row or byte ceiling.
    let claimed: Option<(String,)> = sqlx::query_as(
        "INSERT INTO idempotency_records (user_scope, key, fingerprint, claim_id) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (user_scope, key) DO UPDATE \
            SET claim_id = EXCLUDED.claim_id, created_at = NOW(), \
                response_status = NULL, response_body = NULL \
            WHERE idempotency_records.response_status IS NULL \
              AND idempotency_records.fingerprint = EXCLUDED.fingerprint \
              AND idempotency_records.created_at < NOW() - make_interval(secs => $5) \
         RETURNING key",
    )
    .bind(user_scope)
    .bind(key)
    .bind(fingerprint)
    .bind(claim_id)
    .bind(IN_FLIGHT_TTL_SECS)
    .fetch_optional(&mut *tx)
    .await?;

    let outcome = if claimed.is_some() {
        ClaimOutcome::Claimed
    } else {
        let record: Option<(String, Option<i32>, Option<String>)> = sqlx::query_as(
            "SELECT fingerprint, response_status, response_body \
             FROM idempotency_records WHERE user_scope = $1 AND key = $2",
        )
        .bind(user_scope)
        .bind(key)
        .fetch_optional(&mut *tx)
        .await?;
        match record {
            Some((fingerprint, status, body)) => ClaimOutcome::Existing {
                fingerprint,
                status,
                body,
            },
            None => ClaimOutcome::BudgetExceeded,
        }
    };

    tx.commit().await?;
    Ok(outcome)
}

async fn seal_claim_response(
    pool: &PgPool,
    user_scope: &str,
    key: &str,
    claim_id: &str,
    status: i32,
    body: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    lock_idempotency_principal_and_mark_writer(&mut tx, user_scope).await?;
    sqlx::query(
        "UPDATE idempotency_records SET response_status = $1, response_body = $2 \
         WHERE user_scope = $3 AND key = $4 AND claim_id = $5",
    )
    .bind(status)
    .bind(body)
    .bind(user_scope)
    .bind(key)
    .bind(claim_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Reconstruct a stored response: the body is the captured JSON string.
fn replay_response(status: u16, body: String) -> Response {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = code;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    // Mark the response as a replay so clients/operators can tell it apart.
    response.headers_mut().insert(
        "Idempotency-Replayed",
        header::HeaderValue::from_static("true"),
    );
    response
}

/// True when a stored response is faithfully replayable by this middleware: a
/// JSON body whose only replay-significant output is its status + body. We
/// replay only the body (with `content-type: application/json`), so a response
/// is NOT deduped when it is non-JSON OR carries a header a body-only replay
/// would silently drop — a redirect/resource `Location`, a `Set-Cookie`, an
/// `ETag`/`Content-Location`, or a `Content-Encoding` (an encoded body cannot be
/// faithfully replayed without its encoding header).
///
/// It is ALSO not deduped when the response is marked `Cache-Control: no-store`.
/// That is the standard "do not persist this response" directive: handlers that
/// reveal a one-time plaintext secret (a freshly minted API token, an enrollment
/// credential) set it so the plaintext is never written to the dedup table.
/// Releasing the claim means a retry re-runs rather than replaying a stored
/// secret — the correct one-time semantic — and the credential never lands at
/// rest in `idempotency_records`.
///
/// Such a response releases its claim and passes through unstored.
fn is_replayable(response: &Response) -> bool {
    let headers = response.headers();
    let is_json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("application/json"))
        .unwrap_or(false);
    if !is_json {
        return false;
    }
    // `Cache-Control: no-store` → never persist (covers one-time secret reveals).
    // Scan every Cache-Control header line and compare DIRECTIVES exactly (split
    // on commas, trim, case-insensitive) so a second header line or an odd value
    // can neither hide nor spoof the directive.
    let no_store = headers
        .get_all(header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|cc| cc.split(','))
        .any(|directive| directive.trim().eq_ignore_ascii_case("no-store"));
    if no_store {
        return false;
    }
    const REPLAY_SIGNIFICANT: [header::HeaderName; 5] = [
        header::LOCATION,
        header::SET_COOKIE,
        header::ETAG,
        header::CONTENT_LOCATION,
        header::CONTENT_ENCODING,
    ];
    !REPLAY_SIGNIFICANT.iter().any(|h| headers.contains_key(h))
}

/// The idempotency middleware. Buffers the request body to fingerprint it,
/// atomically claims the key, then either runs the handler once (storing the
/// response) or replays/rejects per `decide`.
pub async fn idempotency_middleware(request: Request, next: Next) -> Response {
    idempotency_middleware_with_budget(request, next, PRINCIPAL_BUDGET).await
}

async fn idempotency_middleware_with_budget(
    request: Request,
    next: Next,
    principal_budget: PrincipalBudget,
) -> Response {
    let method = request.method().clone();
    if !is_mutating(&method) {
        return next.run(request).await;
    }
    let Some(key) = usable_idempotency_key(request.headers()).map(str::to_string) else {
        return next.run(request).await;
    };
    // Scope every record to the authenticated principal so one tenant's key can
    // never collide with — or replay — another's. The middleware runs inside
    // auth; an unauthenticated mutating request is not deduped (pass-through).
    let Some(session) = request.extensions().get::<AuthSession>().cloned() else {
        return next.run(request).await;
    };
    let user_scope = session.user_id.clone();
    // Idempotency needs the durable store; without a DB, behave as before.
    let Some(pool) = get_db() else {
        return next.run(request).await;
    };

    // Fingerprint over the full request target (path AND query), not just path.
    let target = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());

    // Buffer the request body so we can fingerprint it AND still hand it to the
    // handler.
    let (parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, MAX_IDEMPOTENT_BODY).await {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response();
        }
    };
    let fingerprint =
        authorized_request_fingerprint(&session, method.as_str(), &target, &body_bytes);
    let request = Request::from_parts(parts, Body::from(body_bytes));

    // A fresh fence token for THIS claim. Every finalizing UPDATE/DELETE below is
    // scoped to it, so a slow handler whose claim was reclaimed after the TTL
    // cannot clobber the newer owner's record.
    let claim_id = uuid::Uuid::new_v4().to_string();

    // Atomically claim the key. The INSERT claims it when no record exists and
    // the principal still has both row and conservatively reserved byte
    // capacity, OR
    // when an existing record is an ABANDONED in-flight claim by the SAME request
    // (null response, matching fingerprint, older than the TTL) — taking over a
    // crashed request's row so a key never locks out permanently. A fresh
    // in-flight, a completed, or a DIFFERENT-fingerprint record does NOT match
    // the DO UPDATE guard, so the statement returns no row and we fall through to
    // the conflict path (where a different fingerprint becomes a 422).
    let claim = match claim_key_with_budget(
        pool,
        &user_scope,
        &key,
        &fingerprint,
        &claim_id,
        principal_budget,
    )
    .await
    {
        Ok(outcome) => outcome,
        // Once a caller opted into a database-backed idempotency claim, a
        // budget-check/transaction failure must not run a mutation that the
        // service can no longer promise to record and replay.
        Err(error) => {
            tracing::error!(error = %error, "idempotency claim failed closed");
            return idempotency_store_unavailable_response();
        }
    };

    if claim == ClaimOutcome::Claimed {
        // First request for this key: run the handler once and store the result.
        let response = next.run(request).await;
        let status = response.status();

        // Do NOT persist a server error as the idempotent outcome — let a
        // transient 5xx be retried. Release the claim so the retry re-runs.
        // Likewise, only dedup responses we can faithfully replay (JSON, no
        // Location/Set-Cookie/ETag) — release the claim for anything else. The
        // claim_id fence means we only ever release OUR OWN claim.
        if status.is_server_error() || !is_replayable(&response) {
            // If this release DELETE errors, the claim lingers in-flight and blocks
            // retries of this key until it expires (~IN_FLIGHT_TTL_SECS) — which is
            // exactly wrong for a transient 5xx we WANT retried. Log-not-fail (the
            // response is returned regardless) so the stuck claim is visible.
            if let Err(error) = sqlx::query(
                "DELETE FROM idempotency_records \
                 WHERE user_scope = $1 AND key = $2 AND claim_id = $3",
            )
            .bind(&user_scope)
            .bind(&key)
            .bind(&claim_id)
            .execute(pool)
            .await
            {
                tracing::warn!(
                    error = %error,
                    "failed to release idempotency claim for a non-stored response; the \
                     in-flight record will block retries of this key until it expires (~5 min)"
                );
            }
            return response;
        }

        let (resp_parts, resp_body) = response.into_parts();
        let resp_bytes = match axum::body::to_bytes(resp_body, MAX_IDEMPOTENT_BODY).await {
            Ok(b) => b,
            Err(_) => {
                // Could not buffer the response — drop the claim and return a
                // fresh body-less error rather than a corrupt store. If the release
                // DELETE itself errors, the claim lingers in-flight and blocks retries
                // of this key until it expires (~IN_FLIGHT_TTL_SECS); log it so that is
                // visible rather than a silent lock-out.
                if let Err(error) = sqlx::query(
                    "DELETE FROM idempotency_records \
                     WHERE user_scope = $1 AND key = $2 AND claim_id = $3",
                )
                .bind(&user_scope)
                .bind(&key)
                .bind(&claim_id)
                .execute(pool)
                .await
                {
                    tracing::warn!(
                        error = %error,
                        "failed to release idempotency claim after a response-buffering \
                         error; the in-flight record will block retries of this key until \
                         it expires (~5 min)"
                    );
                }
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        // JSON is UTF-8. Refuse to persist an invalid body rather than using a
        // lossy conversion that can both change the replay and expand stored
        // bytes beyond the reservation used at admission.
        let body_str = match String::from_utf8(resp_bytes.to_vec()) {
            Ok(body) => body,
            Err(_) => {
                if let Err(error) = sqlx::query(
                    "DELETE FROM idempotency_records \
                     WHERE user_scope = $1 AND key = $2 AND claim_id = $3",
                )
                .bind(&user_scope)
                .bind(&key)
                .bind(&claim_id)
                .execute(pool)
                .await
                {
                    tracing::warn!(
                        error = %error,
                        "failed to release idempotency claim for an invalid UTF-8 JSON \
                         response; the in-flight record will block retries of this key \
                         until it expires (~5 min)"
                    );
                }
                return Response::from_parts(resp_parts, Body::from(resp_bytes));
            }
        };
        // Fenced by claim_id: if our claim was reclaimed after the TTL while the
        // handler ran, this affects 0 rows (Ok) and we leave the newer owner's record
        // untouched — our caller still gets a valid response. A DB ERROR is different:
        // it leaves OUR record in-flight (response_status NULL), so a retry of this key
        // hits the InFlight branch and gets a 409 until the record expires
        // (~IN_FLIGHT_TTL_SECS). We must NOT fail the request here (the response is
        // already buffered and the handler committed), but we LOG it so operators can
        // see the dedup store is unhealthy rather than silently locking the client out.
        if let Err(error) = seal_claim_response(
            pool,
            &user_scope,
            &key,
            &claim_id,
            i32::from(status.as_u16()),
            &body_str,
        )
        .await
        {
            tracing::warn!(
                error = %error,
                "failed to seal idempotency result; the in-flight record will block \
                 retries of this key until it expires (~5 min)"
            );
        }

        return Response::from_parts(resp_parts, Body::from(resp_bytes));
    }

    match claim {
        // Existing records were read in the same serialized transaction as the
        // failed upsert. Any in-flight row here is fresh; a stale matching one
        // would have been reclaimed.
        ClaimOutcome::Existing {
            fingerprint: rec_fp,
            status: rec_status,
            body: rec_body,
        } => match decide(&rec_fp, rec_status, rec_body, &fingerprint) {
            Decision::Replay { status, body } => replay_response(status, body),
            Decision::Conflict => conflict_response(),
            Decision::InFlight => in_flight_response(),
        },
        ClaimOutcome::BudgetExceeded => principal_budget_response(),
        ClaimOutcome::Claimed => unreachable!("claimed requests return after handler execution"),
    }
}

// ---------------------------------------------------------------------------
// Require-key guard — opt-in per route for the highest-risk creates.
// ---------------------------------------------------------------------------

/// Per-route guard that REJECTS a request lacking a usable `Idempotency-Key`
/// with `400 IDEMPOTENCY_KEY_REQUIRED`, instead of the layer's default optional
/// pass-through. Apply only to the highest-risk create routes via
/// `post(handler).layer(middleware::from_fn(require_idempotency_key))`.
///
/// It composes with the dedup middleware: a present key was already claimed by
/// that (outer) middleware, so the route still deduplicates; this guard only
/// turns an ABSENT key into a hard error. Its accept rule is exactly
/// [`usable_idempotency_key`], so the guard and the dedup layer cannot diverge.
pub async fn require_idempotency_key(request: Request, next: Next) -> Response {
    if usable_idempotency_key(request.headers()).is_none() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "error": "IDEMPOTENCY_KEY_REQUIRED",
                "message": "this endpoint requires an Idempotency-Key header \
                            (a unique, unguessable key per logical request)"
            })),
        )
            .into_response();
    }
    next.run(request).await
}

// ---------------------------------------------------------------------------
// Retention sweep — bounds the table and makes a key reusable after the window.
// ---------------------------------------------------------------------------

/// How long a record is retained for replay before the background sweep deletes
/// it. After this window the same key is reusable (a fresh claim succeeds).
/// The same bounded sweep releases any abandoned unique-key reservation, so a
/// failed claim cannot consume a principal's aggregate budget permanently.
/// Far longer than any realistic create retry; far
/// longer than the in-flight TTL, so a swept row is always long past any handler.
const RETENTION_TTL_SECS: f64 = 86_400.0; // 24 hours

/// Maximum rows removed in one transaction. Repeated ticks drain a backlog
/// without holding a large delete transaction or starving normal claims.
const RETENTION_SWEEP_BATCH: i64 = 1_000;

/// Bound one scheduled drain while allowing it to catch up faster than a
/// single batch. Aggregate admission budgets remain necessary to guarantee a
/// hard table-size ceiling under sustained hostile writes.
const RETENTION_SWEEP_MAX_BATCHES_PER_TICK: usize = 32;

/// Delete idempotency records older than the retention window. Idempotent and
/// safe to run concurrently; returns the number of rows removed. A row older
/// than the retention window is long past any in-flight handler, so this never
/// races a finalizing write. Uses DB-server time only (no client clock).
pub async fn sweep_expired_records(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let removed = sqlx::query(
        "WITH expired AS ( \
             SELECT user_scope, key FROM idempotency_records \
             WHERE created_at < NOW() - make_interval(secs => $1) \
             ORDER BY created_at, user_scope, key \
             LIMIT $2 FOR UPDATE SKIP LOCKED \
         ) \
         DELETE FROM idempotency_records records USING expired \
         WHERE records.user_scope = expired.user_scope AND records.key = expired.key",
    )
    .bind(RETENTION_TTL_SECS)
    .bind(RETENTION_SWEEP_BATCH)
    .execute(pool)
    .await?
    .rows_affected();
    if removed > 0 {
        tracing::info!(removed, "idempotency records swept");
    }
    Ok(removed)
}

async fn drain_expired_records(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let mut total = 0_u64;
    for _ in 0..RETENTION_SWEEP_MAX_BATCHES_PER_TICK {
        let removed = sweep_expired_records(pool).await?;
        total = total.saturating_add(removed);
        if removed < RETENTION_SWEEP_BATCH as u64 {
            break;
        }
        tokio::task::yield_now().await;
    }
    Ok(total)
}

/// Spawn a background task that sweeps expired idempotency records every
/// `interval_secs`. Call once at startup after the DB pool is available; the
/// task runs until the runtime shuts down. The sweep is idempotent, so a
/// duplicate spawn is harmless.
/// Heartbeat registry name for the idempotency retention sweep loop.
const IDEMPOTENCY_SWEEP_NAME: &str = "idempotency_sweep";

pub fn spawn_idempotency_sweep(pool: PgPool, interval_secs: u64) {
    tokio::spawn(async move {
        crate::background::register_loop(IDEMPOTENCY_SWEEP_NAME, interval_secs);
        let mut ticker = interval(std::time::Duration::from_secs(interval_secs));
        // #26 follow-on: Skip missed ticks so a recovered loop resumes on the next
        // aligned boundary rather than bursting catch-up ticks after a backoff/timeout.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await; // skip the immediate first tick (just started)
                             // #31: exponential backoff on consecutive failures so a persistent outage
                             // is retried with increasing spacing instead of hammering + log-spamming
                             // at the base interval. The extra sleep is the real delay; the ticker's
                             // Skip behavior means a recovered loop resumes on the next boundary.
        let timeout = crate::background::iteration_timeout(interval_secs);
        let mut consecutive_failures: u32 = 0;
        loop {
            ticker.tick().await;
            match crate::background::run_bounded(timeout, drain_expired_records(&pool)).await {
                Ok(_) => {
                    consecutive_failures = 0;
                    crate::background::record_loop_success(IDEMPOTENCY_SWEEP_NAME);
                }
                Err(err) => {
                    let backoff = crate::background::note_failure(&mut consecutive_failures);
                    match err {
                        crate::background::IterError::Failed(e) => tracing::error!(
                            error = %e,
                            consecutive_failures,
                            backoff_intervals = backoff,
                            "idempotency sweep failed; backing off"
                        ),
                        crate::background::IterError::TimedOut => tracing::error!(
                            timeout_secs = timeout.as_secs(),
                            consecutive_failures,
                            backoff_intervals = backoff,
                            "idempotency sweep exceeded its iteration timeout; backing off"
                        ),
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(
                        interval_secs.saturating_mul(backoff),
                    ))
                    .await;
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_deterministic_and_input_sensitive() {
        let a = request_fingerprint("POST", "/api/x", b"{\"n\":1}");
        let b = request_fingerprint("POST", "/api/x", b"{\"n\":1}");
        assert_eq!(a, b, "same inputs → same fingerprint");
        assert_eq!(a.len(), 64);
        assert_ne!(
            a,
            request_fingerprint("POST", "/api/x", b"{\"n\":2}"),
            "different body → different fingerprint"
        );
        assert_ne!(
            a,
            request_fingerprint("POST", "/api/y", b"{\"n\":1}"),
            "different path → different fingerprint"
        );
        assert_ne!(
            a,
            request_fingerprint("PUT", "/api/x", b"{\"n\":1}"),
            "different method → different fingerprint"
        );
    }

    #[test]
    fn fingerprint_distinguishes_method_path_body_boundaries() {
        // The newline separators make these unambiguous.
        assert_ne!(
            request_fingerprint("POST", "/a", b"b"),
            request_fingerprint("POST", "/", b"ab"),
        );
    }

    #[test]
    fn authorization_context_digest_is_order_independent_but_scope_sensitive() {
        let mut first = AuthSession {
            user_id: "principal".into(),
            provider_mode: "api-token".into(),
            token_valid: true,
            roles: vec!["Auditor".into(), "Operator".into()],
            site_scope: vec!["SITE-B".into(), "SITE-A".into()],
            environment_scope: vec!["prod".into()],
            ..Default::default()
        };
        let mut reordered = first.clone();
        reordered.roles.reverse();
        reordered.site_scope.reverse();
        assert_eq!(
            authorization_context_digest(&first),
            authorization_context_digest(&reordered)
        );

        first.site_scope = vec!["SITE-A".into()];
        assert_ne!(
            authorization_context_digest(&first),
            authorization_context_digest(&reordered),
            "a narrower token/session authority must not share replay state"
        );
    }

    #[test]
    fn authorized_fingerprint_changes_when_roles_or_scopes_change() {
        let base = AuthSession {
            user_id: "principal".into(),
            provider_mode: "api-token".into(),
            token_valid: true,
            roles: vec!["Operator".into()],
            site_scope: vec!["SITE-A".into()],
            environment_scope: vec!["prod".into()],
            ..Default::default()
        };
        let fingerprint = authorized_request_fingerprint(&base, "POST", "/api/x", b"{}");

        let mut changed = base.clone();
        changed.site_scope = vec!["SITE-B".into()];
        assert_ne!(
            fingerprint,
            authorized_request_fingerprint(&changed, "POST", "/api/x", b"{}")
        );

        changed = base.clone();
        changed.roles.push("Approver".into());
        assert_ne!(
            fingerprint,
            authorized_request_fingerprint(&changed, "POST", "/api/x", b"{}")
        );

        changed = base.clone();
        changed.environment_scope = vec!["staging".into()];
        assert_ne!(
            fingerprint,
            authorized_request_fingerprint(&changed, "POST", "/api/x", b"{}")
        );

        changed = base.clone();
        changed.actor_class = ryuki_engine::auth::ActorClass::Workload;
        assert_ne!(
            fingerprint,
            authorized_request_fingerprint(&changed, "POST", "/api/x", b"{}")
        );
    }

    #[test]
    fn production_principal_budget_reserves_the_full_response_capture_cap() {
        assert_eq!(IDEMPOTENCY_WRITER_CONTRACT_VERSION, "2");
        assert_eq!(
            PRINCIPAL_BUDGET.in_flight_response_reservation, MAX_IDEMPOTENT_BODY as i64,
            "an admitted handler must always be able to seal a maximum-size response"
        );
    }

    #[test]
    fn production_api_cutover_is_non_overlapping_for_writer_contract_migrations() {
        let manifests = include_str!("../../../deploy/kubernetes/base/deployments.yaml");
        let platform_api = manifests
            .split("metadata:\n  name: platform-api")
            .nth(1)
            .and_then(|tail| tail.split("\n---").next())
            .expect("platform-api deployment exists");
        assert!(
            platform_api.contains("strategy:\n    type: Recreate"),
            "idempotency writer-contract migrations forbid mixed-version API overlap"
        );
        assert!(!platform_api.contains("type: RollingUpdate"));
    }

    #[test]
    fn decide_replays_same_request_with_stored_response() {
        let d = decide("fp", Some(201), Some("{\"id\":1}".into()), "fp");
        assert_eq!(
            d,
            Decision::Replay {
                status: 201,
                body: "{\"id\":1}".into()
            }
        );
    }

    #[test]
    fn decide_conflicts_on_different_fingerprint() {
        assert_eq!(
            decide("fp-a", Some(201), Some("{}".into()), "fp-b"),
            Decision::Conflict
        );
    }

    #[test]
    fn decide_in_flight_when_response_not_yet_stored() {
        assert_eq!(decide("fp", None, None, "fp"), Decision::InFlight);
        assert_eq!(decide("fp", Some(201), None, "fp"), Decision::InFlight);
    }

    #[test]
    fn is_mutating_covers_unsafe_methods_only() {
        assert!(is_mutating(&Method::POST));
        assert!(is_mutating(&Method::PUT));
        assert!(is_mutating(&Method::PATCH));
        assert!(is_mutating(&Method::DELETE));
        assert!(!is_mutating(&Method::GET));
        assert!(!is_mutating(&Method::HEAD));
    }

    #[test]
    fn usable_idempotency_key_accepts_only_present_nonempty_bounded() {
        let mut h = HeaderMap::new();
        assert!(usable_idempotency_key(&h).is_none(), "absent → none");
        h.insert("Idempotency-Key", "".parse().unwrap());
        assert!(usable_idempotency_key(&h).is_none(), "empty → none");
        h.insert("Idempotency-Key", "abc-123".parse().unwrap());
        assert_eq!(usable_idempotency_key(&h), Some("abc-123"));
        h.insert("Idempotency-Key", "x".repeat(201).parse().unwrap());
        assert!(usable_idempotency_key(&h).is_none(), ">200 bytes → none");
    }
}

// ---------------------------------------------------------------------------
// DB-gated integration tests — claim / replay / conflict / pass-through.
// Each SKIPS when RYUKI_DATABASE_URL is unset.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::database::DB_TEST_SERIAL;
    use axum::{routing::post, Extension, Router};
    use sqlx::PgPool;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tower::ServiceExt;

    async fn global_pool() -> Option<&'static PgPool> {
        let url = std::env::var("RYUKI_DATABASE_URL").ok()?;
        crate::database::try_connect_with_url(&url, 5, 1, 300, 30, 1800).await;
        let pool = crate::database::get_db()
            .expect("RYUKI_DATABASE_URL is set but the DB connection failed");
        let _ = crate::database::run_migrations(pool).await;
        Some(pool)
    }

    async fn current_writer_transaction<'a>(
        pool: &'a PgPool,
        user_scope: &str,
    ) -> Transaction<'a, Postgres> {
        let mut tx = pool.begin().await.expect("begin current-writer tx");
        lock_idempotency_principal_and_mark_writer(&mut tx, user_scope)
            .await
            .expect("current writer acquires its principal contract fence");
        tx
    }

    /// A handler whose body changes on EVERY real invocation, so a replayed
    /// (deduped) response is detectable: same body = handler ran once.
    async fn counter_handler() -> axum::Json<serde_json::Value> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        axum::Json(serde_json::json!({ "call": n }))
    }

    static BUDGET_HANDLER_CALLS: AtomicU64 = AtomicU64::new(0);

    /// Fixed two-octet JSON response: tests can distinguish the maximum
    /// in-flight reservation from the exact stored-response accounting.
    async fn budget_handler() -> axum::Json<serde_json::Value> {
        BUDGET_HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
        axum::Json(serde_json::json!({}))
    }

    static INVALID_UTF8_HANDLER_CALLS: AtomicU64 = AtomicU64::new(0);

    async fn invalid_utf8_json_handler() -> Response {
        INVALID_UTF8_HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
        let mut response = Response::new(Body::from(vec![0xff, 0xfe]));
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );
        response
    }

    fn session(user: &str) -> AuthSession {
        let mut s = AuthSession::static_dry_run();
        s.user_id = user.to_string();
        s
    }

    /// Router with the idempotency middleware AND an injected session for
    /// `user` — the `Extension` layer is outermost so the session is present in
    /// extensions before the (inner) idempotency middleware reads it.
    fn app_for(user: &str) -> Router {
        app_for_session(session(user))
    }

    fn app_for_session(session: AuthSession) -> Router {
        Router::new()
            .route("/t", post(counter_handler))
            .layer(axum::middleware::from_fn(idempotency_middleware))
            .layer(Extension(session))
    }

    fn api_token_session(
        user: &str,
        site_scope: &[&str],
        environment_scope: &[&str],
    ) -> AuthSession {
        AuthSession {
            user_id: user.to_string(),
            display_name: "Scoped API token".to_string(),
            roles: vec![ryuki_engine::auth::APP_ROLE_VMWARE_OPERATOR.to_string()],
            token_valid: true,
            provider_mode: "api-token".to_string(),
            actor_class: ryuki_engine::auth::ActorClass::Workload,
            site_scope: site_scope
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            environment_scope: environment_scope
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
        }
    }

    fn budget_app_for(user: &str, budget: PrincipalBudget) -> Router {
        Router::new()
            .route("/t", post(budget_handler))
            .layer(axum::middleware::from_fn(
                move |request: Request, next: Next| async move {
                    idempotency_middleware_with_budget(request, next, budget).await
                },
            ))
            .layer(Extension(session(user)))
    }

    fn post_req(key: Option<&str>, body: &'static str) -> Request {
        let mut b = Request::builder()
            .method("POST")
            .uri("/t")
            .header("content-type", "application/json");
        if let Some(k) = key {
            b = b.header("Idempotency-Key", k);
        }
        b.body(Body::from(body)).unwrap()
    }

    async fn body_string(resp: Response) -> (StatusCode, bool, String) {
        let status = resp.status();
        let replayed = resp.headers().get("Idempotency-Replayed").is_some();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            replayed,
            String::from_utf8_lossy(&bytes).into_owned(),
        )
    }

    #[tokio::test]
    async fn writer_contract_rejects_legacy_writes_and_admits_current_writer() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let user = "idem-test-writer-contract";
        let key = "contract-key";
        sqlx::query("DELETE FROM idempotency_records WHERE user_scope = $1")
            .bind(user)
            .execute(pool)
            .await
            .ok();

        // The pre-162 statement shape has neither the transaction-local v2
        // marker nor the principal advisory lock. Migration 162 must reject it
        // at the table boundary even while this principal is below quota.
        let legacy_insert = sqlx::query(
            "INSERT INTO idempotency_records (user_scope, key, fingerprint, claim_id) \
             VALUES ($1, $2, 'legacy-fingerprint', 'legacy-claim')",
        )
        .bind(user)
        .bind(key)
        .execute(pool)
        .await
        .expect_err("an unmarked legacy INSERT must be fenced");
        let legacy_insert_db = legacy_insert
            .as_database_error()
            .expect("writer fence is a database constraint error");
        assert_eq!(legacy_insert_db.code().as_deref(), Some("23514"));
        assert_eq!(
            legacy_insert_db.constraint(),
            Some("idempotency_records_writer_contract")
        );

        let outcome = claim_key_with_budget(
            pool,
            user,
            key,
            "current-fingerprint",
            "current-claim",
            PrincipalBudget {
                max_rows: 2,
                max_response_bytes: 2 * MAX_IDEMPOTENT_BODY as i64,
                in_flight_response_reservation: MAX_IDEMPOTENT_BODY as i64,
            },
        )
        .await
        .expect("contract-v2 claim transaction is admitted");
        assert_eq!(outcome, ClaimOutcome::Claimed);

        let legacy_update = sqlx::query(
            "UPDATE idempotency_records SET response_status = 200, response_body = '{}' \
             WHERE user_scope = $1 AND key = $2",
        )
        .bind(user)
        .bind(key)
        .execute(pool)
        .await
        .expect_err("an unmarked legacy UPDATE must be fenced");
        let legacy_update_db = legacy_update
            .as_database_error()
            .expect("writer fence is a database constraint error");
        assert_eq!(legacy_update_db.code().as_deref(), Some("23514"));
        assert_eq!(
            legacy_update_db.constraint(),
            Some("idempotency_records_writer_contract")
        );

        seal_claim_response(pool, user, key, "current-claim", 200, "{}")
            .await
            .expect("contract-v2 finalizer holds the same principal fence");
        let sealed: (Option<i32>, Option<String>) = sqlx::query_as(
            "SELECT response_status, response_body FROM idempotency_records \
             WHERE user_scope = $1 AND key = $2",
        )
        .bind(user)
        .bind(key)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(sealed, (Some(200), Some("{}".into())));

        sqlx::query("DELETE FROM idempotency_records WHERE user_scope = $1")
            .bind(user)
            .execute(pool)
            .await
            .ok();
    }

    #[tokio::test]
    async fn replays_on_same_key_and_rejects_key_reuse() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let user = "idem-test-user-a";
        let key = "idem-test-replay-7c3";
        sqlx::query("DELETE FROM idempotency_records WHERE user_scope = $1")
            .bind(user)
            .execute(pool)
            .await
            .ok();
        let app = || app_for(user);

        // 1. First call — handler runs, response stored.
        let (s1, r1, b1) = body_string(
            app()
                .oneshot(post_req(Some(key), "{\"x\":1}"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(s1, StatusCode::OK);
        assert!(!r1, "first response is not a replay");

        // 2. Retry, same key + same body — must REPLAY (identical body, handler
        //    did NOT run again), flagged with the replay header.
        let (s2, r2, b2) = body_string(
            app()
                .oneshot(post_req(Some(key), "{\"x\":1}"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(s2, StatusCode::OK);
        assert!(r2, "second response must be a replay");
        assert_eq!(
            b1, b2,
            "replay must return the identical original body (handler ran once)"
        );

        // 3. Same key, DIFFERENT body — must 422.
        let (s3, _, _) = body_string(
            app()
                .oneshot(post_req(Some(key), "{\"x\":2}"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            s3,
            StatusCode::UNPROCESSABLE_ENTITY,
            "key reuse with a different body must be 422"
        );

        // 4. No key — pass-through: handler runs, fresh body each time.
        let (_, _, b4a) =
            body_string(app().oneshot(post_req(None, "{\"x\":1}")).await.unwrap()).await;
        let (_, _, b4b) =
            body_string(app().oneshot(post_req(None, "{\"x\":1}")).await.unwrap()).await;
        assert_ne!(b4a, b4b, "without a key, every request runs the handler");

        sqlx::query("DELETE FROM idempotency_records WHERE user_scope = $1")
            .bind(user)
            .execute(pool)
            .await
            .ok();
    }

    /// Canonical R01-MB-C226 regression: API-token authentication maps two
    /// differently attenuated credentials to the same owner principal. The
    /// authorization digest must turn each scope delta into a different
    /// fingerprint, so the narrower token receives a conflict instead of a
    /// cached response that skipped its handler-level scope check.
    #[tokio::test]
    async fn same_owner_api_tokens_with_different_scopes_cannot_replay() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let user = "idem-test-same-owner-attenuated-tokens";
        sqlx::query("DELETE FROM idempotency_records WHERE user_scope = $1")
            .bind(user)
            .execute(pool)
            .await
            .ok();

        let broad = api_token_session(user, &["SITE-A", "SITE-B"], &["prod", "staging"]);
        let site_narrow = api_token_session(user, &["SITE-A"], &["prod", "staging"]);
        let environment_narrow = api_token_session(user, &["SITE-A", "SITE-B"], &["prod"]);

        let site_key = "idem-test-c226-site-scope";
        let (first_status, first_replayed, first_body) = body_string(
            app_for_session(broad.clone())
                .oneshot(post_req(Some(site_key), "{\"operation\":\"same\"}"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(first_status, StatusCode::OK);
        assert!(!first_replayed);

        let (site_status, site_replayed, _) = body_string(
            app_for_session(site_narrow)
                .oneshot(post_req(Some(site_key), "{\"operation\":\"same\"}"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(site_status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(!site_replayed, "a narrower site token must never replay");

        let (retry_status, retry_replayed, retry_body) = body_string(
            app_for_session(broad.clone())
                .oneshot(post_req(Some(site_key), "{\"operation\":\"same\"}"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(retry_status, StatusCode::OK);
        assert!(
            retry_replayed,
            "the identical broad authority still replays"
        );
        assert_eq!(retry_body, first_body);

        let environment_key = "idem-test-c226-environment-scope";
        let (environment_first, replayed, _) = body_string(
            app_for_session(broad)
                .oneshot(post_req(Some(environment_key), "{\"operation\":\"same\"}"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(environment_first, StatusCode::OK);
        assert!(!replayed);

        let (environment_status, environment_replayed, _) = body_string(
            app_for_session(environment_narrow)
                .oneshot(post_req(Some(environment_key), "{\"operation\":\"same\"}"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(environment_status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            !environment_replayed,
            "a narrower environment token must never replay"
        );

        sqlx::query("DELETE FROM idempotency_records WHERE user_scope = $1")
            .bind(user)
            .execute(pool)
            .await
            .ok();
    }

    /// Cross-tenant isolation: two different principals using the IDENTICAL key
    /// and body must each run their own handler — neither replays nor blocks the
    /// other (the record is scoped by user_scope, not by key alone).
    #[tokio::test]
    async fn keys_are_scoped_per_user() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let (ua, ub) = ("idem-test-scope-a", "idem-test-scope-b");
        let key = "idem-test-shared-key";
        for u in [ua, ub] {
            sqlx::query("DELETE FROM idempotency_records WHERE user_scope = $1")
                .bind(u)
                .execute(pool)
                .await
                .ok();
        }

        // User A claims the shared key.
        let (sa, ra, ba) = body_string(
            app_for(ua)
                .oneshot(post_req(Some(key), "{\"x\":1}"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(sa, StatusCode::OK);
        assert!(!ra, "A's first call is not a replay");

        // User B uses the SAME key + body. Must run B's handler (fresh body),
        // NOT replay A's response and NOT 409/422 against A's record.
        let (sb, rb, bb) = body_string(
            app_for(ub)
                .oneshot(post_req(Some(key), "{\"x\":1}"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(sb, StatusCode::OK);
        assert!(!rb, "B must NOT replay A's response");
        assert_ne!(ba, bb, "B's response is its own, not A's");

        // A retries → replays A's own stored response (both records coexist).
        let (_, ra2, ba2) = body_string(
            app_for(ua)
                .oneshot(post_req(Some(key), "{\"x\":1}"))
                .await
                .unwrap(),
        )
        .await;
        assert!(ra2, "A's retry replays A's record");
        assert_eq!(ba, ba2, "A replays A's body, untouched by B");

        for u in [ua, ub] {
            sqlx::query("DELETE FROM idempotency_records WHERE user_scope = $1")
                .bind(u)
                .execute(pool)
                .await
                .ok();
        }
    }

    /// Concurrent fresh keys for one principal share one serialized row
    /// allowance. Once full, an admitted key must still replay and another
    /// principal must retain an independent allowance.
    #[tokio::test]
    async fn principal_row_budget_is_atomic_without_breaking_replay_or_isolation() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let (user, other_user) = ("idem-test-row-budget", "idem-test-row-budget-other");
        for principal in [user, other_user] {
            sqlx::query("DELETE FROM idempotency_records WHERE user_scope = $1")
                .bind(principal)
                .execute(pool)
                .await
                .ok();
        }

        let budget = PrincipalBudget {
            max_rows: 4,
            max_response_bytes: 4_096,
            in_flight_response_reservation: 128,
        };
        let calls_before = BUDGET_HANDLER_CALLS.load(Ordering::SeqCst);
        let app = budget_app_for(user, budget);
        let mut tasks = Vec::new();
        for index in 0..12 {
            let app = app.clone();
            tasks.push(tokio::spawn(async move {
                let key = format!("row-budget-{index}");
                let response = app.oneshot(post_req(Some(&key), "{}")).await.unwrap();
                (key, response.status())
            }));
        }

        let mut results = Vec::new();
        for task in tasks {
            results.push(task.await.unwrap());
        }
        assert_eq!(
            results
                .iter()
                .filter(|(_, status)| *status == StatusCode::OK)
                .count(),
            budget.max_rows as usize,
            "concurrent fresh keys cannot oversubscribe the row budget"
        );
        assert_eq!(
            results
                .iter()
                .filter(|(_, status)| *status == StatusCode::TOO_MANY_REQUESTS)
                .count(),
            results.len() - budget.max_rows as usize
        );
        assert_eq!(
            BUDGET_HANDLER_CALLS.load(Ordering::SeqCst) - calls_before,
            budget.max_rows as u64,
            "rejected fresh keys must not run the protected mutation"
        );
        let stored_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM idempotency_records WHERE user_scope = $1")
                .bind(user)
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(stored_rows, budget.max_rows);

        let admitted_key = results
            .iter()
            .find(|(_, status)| *status == StatusCode::OK)
            .map(|(key, _)| key.as_str())
            .unwrap();
        let calls_before_replay = BUDGET_HANDLER_CALLS.load(Ordering::SeqCst);
        let (status, replayed, body) = body_string(
            budget_app_for(user, budget)
                .oneshot(post_req(Some(admitted_key), "{}"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(replayed, "an existing key must replay at the row ceiling");
        assert_eq!(body, "{}");
        assert_eq!(
            BUDGET_HANDLER_CALLS.load(Ordering::SeqCst),
            calls_before_replay,
            "replay must not re-run the handler"
        );

        let other_status = budget_app_for(other_user, budget)
            .oneshot(post_req(Some("independent-key"), "{}"))
            .await
            .unwrap()
            .status();
        assert_eq!(
            other_status,
            StatusCode::OK,
            "another principal has an independent fair-share budget"
        );

        for principal in [user, other_user] {
            sqlx::query("DELETE FROM idempotency_records WHERE user_scope = $1")
                .bind(principal)
                .execute(pool)
                .await
                .ok();
        }
    }

    /// In-flight claims reserve the full possible response, then sealing a
    /// small response releases the unused reservation. Admission at the exact
    /// byte boundary succeeds; the next fresh key is rejected before its
    /// handler runs, while an existing key still replays.
    #[tokio::test]
    async fn principal_byte_budget_reserves_then_reconciles_exact_octets() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let user = "idem-test-byte-budget";
        for principal in [user, "idem-test-byte-budget-utf8"] {
            sqlx::query("DELETE FROM idempotency_records WHERE user_scope = $1")
                .bind(principal)
                .execute(pool)
                .await
                .ok();
        }

        let budget = PrincipalBudget {
            max_rows: 10,
            max_response_bytes: 10,
            in_flight_response_reservation: 8,
        };
        let calls_before = BUDGET_HANDLER_CALLS.load(Ordering::SeqCst);
        for key in ["byte-budget-a", "byte-budget-b"] {
            let response = budget_app_for(user, budget)
                .oneshot(post_req(Some(key), "{}"))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "sealing the first small response must free room for the second reservation"
            );
        }
        assert_eq!(
            BUDGET_HANDLER_CALLS.load(Ordering::SeqCst) - calls_before,
            2
        );

        let response = budget_app_for(user, budget)
            .oneshot(post_req(Some("byte-budget-c"), "{}"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            BUDGET_HANDLER_CALLS.load(Ordering::SeqCst) - calls_before,
            2,
            "byte-budget rejection must happen before the mutation"
        );

        let (response_bytes, row_count): (i64, i64) = sqlx::query_as(
            "SELECT COALESCE(SUM(response_bytes), 0)::BIGINT, COUNT(*)::BIGINT \
             FROM idempotency_records WHERE user_scope = $1",
        )
        .bind(user)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(
            response_bytes, 4,
            "two empty-object JSON responses are four octets"
        );
        assert_eq!(row_count, 2);

        let calls_before_replay = BUDGET_HANDLER_CALLS.load(Ordering::SeqCst);
        let (status, replayed, _) = body_string(
            budget_app_for(user, budget)
                .oneshot(post_req(Some("byte-budget-a"), "{}"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(replayed, "existing replay bypasses fresh-byte admission");
        assert_eq!(
            BUDGET_HANDLER_CALLS.load(Ordering::SeqCst),
            calls_before_replay
        );

        let utf8_body = "{\"value\":\"é🙂\"}";
        let mut writer_tx = current_writer_transaction(pool, "idem-test-byte-budget-utf8").await;
        sqlx::query(
            "INSERT INTO idempotency_records \
             (user_scope, key, fingerprint, claim_id, response_status, response_body) \
             VALUES ($1, 'utf8-octets', 'fp', 'claim', 200, $2)",
        )
        .bind("idem-test-byte-budget-utf8")
        .bind(utf8_body)
        .execute(&mut *writer_tx)
        .await
        .unwrap();
        writer_tx.commit().await.unwrap();
        let stored_octets: i64 = sqlx::query_scalar(
            "SELECT response_bytes FROM idempotency_records \
             WHERE user_scope = 'idem-test-byte-budget-utf8' AND key = 'utf8-octets'",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(stored_octets, utf8_body.len() as i64);
        assert!(stored_octets > utf8_body.chars().count() as i64);

        for principal in [user, "idem-test-byte-budget-utf8"] {
            sqlx::query("DELETE FROM idempotency_records WHERE user_scope = $1")
                .bind(principal)
                .execute(pool)
                .await
                .ok();
        }
    }

    /// No permanent lockout: an ABANDONED in-flight claim (the handler never
    /// stored a response and the row is older than the TTL) must be RECLAIMED by
    /// the next request — it runs the handler, not 409 forever.
    #[tokio::test]
    async fn stale_in_flight_claim_is_reclaimed() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let user = "idem-test-stale";
        let key = "idem-test-stale-key";
        let full_budget = PrincipalBudget {
            max_rows: 1,
            max_response_bytes: 128,
            in_flight_response_reservation: 128,
        };
        sqlx::query("DELETE FROM idempotency_records WHERE user_scope = $1")
            .bind(user)
            .execute(pool)
            .await
            .ok();

        // Plant an abandoned in-flight claim whose fingerprint MATCHES the retry
        // (an identical request that crashed mid-flight): null response, 10m old.
        let matching_fp =
            authorized_request_fingerprint(&session(user), "POST", "/t", b"{\"x\":1}");
        let mut writer_tx = current_writer_transaction(pool, user).await;
        sqlx::query(
            "INSERT INTO idempotency_records (user_scope, key, fingerprint, claim_id, created_at) \
             VALUES ($1, $2, $3, 'abandoned-claim', NOW() - INTERVAL '10 minutes')",
        )
        .bind(user)
        .bind(key)
        .bind(&matching_fp)
        .execute(&mut *writer_tx)
        .await
        .unwrap();
        writer_tx.commit().await.unwrap();

        // The identical retry must RECLAIM and RUN the handler (200, not 409),
        // even though this one row consumes the test principal's entire row and
        // in-flight byte allowance.
        let (status, replayed, _) = body_string(
            budget_app_for(user, full_budget)
                .oneshot(post_req(Some(key), "{\"x\":1}"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "an identical stale in-flight claim must not lock the key out (no 409)"
        );
        assert!(
            !replayed,
            "reclaim runs the handler fresh, it is not a replay"
        );

        // A DIFFERENT request on a stale dead key must NOT be reclaimed — it is a
        // key-reuse conflict (422), not a silent takeover.
        sqlx::query("DELETE FROM idempotency_records WHERE user_scope = $1")
            .bind(user)
            .execute(pool)
            .await
            .ok();
        let mut writer_tx = current_writer_transaction(pool, user).await;
        sqlx::query(
            "INSERT INTO idempotency_records (user_scope, key, fingerprint, claim_id, created_at) \
             VALUES ($1, $2, $3, 'abandoned-claim', NOW() - INTERVAL '10 minutes')",
        )
        .bind(user)
        .bind(key)
        .bind(&matching_fp)
        .execute(&mut *writer_tx)
        .await
        .unwrap();
        writer_tx.commit().await.unwrap();
        let (status_diff, _, _) = body_string(
            budget_app_for(user, full_budget)
                .oneshot(post_req(Some(key), "{\"x\":999}"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            status_diff,
            StatusCode::UNPROCESSABLE_ENTITY,
            "a different request on a dead key is a 422 conflict, not a reclaim"
        );

        sqlx::query("DELETE FROM idempotency_records WHERE user_scope = $1")
            .bind(user)
            .execute(pool)
            .await
            .ok();
    }

    /// The retention sweep deletes records older than the window and keeps fresh
    /// ones — bounding the table and freeing the key after the window.
    #[tokio::test]
    async fn sweep_deletes_only_expired_records() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let user = "idem-test-sweep";
        sqlx::query("DELETE FROM idempotency_records WHERE user_scope = $1")
            .bind(user)
            .execute(pool)
            .await
            .ok();

        // More than one transaction batch well past the retention window, plus
        // one fresh record. The scheduled drain must make bounded progress
        // across batches without turning one DELETE into an unbounded write.
        let mut writer_tx = current_writer_transaction(pool, user).await;
        sqlx::query(
            "INSERT INTO idempotency_records \
             (user_scope, key, fingerprint, claim_id, response_status, response_body, created_at) \
             SELECT $1, 'old-' || n::text, 'fp', 'c', 200, '{}', \
                    NOW() - INTERVAL '2 days' \
             FROM generate_series(1, $2) AS n",
        )
        .bind(user)
        .bind(RETENTION_SWEEP_BATCH + 5)
        .execute(&mut *writer_tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO idempotency_records \
             (user_scope, key, fingerprint, claim_id, response_status, response_body, created_at) \
             VALUES ($1, 'new', 'fp', 'c', 200, '{}', NOW())",
        )
        .bind(user)
        .execute(&mut *writer_tx)
        .await
        .unwrap();
        writer_tx.commit().await.unwrap();

        let removed = drain_expired_records(pool).await.unwrap();
        assert_eq!(
            removed,
            (RETENTION_SWEEP_BATCH + 5) as u64,
            "the bounded drain must continue after one full transaction batch"
        );

        let old_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM idempotency_records \
             WHERE user_scope = $1 AND key LIKE 'old-%'",
        )
        .bind(user)
        .fetch_one(pool)
        .await
        .unwrap();
        let fresh: Option<(String,)> = sqlx::query_as(
            "SELECT key FROM idempotency_records WHERE user_scope = $1 AND key = 'new'",
        )
        .bind(user)
        .fetch_optional(pool)
        .await
        .unwrap();
        assert_eq!(old_count, 0, "all expired test records were deleted");
        assert!(fresh.is_some(), "the fresh record was retained");

        let post_sweep_budget = PrincipalBudget {
            max_rows: 2,
            max_response_bytes: 256,
            in_flight_response_reservation: 128,
        };
        let admitted_after_sweep = budget_app_for(user, post_sweep_budget)
            .oneshot(post_req(Some("after-sweep"), "{}"))
            .await
            .unwrap();
        assert_eq!(
            admitted_after_sweep.status(),
            StatusCode::OK,
            "bounded cleanup must release expired row and byte reservations"
        );

        sqlx::query("DELETE FROM idempotency_records WHERE user_scope = $1")
            .bind(user)
            .execute(pool)
            .await
            .ok();
    }

    /// A `Cache-Control: no-store` response (a one-time secret reveal, e.g. a
    /// freshly minted token) is NOT persisted or replayed: the claim is released,
    /// so a retry re-runs and the secret never lands in idempotency_records.
    #[tokio::test]
    async fn no_store_response_is_not_persisted() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let user = "idem-test-nostore";
        let key = "idem-test-nostore-key";
        sqlx::query("DELETE FROM idempotency_records WHERE user_scope = $1")
            .bind(user)
            .execute(pool)
            .await
            .ok();

        async fn no_store_handler() -> impl axum::response::IntoResponse {
            static C: AtomicU64 = AtomicU64::new(0);
            let n = C.fetch_add(1, Ordering::SeqCst);
            (
                [(axum::http::header::CACHE_CONTROL, "no-store")],
                axum::Json(serde_json::json!({ "call": n })),
            )
        }
        let app = || {
            Router::new()
                .route("/s", post(no_store_handler))
                .layer(axum::middleware::from_fn(idempotency_middleware))
                .layer(Extension(session(user)))
        };
        let req = || {
            Request::builder()
                .method("POST")
                .uri("/s")
                .header("content-type", "application/json")
                .header("Idempotency-Key", key)
                .body(Body::from("{\"x\":1}"))
                .unwrap()
        };

        let (_, _, b1) = body_string(app().oneshot(req()).await.unwrap()).await;
        let (_, r2, b2) = body_string(app().oneshot(req()).await.unwrap()).await;
        assert!(!r2, "a no-store response is never replayed");
        assert_ne!(
            b1, b2,
            "a no-store response is not deduped; the handler runs each time"
        );

        // Nothing for the key was persisted — the secret never lands at rest.
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT key FROM idempotency_records WHERE user_scope = $1 AND key = $2",
        )
        .bind(user)
        .bind(key)
        .fetch_optional(pool)
        .await
        .unwrap();
        assert!(
            row.is_none(),
            "a no-store response must not be stored in idempotency_records"
        );

        sqlx::query("DELETE FROM idempotency_records WHERE user_scope = $1")
            .bind(user)
            .execute(pool)
            .await
            .ok();
    }

    /// A body labelled JSON but containing invalid UTF-8 is returned byte-for-
    /// byte and never stored. This prevents lossy expansion beyond the reserved
    /// response budget and prevents a replay from differing from the original.
    #[tokio::test]
    async fn invalid_utf8_json_response_is_released_without_lossy_replay() {
        let _serial = DB_TEST_SERIAL.lock().await;
        let Some(pool) = global_pool().await else {
            eprintln!("SKIP: RYUKI_DATABASE_URL not set");
            return;
        };
        let user = "idem-test-invalid-utf8";
        let key = "idem-test-invalid-utf8-key";
        sqlx::query("DELETE FROM idempotency_records WHERE user_scope = $1")
            .bind(user)
            .execute(pool)
            .await
            .ok();

        let app = || {
            Router::new()
                .route("/invalid", post(invalid_utf8_json_handler))
                .layer(axum::middleware::from_fn(idempotency_middleware))
                .layer(Extension(session(user)))
        };
        let request = || {
            Request::builder()
                .method("POST")
                .uri("/invalid")
                .header("content-type", "application/json")
                .header("Idempotency-Key", key)
                .body(Body::from("{}"))
                .unwrap()
        };

        let calls_before = INVALID_UTF8_HANDLER_CALLS.load(Ordering::SeqCst);
        for _ in 0..2 {
            let response = app().oneshot(request()).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert!(
                response.headers().get("Idempotency-Replayed").is_none(),
                "invalid UTF-8 JSON cannot be replayed"
            );
            let bytes = axum::body::to_bytes(response.into_body(), MAX_IDEMPOTENT_BODY)
                .await
                .unwrap();
            assert_eq!(bytes.as_ref(), &[0xff, 0xfe]);
        }
        assert_eq!(
            INVALID_UTF8_HANDLER_CALLS.load(Ordering::SeqCst) - calls_before,
            2,
            "the released claim makes the retry run the handler again"
        );

        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM idempotency_records WHERE user_scope = $1 AND key = $2",
        )
        .bind(user)
        .bind(key)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(rows, 0, "invalid UTF-8 is never retained for replay");

        sqlx::query("DELETE FROM idempotency_records WHERE user_scope = $1")
            .bind(user)
            .execute(pool)
            .await
            .ok();
    }

    /// The require-key guard rejects a missing/empty key with 400 and lets a
    /// usable key through to the handler. Pure middleware — needs no DB.
    #[tokio::test]
    async fn require_idempotency_key_guard_rejects_missing_header() {
        let app = || {
            Router::new()
                .route("/g", post(|| async { "ok" }))
                .layer(axum::middleware::from_fn(require_idempotency_key))
        };
        let post_to_g = |key: Option<&str>| {
            let mut b = Request::builder().method("POST").uri("/g");
            if let Some(k) = key {
                b = b.header("Idempotency-Key", k);
            }
            b.body(Body::empty()).unwrap()
        };

        // Missing key → 400.
        let resp = app().oneshot(post_to_g(None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Empty key → 400 (same rule as the dedup layer).
        let resp = app().oneshot(post_to_g(Some(""))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Usable key → passes through to the handler.
        let resp = app().oneshot(post_to_g(Some("k-123"))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
