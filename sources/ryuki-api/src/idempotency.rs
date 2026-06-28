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
use sqlx::PgPool;
use tokio::time::interval;

use crate::database::get_db;

/// Cap on the request/response body we will buffer for fingerprinting/replay.
/// Create payloads and their JSON responses are well under this.
const MAX_IDEMPOTENT_BODY: usize = 1 << 20; // 1 MiB

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
/// `ETag`/`Content-Location`, or a `Content-Encoding` (a gzipped body would be
/// mangled by the lossy UTF-8 capture and replayed without its encoding header).
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
    let Some(user_scope) = request
        .extensions()
        .get::<AuthSession>()
        .map(|s| s.user_id.clone())
    else {
        return next.run(request).await;
    };
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
    let fingerprint = request_fingerprint(method.as_str(), &target, &body_bytes);
    let request = Request::from_parts(parts, Body::from(body_bytes));

    // A fresh fence token for THIS claim. Every finalizing UPDATE/DELETE below is
    // scoped to it, so a slow handler whose claim was reclaimed after the TTL
    // cannot clobber the newer owner's record.
    let claim_id = uuid::Uuid::new_v4().to_string();

    // Atomically claim the key. The INSERT claims it when no record exists OR
    // when an existing record is an ABANDONED in-flight claim by the SAME request
    // (null response, matching fingerprint, older than the TTL) — taking over a
    // crashed request's row so a key never locks out permanently. A fresh
    // in-flight, a completed, or a DIFFERENT-fingerprint record does NOT match
    // the DO UPDATE guard, so the statement returns no row and we fall through to
    // the conflict path (where a different fingerprint becomes a 422).
    let claimed: Option<(String,)> = match sqlx::query_as(
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
    .bind(&user_scope)
    .bind(&key)
    .bind(&fingerprint)
    .bind(&claim_id)
    .bind(IN_FLIGHT_TTL_SECS)
    .fetch_optional(pool)
    .await
    {
        Ok(row) => row,
        // On a storage error, fail open to the handler rather than blocking the
        // request — idempotency is best-effort, not a hard gate.
        Err(error) => {
            tracing::error!(error = %error, "idempotency claim failed; proceeding without dedup");
            return next.run(request).await;
        }
    };

    if claimed.is_some() {
        // First request for this key: run the handler once and store the result.
        let response = next.run(request).await;
        let status = response.status();

        // Do NOT persist a server error as the idempotent outcome — let a
        // transient 5xx be retried. Release the claim so the retry re-runs.
        // Likewise, only dedup responses we can faithfully replay (JSON, no
        // Location/Set-Cookie/ETag) — release the claim for anything else. The
        // claim_id fence means we only ever release OUR OWN claim.
        if status.is_server_error() || !is_replayable(&response) {
            let _ = sqlx::query(
                "DELETE FROM idempotency_records \
                 WHERE user_scope = $1 AND key = $2 AND claim_id = $3",
            )
            .bind(&user_scope)
            .bind(&key)
            .bind(&claim_id)
            .execute(pool)
            .await;
            return response;
        }

        let (resp_parts, resp_body) = response.into_parts();
        let resp_bytes = match axum::body::to_bytes(resp_body, MAX_IDEMPOTENT_BODY).await {
            Ok(b) => b,
            Err(_) => {
                // Could not buffer the response — drop the claim and return a
                // fresh body-less error rather than a corrupt store.
                let _ = sqlx::query(
                    "DELETE FROM idempotency_records \
                     WHERE user_scope = $1 AND key = $2 AND claim_id = $3",
                )
                .bind(&user_scope)
                .bind(&key)
                .bind(&claim_id)
                .execute(pool)
                .await;
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        let body_str = String::from_utf8_lossy(&resp_bytes).into_owned();
        // Fenced by claim_id: if our claim was reclaimed after the TTL while the
        // handler ran, this affects 0 rows and we leave the newer owner's record
        // untouched — our caller still gets a valid response.
        let _ = sqlx::query(
            "UPDATE idempotency_records SET response_status = $1, response_body = $2 \
             WHERE user_scope = $3 AND key = $4 AND claim_id = $5",
        )
        .bind(i32::from(status.as_u16()))
        .bind(&body_str)
        .bind(&user_scope)
        .bind(&key)
        .bind(&claim_id)
        .execute(pool)
        .await;

        return Response::from_parts(resp_parts, Body::from(resp_bytes));
    }

    // Conflict: a record already exists for this (scope, key). Look it up and
    // decide. Any in-flight row we see here is fresh — a stale one would have
    // been reclaimed by the INSERT above.
    let record: Option<(String, Option<i32>, Option<String>)> = sqlx::query_as(
        "SELECT fingerprint, response_status, response_body FROM idempotency_records \
         WHERE user_scope = $1 AND key = $2",
    )
    .bind(&user_scope)
    .bind(&key)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    match record {
        Some((rec_fp, rec_status, rec_body)) => {
            match decide(&rec_fp, rec_status, rec_body, &fingerprint) {
                Decision::Replay { status, body } => replay_response(status, body),
                Decision::Conflict => conflict_response(),
                Decision::InFlight => in_flight_response(),
            }
        }
        // The record vanished between the claim attempt and the lookup (e.g. a
        // concurrent sweep). Fail open — run the handler.
        None => next.run(request).await,
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
/// it. After this window the same key is reusable (a fresh claim succeeds) and
/// the table stays bounded. Far longer than any realistic create retry; far
/// longer than the in-flight TTL, so a swept row is always long past any handler.
const RETENTION_TTL_SECS: f64 = 86_400.0; // 24 hours

/// Delete idempotency records older than the retention window. Idempotent and
/// safe to run concurrently; returns the number of rows removed. A row older
/// than the retention window is long past any in-flight handler, so this never
/// races a finalizing write. Uses DB-server time only (no client clock).
pub async fn sweep_expired_records(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let removed = sqlx::query(
        "DELETE FROM idempotency_records WHERE created_at < NOW() - make_interval(secs => $1)",
    )
    .bind(RETENTION_TTL_SECS)
    .execute(pool)
    .await?
    .rows_affected();
    if removed > 0 {
        tracing::info!(removed, "idempotency records swept");
    }
    Ok(removed)
}

/// Spawn a background task that sweeps expired idempotency records every
/// `interval_secs`. Call once at startup after the DB pool is available; the
/// task runs until the runtime shuts down. The sweep is idempotent, so a
/// duplicate spawn is harmless.
pub fn spawn_idempotency_sweep(pool: PgPool, interval_secs: u64) {
    tokio::spawn(async move {
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
            match crate::background::run_bounded(timeout, sweep_expired_records(&pool)).await {
                Ok(_) => consecutive_failures = 0,
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

    /// A handler whose body changes on EVERY real invocation, so a replayed
    /// (deduped) response is detectable: same body = handler ran once.
    async fn counter_handler() -> axum::Json<serde_json::Value> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        axum::Json(serde_json::json!({ "call": n }))
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
        Router::new()
            .route("/t", post(counter_handler))
            .layer(axum::middleware::from_fn(idempotency_middleware))
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
        sqlx::query("DELETE FROM idempotency_records WHERE user_scope = $1")
            .bind(user)
            .execute(pool)
            .await
            .ok();

        // Plant an abandoned in-flight claim whose fingerprint MATCHES the retry
        // (an identical request that crashed mid-flight): null response, 10m old.
        let matching_fp = request_fingerprint("POST", "/t", b"{\"x\":1}");
        sqlx::query(
            "INSERT INTO idempotency_records (user_scope, key, fingerprint, claim_id, created_at) \
             VALUES ($1, $2, $3, 'abandoned-claim', NOW() - INTERVAL '10 minutes')",
        )
        .bind(user)
        .bind(key)
        .bind(&matching_fp)
        .execute(pool)
        .await
        .unwrap();

        // The identical retry must RECLAIM and RUN the handler (200, not 409).
        let (status, replayed, _) = body_string(
            app_for(user)
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
        sqlx::query(
            "INSERT INTO idempotency_records (user_scope, key, fingerprint, claim_id, created_at) \
             VALUES ($1, $2, $3, 'abandoned-claim', NOW() - INTERVAL '10 minutes')",
        )
        .bind(user)
        .bind(key)
        .bind(&matching_fp)
        .execute(pool)
        .await
        .unwrap();
        let (status_diff, _, _) = body_string(
            app_for(user)
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

        // One record well past the retention window, one fresh.
        sqlx::query(
            "INSERT INTO idempotency_records \
             (user_scope, key, fingerprint, claim_id, response_status, response_body, created_at) \
             VALUES ($1, 'old', 'fp', 'c', 200, '{}', NOW() - INTERVAL '2 days')",
        )
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO idempotency_records \
             (user_scope, key, fingerprint, claim_id, response_status, response_body, created_at) \
             VALUES ($1, 'new', 'fp', 'c', 200, '{}', NOW())",
        )
        .bind(user)
        .execute(pool)
        .await
        .unwrap();

        let removed = sweep_expired_records(pool).await.unwrap();
        assert!(removed >= 1, "the expired record must be swept");

        let old: Option<(String,)> = sqlx::query_as(
            "SELECT key FROM idempotency_records WHERE user_scope = $1 AND key = 'old'",
        )
        .bind(user)
        .fetch_optional(pool)
        .await
        .unwrap();
        let fresh: Option<(String,)> = sqlx::query_as(
            "SELECT key FROM idempotency_records WHERE user_scope = $1 AND key = 'new'",
        )
        .bind(user)
        .fetch_optional(pool)
        .await
        .unwrap();
        assert!(old.is_none(), "the expired record was deleted");
        assert!(fresh.is_some(), "the fresh record was retained");

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
