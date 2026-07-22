# HTTP idempotency keys

Status: **design + slice 1 implemented**. Author: platform.

## Problem

The POST "create" endpoints generate a fresh `Uuid::new_v4()` and INSERT with no
idempotency mechanism. A client retry after a network timeout (the response was
lost in flight) therefore creates a **duplicate** resource — a second campaign,
emergency change, incident, runbook, etc. with a different id but the same
payload. This is systemic across the create handlers, not a localized bug; the
fix is a cross-cutting idempotency layer, not per-handler patches.

## Design

Standard HTTP idempotency: a client that wants at-most-once create semantics
sends an `Idempotency-Key` header (an unguessable UUID it generates). The server
remembers the first response for that key and **replays** it on a retry instead
of re-executing.

### Middleware

A single Axum `idempotency_middleware` layer wraps the router:

1. **Pass-through** when the request is not a mutating method, has no
   `Idempotency-Key` header, has no authenticated session, or no DB is
   configured — zero behavior change for every existing client.
2. Buffer the request body and compute an authorized fingerprint from both the
   request digest (`method`, path-and-query, body) and the server-derived
   `AuthSession` authority digest. The authority digest binds the principal,
   provider mode, actor class, token-validity state, and canonicalized role,
   site-scope, and environment-scope sets. A key reused with a *different*
   request or a differently authorized credential is therefore detected.
3. **Atomically claim** the key for `(user_scope, key)`: `INSERT INTO
   idempotency_records (user_scope, key, fingerprint) … ON CONFLICT
   (user_scope, key) DO UPDATE … WHERE <the existing row is an abandoned
   in-flight claim>`. The statement claims the key when no record exists OR when
   the existing record is an in-flight claim older than the TTL (a crashed
   request's row is taken over). A fresh in-flight, a completed, or a
   different-fingerprint record does not match the guard, so the statement
   returns no row and the conflict path runs.
   - **Claimed** → run the handler, capture `(status, body)`, store them on the
     record, and return the response.
   - **Conflict + same fingerprint + a stored response** → **replay** the stored
     `(status, body)` (the retry case; no re-execution).
   - **Conflict + same fingerprint + no stored response yet** → a concurrent
     in-flight request holds the key → **409** "request in progress, retry".
   - **Conflict + different fingerprint** → **422** "Idempotency-Key reused with
     a different request".
4. Records older than the TTL are ignored on lookup and swept, so a key is
   reusable after the window (and the table stays bounded).

Only mutating responses are stored; a server error (5xx) is **not** persisted as
the idempotent outcome, so a transient failure can be retried. **Only responses
the middleware can faithfully replay are deduped** — i.e. `application/json`
bodies carrying no header a body-only replay would drop. A non-JSON body, or a
JSON response with `Location`, `Set-Cookie`, `ETag`, `Content-Location`, or
`Content-Encoding`, releases the claim and passes through unstored, so we never
replay a header-stripped or corrupted response.

### Permanent-lockout safety (in-flight TTL)

A claimed record whose handler never stored a response (the process crashed, the
task was cancelled, or the final UPDATE failed) would otherwise leave the row
`response_status IS NULL` forever and **409 every retry permanently**. The claim
INSERT therefore reclaims any in-flight record older than `IN_FLIGHT_TTL`
(5 minutes — far longer than any create handler) by taking over its row. A key
can never lock out.

### Scope by the principal, not the key alone

Records are keyed by `(user_scope, key)` where `user_scope` is the authenticated
opaque `session.principal_id` rendered as its canonical UUID (the middleware
runs *inside* auth). A provider subject or compatibility display identifier is
never accepted as this namespace. One principal's key can never collide with —
or replay — another principal's response, even if the key value is reused or
leaked. An unauthenticated mutating request has no session and is not deduped
(pass-through).

The namespace intentionally remains principal-based, while the stored
fingerprint is authorization-aware. Two API tokens may share the same
opaque principal, but a role, site-scope, environment-scope, provider, actor
class, or validity difference changes their fingerprint. Reusing the broader
token's key with a narrower token therefore returns the different-request 422
instead of replaying a response before the narrower token reaches its handler
scope guard. A database-backed HTTP regression covers both site and environment
attenuation for the canonical R01-MB-C226 path.

### Opaque-principal namespace cutover

Migration 199 cannot translate legacy provider-subject replay rows into opaque
principal UUIDs and therefore removes them during its non-overlapping registry
cutover. That deletion must not shorten the advertised 24-hour at-most-once
window: a client can legitimately retry a committed mutation whose response
was lost immediately before the migration.

Migration 200 consequently upgrades the database writer marker to contract v3,
recreates its trigger over `INSERT`, `UPDATE`, and `DELETE`, and makes that
trigger `ALWAYS`. Its exclusive preflight rejects any retained post-199
in-flight claim and any retained namespace that does not exactly match an
existing opaque principal. (When migrations 199 and 200 co-apply, migration
199 has already removed the legacy rows.) Every later non-owner v3 write must
also name an existing canonical principal, so a direct writer cannot recreate
a provider-subject namespace.

The platform migration runner records whether the database was pristine before
the embedded migration inventory began. A pristine install persists a no-fence
state and may serve immediately; a conservative missing/upgrade marker requires
the fence. For an upgrade, the deadline is migration 199's PostgreSQL
transaction-start timestamp plus 24 hours and a conservative five-minute
margin. The required traffic withdrawal and zero-session drain precede that
transaction, so the deadline preserves more than the complete replay window
after the last possible old mutation; `installed_on` is not treated as a commit
timestamp. The database stores that decision in the trusted,
migration-owner-managed
`idempotency_principal_cutover_state` row, and strict startup re-attests the
row, tables, exact function body/configuration/owner/ACL, and sole `ALWAYS`
trigger before serving. This detects structural and accidental drift; as with
the ledger and every schema object, a compromised migration owner remains
outside the serving-role threat boundary.

Until that deadline, a least-privilege application role cannot insert, update,
or delete replay state. Because the `BEFORE INSERT` contract runs before
uniqueness conflict handling, even a retry that could otherwise replay an
already-completed post-cutover row receives the same temporary fail-closed
response. Claim failure remains a retryable 503 and occurs before the handler
runs. The schema/migration owner is exempt so migration work and principal
lifecycle invalidation can proceed, but production postflight proves that this
owner is not the serving role. At the deadline, every possible pre-199 receipt
is outside its promised retention window and normal UUID-scoped claims,
finalization, release, and retention deletion resume.

### Storage

`idempotency_records (PRIMARY KEY (user_scope, key), fingerprint,
response_status, response_body, response_bytes, created_at)`.
`response_status`/`response_body` are NULL between the claim and the handler
completing (the in-flight window the 409 covers, and the window the TTL reclaim
recovers). `response_bytes` is a generated exact UTF-8 octet count.

### Principal fair-share admission

A fresh key is admitted only while its server-derived principal retains both
row and response-byte headroom: at most 10,000 live rows and 64 MiB of stored
response octets. Admission holds a transaction-scoped advisory lock derived
from the principal, so concurrent fresh keys cannot decide from the same stale
aggregate. An in-flight row reserves the full 1 MiB response capture ceiling;
sealing reconciles it to exact generated octets. Existing keys bypass fresh-key
admission so replay, conflict, and stale same-request takeover remain available
at quota. A claim or budget-store failure fails closed before the protected
handler runs.

### Writer-contract cutover

Migration 162 originally added a table trigger requiring every INSERT/UPDATE
transaction to declare writer contract v2 and already hold the matching
principal advisory lock. Migration 200 supersedes that contract with v3,
canonical opaque-principal validation, the temporary replay-window fence, and
active-window DELETE protection. The checked-in Kubernetes `platform-api`
Deployment nevertheless uses non-overlapping `Recreate`: pre-162 middleware
failed open on a rejected claim, so the database trigger cannot by itself make
mixed-version request handling safe. Rendered production overlays must preserve
that cutover.

## Slice plan

- **Slice 1.** The `idempotency_records` table (`(user_scope, key)` PK) + the
  middleware (claim / replay / conflict / in-flight / pass-through, per-user
  scoping, in-flight TTL reclaim, JSON-only dedup) wired into the router, with
  unit tests for the fingerprint and decision logic and DB-gated integration
  tests for claim→replay, key-reuse→422, and cross-tenant isolation.
- **Slice 2a (this change).** The retention sweep: a background task
  (`spawn_idempotency_sweep`) deletes records older than the 24h retention
  window every hour, bounding the table and making a key reusable after the
  window. DB-gated test for expired-deleted / fresh-retained.
- **Slice 2b (this change).** Require the header on the highest-risk routes
  rather than leaving it optional: a `require_idempotency_key` route-layer guard
  returns `400 IDEMPOTENCY_KEY_REQUIRED` when the header is absent. Applied first
  to `POST /api/ops/emergency/initiate` (break-glass, irreversible). The guard
  shares `usable_idempotency_key` with the dedup middleware so they cannot drift,
  and composes inside it (a present key is already claimed, so the route still
  dedups). Extending to the portal-called high-risk routes (live-apply approve,
  token mint) first requires teaching the portal's single egress
  (`UpstreamClient`) to generate and send a key — otherwise those flows 400.

### One-time secrets are never stored (`Cache-Control: no-store`)

A handler that reveals a one-time plaintext secret (e.g. `admin_tokens_create`
returns a freshly minted token exactly once, persisting only its hash) sets
`Cache-Control: no-store` on its response. The middleware honors that directive:
a no-store response releases its claim and is **not** stored or replayed, so the
plaintext never lands at rest in `idempotency_records`. The trade-off is that
such an endpoint is not deduplicated — a retry re-runs (its pre-idempotency
behavior) rather than replaying a stored secret, which is the correct one-time
semantic. This is enforced centrally in `is_replayable`, not per handler.

## What this does NOT do

Clients that do not send `Idempotency-Key` get exactly today's behavior (a retry
still duplicates) — idempotency is opt-in per request, the standard HTTP
contract. The only handler change is the `no-store` header on one-time-secret
responses (correct HTTP hardening, independent of this feature).

The fingerprint does not bind a raw token UUID. Credentials with the same
server-derived principal and identical effective authorization are deliberately
replay-equivalent; this does not cross the delegated-token scope boundary in
R01-MB-C226. The generic middleware also does not invent a version for mutable
resource-specific policy that is absent from `AuthSession`. A future route whose
response authorization can change without changing the bound session authority
must opt out with `Cache-Control: no-store` or add an explicit route-level
revalidation contract before it is eligible for replay.
