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
2. Buffer the request body and compute `fingerprint = sha256(method ++
   path-and-query ++ body)` so a key reused with a *different* request — even
   one differing only in query string — is detected.
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
`session.user_id` (the middleware runs *inside* auth). One tenant's key can
never collide with — or replay — another tenant's response, even if the key
value is reused or leaked. An unauthenticated mutating request has no session
and is not deduped (pass-through).

### Storage

`idempotency_records (PRIMARY KEY (user_scope, key), fingerprint,
response_status, response_body, created_at)`. `response_status`/`response_body`
are NULL between the claim and the handler completing (the in-flight window the
409 covers, and the window the TTL reclaim recovers).

## Slice plan

- **Slice 1 (this change).** The `idempotency_records` table (`(user_scope, key)`
  PK) + the middleware (claim / replay / conflict / in-flight / pass-through,
  per-user scoping, in-flight TTL reclaim, JSON-only dedup) wired into the
  router, with unit tests for the fingerprint and decision logic and DB-gated
  integration tests for claim→replay, key-reuse→422, and cross-tenant isolation.
- **Slice 2.** A background sweep for expired keys; require the header on the
  highest-risk routes (e.g. `emergency/initiate`) rather than leaving it
  optional.

## What this does NOT do

It does not change any handler. Clients that do not send `Idempotency-Key` get
exactly today's behavior (a retry still duplicates) — idempotency is opt-in per
request, which is the standard HTTP contract.
