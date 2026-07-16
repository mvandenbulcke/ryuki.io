# Fleet-wide circuit-breaker status — GET /api/integrations/circuits

Status: SHIPPED (fresh discovery swarm, CONFIRMED H / S / low-risk). Plan review
NEEDS-CHANGES → APPROVE (route-shadow MAJOR closed by the `ic-` id prefix; now-after-SELECT,
state allow-list, FK-cascade MINORs folded in); implementation review APPROVE (no defects; the
half_open/closed allow-list test coverage added per the residual note). The SMALLEST additive
read: the one durable failing-integration signal with NO aggregate operator view. NO migration,
NO hot-path, NO mutation.

## The gap (verified)
`circuit_breakers` is written (integration.rs:1579 INSERT-on-open, :1630 DELETE-on-reset) and gates
provider calls, but EVERY read filters by a single connection: `BREAKER_SELECT` (integration.rs:1473)
is `... WHERE connection_id = $1`, and the only HTTP surface is `GET /api/integrations/{id}/circuit`
(integration.rs:1487, per-connection). So an operator cannot answer "which integration breakers are
OPEN right now?" without polling every connection id serially. Every other time-sensitive signal in
the codebase ships an aggregate operator list (`/api/protect/secrets/expiring`,
`/api/integrations/credentials/expiring`, `/api/identity/gmsa/expiring`, …) — the open-breaker state
is the only one without. An open breaker means a provider integration is actively failing and being
gated THIS MOMENT: the most time-sensitive operability signal the platform persists.

## Design — mirror the per-connection circuit read + the aggregate-list pattern
`circuit_breakers` only ever holds non-closed rows (a reset DELETEs the row, integration.rs:1630), so
listing the table IS the actionable set (open + half_open). One additive admin read:

### Endpoint — GET /api/integrations/circuits (admin)
`integration_circuits_list(Extension<AuthSession>)`, mirroring `integration_circuit_get`
(integration.rs:1487):
1. `require_admin(&session)?` (the per-connection circuit read is admin-gated; match it).
2. No DB → `{ "source": "no-db", "breakers": [] }` (no durable breakers without a DB).
3. Query (a new list SELECT that ALSO returns `connection_id`, which `BreakerRow` omits — the
   adversarial's mechanical note). Use an explicit state ALLOW-LIST (review MINOR) — defense beyond
   the mig 106 `CHECK (state IN ('closed','open','half_open'))`, so no corrupt/unknown state can
   ever enter the actionable list:
   ```
   SELECT connection_id, state, consecutive_failures, consecutive_successes, opened_at_unix
   FROM circuit_breakers WHERE state IN ('open', 'half_open')
   ORDER BY opened_at_unix DESC NULLS LAST, connection_id
   ```
   (`ORDER BY opened_at_unix DESC` surfaces the most-recently-tripped first; `NULLS LAST` covers a
   `half_open` row whose `opened_at_unix` the mig-106 CHECK does not require.)
4. Sample the shared DB clock via `DB_NOW_UNIX` (integration.rs:1482) AFTER the list SELECT (review
   MINOR) — so a breaker opened between the two statements can never have `opened_at_unix > now_unix`
   (which would make the derived cooldown math odd). The same clock the per-connection read uses, so
   `allow_now`/`cooldown_remaining_secs` never skew between workers.
5. For each row reuse the existing pure renderers: build a `Breaker` from the row (same state-match
   as `breaker_from_row`, integration.rs:1442) and render with `breaker_json(&b, &cfg, now_unix)`
   (integration.rs:1458) — then inject `connection_id`. `cfg = BreakerConfig::DEFAULT` (the same
   default the per-connection read uses).
6. Return `{ "source": "db", "now_unix": <db clock>, "breakers": [ {connection_id, state,
   consecutive_failures, consecutive_successes, opened_at_unix, allow_now, cooldown_remaining_secs} ] }`.

### Route — no shadow (review MAJOR, resolved)
`.route("/api/integrations/circuits", get(integration_circuits_list))` — a STATIC segment in the
`{id}` slot, exactly like the shipped `/api/integrations/credentials/expiring` (integration.rs:1715).
A `connection_id` can NEVER be the literal `circuits`: ids are SERVER-MINTED by `new_connection_id`
(integration_connections.rs:134) as `ic-{vendor_type}-{8hex}` (always `ic-` prefixed; there is no
client-supplied-id path — `integration_create` binds the server-generated id). So the static
`circuits` literal cannot shadow any real `/api/integrations/{id}`. (`circuits` ≠ the other static
`credentials` segment either.) Route-tree smoke additionally confirms axum accepts the tree.

### No orphans (review MINOR, resolved)
`circuit_breakers.connection_id REFERENCES integration_connections(id) ON DELETE CASCADE` (mig
106:12), so deleting a connection cascades away its breaker — the list never shows a breaker for a
since-deleted connection.

### Secret hygiene
The breaker row carries only state + counters + a timestamp + the connection_id — NO credential
material, endpoint, or secret. (The per-connection circuit read already returns these same fields.)

## Tests
- DB: seed a connection + INSERT an `open` circuit_breakers row → GET /circuits lists it with
  `connection_id`, `state="open"`, the counters, and a derived `allow_now`/`cooldown`. A connection
  with NO breaker row (healthy) does NOT appear. (Mirror the existing circuit DB test that asserts a
  default `closed` for an unseeded connection.)
- No-DB: returns `{source:"no-db","breakers":[]}`.
- Route-tree smoke: `full_app_route_tree_builds_without_panic` (the static `circuits` segment vs the
  `{id}` routes — no panic/collision).
- Admin gate: a non-admin session → 403 (require_admin), mirroring the per-connection read.

## Out of scope
- A `?all=true` to also include closed breakers (closed rows don't persist, so there's nothing to
  show; skip).
- The separate (CONFIRMED) follow-up gap from the same swarm: integration-connection MUTATION
  handlers (create/update/delete/circuit_reset/set_credential_expiry) write NO audit_log row — only
  `integration_test` audits (integration.rs:1114). A focused audit-trail slice (richest for the
  destructive `integration_delete`, via `DELETE … RETURNING` for the audit detail) is deferred to its
  own change — create/update are multi-branch tx-bearing handlers that warrant careful, separate work.
