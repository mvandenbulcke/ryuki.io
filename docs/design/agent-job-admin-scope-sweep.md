# Agent-job admin scope-guard sweep (run-5 A0)

## Decision (ADR)

The execution-plane admin surface in `sources/ryuki-api/src/agents.rs` **IS site-scoped**, not
platform-global. This closes a cross-scope capability + state-oracle: a scoped admin (admin role +
non-empty `site_scope`/`environment_scope`, issuable via an `api_tokens` row) could mutate or
state-oracle an out-of-scope request's agent job, even though the same principal is already 404'd
from that request's lifecycle handlers in `contracts.rs`.

### Why scoped (the orthogonality invariant)
Scope is orthogonal to permission tier — proven, not assumed:
- `AuthSession` carries `roles` and independent `site_scope`/`environment_scope`
  (auth.rs:58); `check_permission` derives only from roles (auth.rs:241); `scope_permits` checks
  only the scope vectors (auth.rs:270). A token can hold `admin` AND a `site_scope`.
- `requests_approve_live_apply` checks `admin` then `scope_guard_or_404`, commented *"Admin
  permission alone does not imply unrestricted scope."* (contracts.rs:15452), with a passing test
  that a `site_scope=["GBLON"]` admin gets **404** on a DEFRA request (contracts.rs:47784).

The agent-job admin surface is a **second control surface over the same requests**: force-fail /
cancel / reconcile / requeue / reprioritize / read-state of the job an out-of-scope request spawned.
Leaving it unscoped bypasses the front-door guard through the execution-plane side door.

### Why NOT "admin = superuser"
The run-5 finder's `admin=superuser` assumption (swarm-findings-2026-07-01-run5.md:27-29) is false
for site-bearing resources. The repo DOES have a deliberate platform-global admin class
(`admin_platform_settings_history`, `chargeback_rate_set`, `admin_notification_dispatch_outbox`),
but those resources have no site axis. Agent jobs DO (transitively, via `spec.request_id`).

## The job → request linkage
`agent_jobs` has no `site`/`environment` column; the parent request is reached via the dispatched
**`spec.request_id`** (JSONB `spec` column), which is **authoritative**. The scalar `request_id`
column is NOT load-bearing and can diverge: `create_agent_job` accepts an independent `request_id`
and `spec` (agents.rs:1699), and result ingestion already binds to `stored_spec.request_id` not the
scalar (agents.rs:1213, 1384). `requests.site` / `requests.environment` are `NOT NULL`
(003_requests.sql:6) and **immutable** — no `UPDATE requests SET site/environment` exists anywhere.

## The 3-way split

### Category 1 — by-id, single request → SCOPE GUARD (404). 8 handlers.
Resolve the parent request via `spec.request_id` → `SELECT site, environment FROM requests WHERE
id = $req` → `scope_guard_or_404(&session, &site, &env, &job_id)` **BEFORE** the mutation/read and
**before** any status-409 branch (out-of-scope = 404, no oracle; wrong status = 409).

| Handler | Line | Shape today | Change |
|---|---|---|---|
| `admin_approve_live_apply_job` | 2278 | reads `requests.site` for `enforce_site_operational` only | also fetch `environment`; `scope_guard_or_404` BEFORE operational/status/grant-mint branches |
| `admin_requeue_dead_lettered_job` | 2651 | already decodes `spec.request_id` | guard after decode, before parent-active/status branch |
| `admin_force_fail_job` | 3060 | already `FOR UPDATE` + decodes `spec` | guard after decode, before the `Leased`/`LiveApply` 409s |
| `admin_resolve_reconcile_required_job` | 2812 | UPDATE-first, RETURNING scalar | **add `FOR UPDATE` pre-read** (decode `spec.request_id`), guard, THEN status CAS |
| `admin_cancel_pending_job` | 2935 | UPDATE-first, RETURNING scalar | **add `FOR UPDATE` pre-read**, guard, THEN status CAS |
| `admin_set_job_priority` | 3213 | UPDATE-first, RETURNING scalar | **add `FOR UPDATE` pre-read**, guard, THEN status CAS |
| `admin_agent_job_result` | 3374 | reads result by job_id | decode `spec.request_id` (or `FOR UPDATE`-free read of `spec`), guard before returning result |
| `admin_agent_job_get` | 3464 | reads `/state` by job_id | same — guard before returning state |

**TOCTOU.** Under the job-row `FOR UPDATE` lock + immutable `requests.site`, the post-load guard is
TOCTOU-safe; a site-in-CAS subquery is optional defense-in-depth (skip it). Note: this safety
assumes no production hard-delete of a `requests` row mid-tx (none found).

### Category 2 — aggregates / lists → VECTOR NARROW. 2 handlers.
For a scoped principal, join `requests` via the **extracted `spec.request_id`** and narrow with the
existing multi-scope vector helpers (NOT a single-value filter — scopes are comma-separated vectors,
main.rs:256). Exclude orphan / malformed-spec rows from a scoped principal's view. An unrestricted
(empty-scope) admin's query is unchanged (sees all, including orphans). Because `requests.site/
environment` are NOT NULL, there is **no nullable-axis policy split** here.

| Handler | Line | Change |
|---|---|---|
| `admin_dead_lettered_jobs` | 2619 | scoped: `JOIN requests r ON r.id = (aj.spec->>'request_id')::uuid` + vector `ANY` filter on `r.site`/`r.environment` before `ORDER BY ... LIMIT 500` |
| `admin_agent_queue_depth` | 3321 | scoped: same join + vector filter before `GROUP BY platform`; reuse the contracts.rs aggregate-narrowing helper vocabulary (`enforce_scope_filters` / `multi_scope`) rather than hand-rolling |

### Category 3 — agent-FLEET lifecycle → DENY-IF-SCOPED (403). 4 handlers.
`agents.platform` is **site-adjacent** (protocol calls it "platform / site", types.rs:131; leasing
matches `agent_jobs.platform = agent.platform`, agents.rs:570) but there is no `platform → site`
mapping in the schema, so a coherent dual-axis scope cannot be resolved. Posture: a fleet operation
requires an **unrestricted** principal — mirrors the repo's "platform-wide rows only for unrestricted
principals" pattern (contracts.rs:23708). A scoped principal (any non-empty `site_scope` OR
`environment_scope`) gets **403**, evaluated as a session-property gate BEFORE any row lookup (so no
existence oracle).

| Handler | Line | Change |
|---|---|---|
| `admin_approve_agent` | 356 | deny-if-scoped 403 (fleet mutation) |
| `admin_revoke_agent` | 462 | deny-if-scoped 403 (fleet mutation — revoking a runner is a cross-site DoS) |
| `admin_list_agents` | 2453 | deny-if-scoped 403 (fleet read) |
| `admin_agents_liveness` | 2580 | deny-if-scoped 403 (fleet read) |

## Tests (agents.rs db tests; per-domain, `make test-db`-gated — do NOT run full test-db)
- Cat 1, per handler: scoped-admin (`site_scope=["GBLON"]`) out-of-scope → **404** (no oracle vs a
  missing id); in-scope → acts normally; unrestricted admin → unchanged. Mirror
  contracts.rs:47784. For the 3 new-pre-read handlers also assert order: out-of-scope wrong-status
  job → 404 (not 409).
- Cat 2: scoped admin sees only in-scope rows/counts; orphan/malformed-spec row excluded for scoped,
  included for unrestricted; unrestricted sees all.
- Cat 3, per handler: scoped admin → **403**; unrestricted admin → acts.

## Deferred follow-ups (NOT in this slice)
1. **Scoped fleet reads by platform.** If `platform == site` is ever documented/enforced, narrow
   `list_agents`/`liveness` by `agents.platform` for scoped principals instead of denying. Needs a
   real platform↔site mapping first.
2. **Hard `request_id == spec.request_id` invariant** (DB CHECK or app guarantee at insert). Once
   in place, scoped aggregates could trust/index the scalar column instead of JSONB extraction.

## Risk / rollback
Additive guards + one ADR + tests; no schema change, no migration, no behavior change for
unrestricted principals. Rollback = revert.

## Implementation notes (defensible deviations from the literal design)
- **By-id guards use `row_scope_permits` + each handler's OWN `not_found(...)`**, not
  `scope_guard_or_404`. Reason: agents.rs `not_found` emits `{"error":"agent job '{id}' not
  found"}`, which differs from contracts.rs `status_404`. Using the predicate + the handler's
  native missing-message makes the out-of-scope 404 BYTE-IDENTICAL to that handler's missing 404 —
  strictly more oracle-safe within agents.rs.
- **Every by-id guard is gated on `if is_scoped(&session)`** so an unrestricted admin skips the
  scope resolution entirely — zero extra queries, behavior byte-unchanged (the documented
  `is_scoped` short-circuit).
- **reconcile / cancel / set_priority** gained a NEW `SELECT spec … FOR UPDATE` pre-read before the
  status CAS (they were UPDATE-first); guard runs before the 409 → out-of-scope is 404 not 409.
- **Aggregates** JOIN `requests` via `r.id::text = (aj.spec->>'request_id')` (TEXT compare) rather
  than `(…)::uuid` — the cast THROWS (500s the whole query) on a malformed value; the text compare
  excludes malformed/orphan rows cleanly per the design's exclusion requirement.
- **approve_live_apply** 404s out-of-scope AND unknown requests identically for a scoped principal
  (no oracle vs the downstream create_live_apply_job error); unrestricted path unchanged.

## Coverage
20 db tests, all green against a live DB (`db_scope_*`): 8 by-id out-of-scope→404 (incl. 5
wrong-status→404-not-409 oracle-ordering cases), requeue in-scope happy path, dead_lettered +
queue_depth scoped-narrow + dead_lettered unrestricted-sees-all, 4 fleet scoped→403. **Gap (by
design):** `approve_live_apply` has no db test — its `cp_signing_key` 503-check precedes the guard,
so a db test needs CP-key setup that reorders past it; the guard was verified by inspection and
independent review instead.
Test gotchas fixed: the scoped-admin helper must use `APP_ROLE_PLATFORM_ADMIN` (role `"admin"` grants
nothing → 403 before the guard); tests use `handler_pool_lenient()` (strict `handler_pool()` silently
SKIPS on local migration drift, masking everything).

## Review
Decision rationale reviewed (APPROVE-WITH-CHANGES; all 6 changes folded in above).
Implementation reviewed before commit (see commit trailer).
