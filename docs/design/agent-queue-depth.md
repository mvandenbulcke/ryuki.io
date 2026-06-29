# Agent queue-depth visibility — GET /api/admin/agents/queue-depth

Status: SHIPPED (codex plan APPROVE + codex impl APPROVE, no findings; 2 MINORs folded in
— the handler maps each
`QueueDepthRow` to `json!` MANUALLY (FromRow alone isn't enough for serialization), and the
`oldest_pending_at` test binds a FIXED `DateTime<Utc>` into `created_at` and asserts exact
equality, not a `NOW() - INTERVAL` value). Verify-first swarm 2026-06-29 finding #6 (read
slice) — ALSO the pending-jobs view deferred from #15 (job prioritization). VERIFIED: no
queue-depth/pending-count endpoint exists; `admin_list_agents` (agents.rs:2320) lists agents
with their RECENT (leased) jobs, not the PENDING backlog per platform. So an operator has no
visibility into how deep the dispatch queue is for a platform — and, after #15, no way to
see which platform's queue to reprioritize. Additive: NO migration (priority already exists
from #15), NO engine change.

## Scope of this slice
The READ half of swarm #6 (operator visibility into queue backing). The WRITE half —
backpressure (a MAX_PENDING cap + reject/delay on create_agent_job) — is DEFERRED: it
touches the critical request→job creation path and needs its own careful change. This slice
is a pure admin read.

## Endpoint — GET /api/admin/agents/queue-depth
`admin_agent_queue_depth(Extension<AuthSession>)`, mirroring `admin_list_agents`:
1. EXPLICIT `check_permission(&session, "admin")` → 403 (defense-in-depth: GET routes under
   /api/admin/ may not be gated by the RBAC middleware, which typically covers mutating
   methods — admin_list_agents re-checks for exactly this reason).
2. `get_db()` → 503.
3. One aggregate query (agent_jobs are PLATFORM-scoped, admin-wide — no site axis):
   ```sql
   SELECT platform, COUNT(*) AS pending_count,
          MIN(created_at) AS oldest_pending_at, MAX(priority) AS top_priority
   FROM agent_jobs WHERE status = 'Pending'
   GROUP BY platform ORDER BY platform
   ```
   Only `Pending` jobs are "queued" (Leased/Running/Succeeded/Failed/Expired/Reconcile
   Required/LiveRefused/DeadLettered are excluded). Each group has ≥1 row, so the aggregates
   are non-null (no Options).
4. Return `{ "queues": [ {platform, pending_count, oldest_pending_at: <rfc3339>,
   top_priority}, ... ] }`. A `FromRow` `QueueDepthRow { platform: String, pending_count:
   i64, oldest_pending_at: DateTime<Utc>, top_priority: i32 }`. No secret/spec/live_context
   exposure (only the aggregates + platform name).

## Route
`.route("/api/admin/agents/queue-depth", get(admin_agent_queue_depth))` — static
`queue-depth` in the `{agent_id}` slot (matchit static-wins, same as `liveness`/
`dead-lettered-jobs`/`jobs`; route-tree smoke confirms).

## Tests (agents.rs db tests + a no-DB 403)
1. **happy** (DB, handler_pool + DB_TEST_SERIAL): seed pending jobs across TWO unique
   platforms — platform A with 3 pending (one bumped to priority 9, one backdated oldest),
   platform B with 1 pending; ALSO a non-pending (Leased) job on A. GET → the A entry has
   pending_count 3 (the Leased one EXCLUDED), top_priority 9, oldest_pending_at = the
   backdated instant; the B entry has pending_count 1. (Assert on the seeded platforms by
   name — other platforms in the shared DB are ignored.)
2. **only-pending**: the Leased job on A is NOT counted (covered by #1's count == 3).
3. **403**: a non-admin session → 403 (before DB).
Use unique platform names (fresh uuid) for isolation; cleanup by platform.

## Files
- sources/ryuki-api/src/agents.rs (admin_agent_queue_depth + QueueDepthRow + route + tests).
NO migration, NO engine change.

## Out of scope
- Backpressure / a MAX_PENDING_PER_PLATFORM cap + reject-on-create (the WRITE half of #6 —
  a separate change touching the job-creation critical path).
- Per-job-kind / per-priority breakdown beyond the top priority (extensible later).
- Site-scoping (agent_jobs are platform-scoped; this is an admin-wide operational view).
