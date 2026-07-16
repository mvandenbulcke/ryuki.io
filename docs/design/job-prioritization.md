# Job prioritization — priority-weighted agent-job dispatch

Status: SHIPPED (plan review APPROVE + implementation review APPROVE, no findings; 4 MINORs folded in,
1 deferred — see "## Plan-review fixes" at the end). Verify-first swarm 2026-06-29
finding #15.
VERIFIED: agent-job dispatch (`poll_job`, agents.rs:549) is `SELECT id FROM agent_jobs
WHERE platform = $6 AND status = 'Pending' ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT
1` — strict FIFO by `created_at`, NO priority. `agent_jobs` (mig 054 + 055/056/121) has NO
priority column. So a critical job queued behind a backlog waits its turn. Additive: ONE
migration (column + index), the dispatch ORDER BY, and an admin reprioritize endpoint.

## Migration 127 (migrations/127_agent_jobs_priority.sql)
Latest migration is 126 → 127 is next.
```sql
ALTER TABLE agent_jobs
    ADD COLUMN IF NOT EXISTS priority INT NOT NULL DEFAULT 5
    CHECK (priority BETWEEN 0 AND 9);
-- The dispatch index: most-urgent-first, then FIFO, within the pending set per platform.
CREATE INDEX IF NOT EXISTS idx_agent_jobs_dispatch
    ON agent_jobs (platform, priority DESC, created_at)
    WHERE status = 'Pending';
```
`DEFAULT 5` = normal; higher = more urgent (0..=9). Every existing `INSERT INTO agent_jobs`
(create_agent_job etc.) omits `priority`, so they ALL get the default — NO insert changes.
`AGENT_JOB_COLUMNS`/`AgentJobRow` are NOT touched (the dispatch RETURNING doesn't need
priority; the reprioritize endpoint uses its own RETURNING).

## Dispatch (agents.rs poll_job, line 549)
`ORDER BY created_at` → `ORDER BY priority DESC, created_at` (most-urgent-first, then FIFO
within a priority). The `FOR UPDATE SKIP LOCKED LIMIT 1` is unchanged, so a higher-priority
Pending job is leased before a lower-priority one; ties keep FIFO. (The test-only duplicate
of this query at agents.rs:3216 gets the same change for consistency.)

## Admin reprioritize endpoint (agents.rs)
`POST /api/admin/agents/jobs/{job_id}/priority`, mirroring `admin_requeue_dead_lettered_job`
(Extension<AuthSession>, `check_permission("admin")`, agents.rs error helpers):
- Body `{ "priority": <0..=9> }` (deny_unknown_fields); out of range → 400.
- `admin` permission → 403 otherwise.
- `get_db` → 503; parse uuid → 404.
- `UPDATE agent_jobs SET priority = $1, updated_at = NOW() WHERE id = $2 AND status =
  'Pending' RETURNING id, priority, status`. Only a PENDING job can be reprioritized — a
  Leased/running/terminal job's queue priority is moot (CAS on status).
- 1 row → 200 `{job_id, priority, status}`. 0 rows → re-read: missing → 404; present (not
  Pending) → 409 ("only a pending job can be reprioritized"). Audited
  (`security_audit("agent-job-reprioritize", old?, new, {job_id, priority})`).

## Route
`.route("/api/admin/agents/jobs/{job_id}/priority", post(admin_set_job_priority))`. The
static `jobs` segment coexists with `/api/admin/agents/{agent_id}/...` and
`/api/admin/agents/dead-lettered-jobs/...` (matchit static-wins; route-tree smoke confirms).

## Tests (agents.rs db tests + a no-DB validation)
1. **dispatch order** (DB): seed two Pending jobs for one platform — an OLDER low-priority
   (priority 2) and a NEWER high-priority (priority 8); an approved agent polls → it leases
   the HIGH-priority (newer) one FIRST, despite the older one's earlier created_at. (Proves
   priority beats FIFO.) A second poll leases the remaining one.
2. **reprioritize happy** (DB): a Pending job → POST priority=9 → 200; the row's priority is
   9; an audit row exists.
3. **reprioritize non-pending** (DB): a Leased job → 409; its priority unchanged.
4. **404 / validation** (no-DB or DB): unknown job_id → 404; priority 99 / -1 → 400;
   non-admin → 403.

## Files
- migrations/127_agent_jobs_priority.sql
- sources/ryuki-api/src/agents.rs (dispatch ORDER BY + admin_set_job_priority + Body struct
  + tests), and the route registration (wherever the admin agent routes live).

## Plan-review fixes (SUPERSEDE the body where they conflict)
- **MINOR — `id` tie-breaker.** Dispatch is `ORDER BY priority DESC, created_at, id` (and the
  index is `(platform, priority DESC, created_at, id) WHERE status='Pending'`) so equal
  (priority, created_at) jobs have a fully deterministic, stable order.
- **MINOR — plain `CREATE INDEX`** (not CONCURRENTLY): the sqlx migration runner is
  transactional (CONCURRENTLY can't run in a tx), and `agent_jobs` is a control-plane queue
  (jobs reach a terminal state), not a hot multi-million-row table — consistent with the
  existing partial indexes (mig 122/125). Documented tradeoff.
- **MINOR — range 400 via `bad_request`.** The handler validates `priority` in `0..=9` and
  returns the agents.rs `bad_request(...)` (a clean 400) for out-of-range; a malformed
  (non-int) body is axum's default JSON rejection, as for every other typed body.
- **MINOR — tests.** Add (a) an EQUAL-priority FIFO test (two priority-5 jobs, older
  dispatched first), (b) a DEFAULT-applied assertion (a job inserted without `priority` reads
  back 5), using EXPLICIT backdated `created_at` (no sleeps).
- **MINOR (DEFERRED) — admin job listing.** The existing GET /api/admin/agents lists LEASED
  jobs per agent (agent_id set), whose priority is moot; reprioritization targets PENDING
  jobs (agent_id NULL), which that list does not show. So a usable "see priorities to
  reprioritize" view is a SEPARATE pending-jobs-by-platform endpoint (follow-up), not a
  projection tweak. The reprioritize response returns the resulting priority meanwhile.

## Out of scope
- A pending-jobs-by-platform admin view exposing each job's `priority` (the usable companion
  to reprioritize) — a read follow-up (the reprioritize response + dispatch order make
  priority observable now).
- Deriving the initial priority from request.criticality (criticality is hardcoded
  "standard" today — would be inert; a separate change).
- Starvation prevention / aging (a low-priority job never dispatching while high-priority
  jobs keep arriving) — a fairness follow-up; FIFO-within-priority is the first cut.
