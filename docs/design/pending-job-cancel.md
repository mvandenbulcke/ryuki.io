# Admin cancel of a Pending agent job (run-3)

## Problem

The agent-job lifecycle (`agent_jobs`, mig 054) has no way for an admin to CANCEL a job. Once a
request dispatches a job it sits `Pending` until an agent leases it — but if the job was created in
error, targets a decommissioned platform, or is simply no longer wanted, there is no terminal exit
except letting an agent pick it up and run it. Operators need to stop a queued job before it
executes. This adds an admin cancel for `Pending` jobs.

## Scope: Pending ONLY (safety)

Cancel applies ONLY to a `Pending` job (not yet leased). Once `Leased`/`Running`, an agent owns the
job and is (or will be) executing it; cancelling CP-side would split-brain (the agent finishes and
reports a result for a "cancelled" job). For those, the operator lets it finish or uses the existing
lease-expiry / reconcile path. A non-Pending job → **409**. This mirrors how `poll_job` only ever
leases `WHERE status = 'Pending'`, so a `Cancelled` job is never dispatched.

## Approach (mirrors `admin_resolve_reconcile_required_job`, commit f8c99c0)

**New terminal status `Cancelled`.** Migration `136_agent_jobs_cancelled_status.sql` widens the
`agent_jobs_status_check` CHECK (ALTER DROP/ADD, guarded, exactly like mig 121 added `DeadLettered`)
to admit `'Cancelled'`. Like `DeadLettered`, `Cancelled` is a CP-internal terminal status and is
NOT added to the `JobStatus` protocol enum — that enum is the agent-facing dispatchable subset, and
`poll_job` filters `status = 'Pending'`, so a `Cancelled` job is never decoded into `JobStatus`
(the `DeadLettered` precedent proves this is consistent and safe). Admin reads return `status` as a
String passthrough.

**Handler** `admin_cancel_pending_job(Path(job_id), Extension(session), Json(CancelBody{reason}))`
in `agents.rs`:
- admin permission required (403 otherwise);
- `reason` trimmed, non-empty, ≤ 2000 chars (mirrors the reconcile reason);
- parse `job_id` as UUID → 404 on a bad id;
- in one tx, CAS:
  `UPDATE agent_jobs SET status = 'Cancelled', updated_at = NOW() WHERE id = $1 AND status =
   'Pending' RETURNING request_id::text, platform`;
- `None` → re-read status: not found → **404**; otherwise → **409**
  (`"job is in status 'X'; only Pending jobs can be cancelled"`). A concurrent double-cancel
  collapses to one success (the second sees `Cancelled` → 409);
- audit `"agent-job-cancelled"` (from `pending` → `cancelled`) with `{job_id, request_id, platform,
  reason}` — the free-text reason lives ONLY in the audit row;
- emit a NON-alerting `job.cancelled` domain event (aggregate `agent_job`) with
  **`to_status: "admin-cancelled"`** — a marker that is deliberately NOT in
  `alert_worthy_statuses()`, so the alert feed's coarse SQL prefilter never even FETCHES it (codex
  B1: relying on `classify()` to drop a prefilter-matched `"cancelled"` is fragile — a future
  `severity_for_agent_job_status` change could silently page cancels; using a non-prefilter status
  is the robust `reconcile-resolved` precedent). Payload carries only static secret-safe fields
  (NO reason);
- commit; response `{job_id, request_id, status: "Cancelled", cancelled: true}`.
- **Job-scoped** (codex B2): the cancel transitions ONLY the job. Its parent request stays in its
  prior state (`executing`) — it is NOT stranded into an invalid state: `executing` is non-concluded,
  so the operator completes the 2-step workflow with the EXISTING, well-tested
  `POST /api/requests/{id}/fail` (valid from any non-concluded state) or a retry. Auto-failing the
  request from here was rejected: it would duplicate the whole request-fail path
  (`request_lifecycle::fail_request` + scope guard + `apply_transition_audited` + the request's own
  audit/event, all in contracts.rs) inside the agents.rs job handler — high cross-aggregate coupling
  for no gain over the existing path. The response surfaces `request_id` so the operator knows which
  request to handle; a test asserts the parent request remains present and `executing` (actionable)
  after the cancel. This is identical to the reconcile-resolve contract.

**Route**: `POST /api/admin/agents/jobs/{job_id}/cancel` (admin tier, beside the reconcile route).

## Tests (agents.rs db tests)
- Cancel a `Pending` job → 200 `{status: Cancelled}`; the row is `Cancelled`; exactly one
  `agent-job-cancelled` audit row (with the reason); one `job.cancelled` domain event whose
  `to_status` is `admin-cancelled`; the test asserts `admin-cancelled` is NOT in
  `event_alerts::alert_worthy_statuses()` — the set the alert feed's SQL prefilter keys on — so the
  prefilter can never fetch a cancel event (codex B1); and the PARENT REQUEST is still present and
  `executing` (actionable — codex B2).
- Cancel a `Leased` job → 409 (and the row stays `Leased`, no audit).
- Cancel an unknown id → 404 (no audit).
- Double-cancel → second is 409.
- Non-admin → 403.

## Risk / rollback
Additive: one new terminal status (CHECK widen), one handler + route, one audit + one non-alerting
event. No change to dispatch/lease/ack/result paths. A `Cancelled` job simply never leases (it left
the `WHERE status='Pending'` dispatch + priority-index predicates). Rollback = revert + (optionally)
narrow the CHECK once no `Cancelled` rows exist.
