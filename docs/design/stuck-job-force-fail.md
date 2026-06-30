# Admin force-fail of a stuck Leased agent job (run-5)

## Problem

The agent-job lifecycle now lets an admin CANCEL a `Pending` job (8e2cb05) and RESOLVE a
`ReconcileRequired` job (f8c99c0). But a job that was LEASED to an agent which then died (or never
acked) has no admin escape hatch: it sits `Leased` until its lease expires, then `expire_leases`
redispatches it (OfflineDryRun/LivePlan back to `Pending`) or dead-letters it after the cap. An
operator who KNOWS the job is garbage (dead agent, bad spec, decommissioned platform) cannot
terminally fail it NOW — they must wait out N lease-expiry cycles + the dead-letter cap. This adds
an admin force-fail for a `Leased` job.

## Scope: Leased + NON-LiveApply mode ONLY (safety) — codex blocker

Cancel covers `Pending` (not yet leased). This covers `Leased` jobs whose mode is `OfflineDryRun`
or `LivePlan` — modes that NEVER touch real infrastructure (offline validation / read-only plan).
Force-failing one → `Failed` is unambiguously safe: nothing was applied, and a late ack/result is
rejected by the existing result CAS (`… AND status IN ('Leased','Running')` — once `Failed`, 0 rows
match).

EXCLUDED → 409:
- `Running` (agent acked and is EXECUTING) — a running job belongs on the lease-expiry / reconcile
  path, not a blunt force-fail.
- `Leased` **LiveApply** (codex blocker): `Leased` is NOT a mode-agnostic "touched no infra"
  predicate — the agent has the work, and with out-of-order ack/result delivery a `LiveApply` agent
  could have STARTED applying real infra before/while acking. Force-failing it → `Failed` would
  reject a late result and strand unreconciled infra. So a `Leased LiveApply` must go through the
  lease-expiry path, which correctly routes it to `ReconcileRequired`. This endpoint never sets
  `ReconcileRequired` itself (it does not own that alert/audit semantic). This mirrors
  `expire_leases`, which already splits `mode IN ('OfflineDryRun','LivePlan')` (redispatch) vs
  `mode = 'LiveApply'` (ReconcileRequired).

## Approach (mirror `admin_cancel_pending_job`, commit 8e2cb05)

`POST /api/admin/agents/jobs/{job_id}/force-fail` (admin-tier), in `agents.rs`:
- admin permission (403 otherwise); `reason` trimmed, non-empty, ≤ 2000;
- parse `job_id` UUID → 404;
- in one tx, `SELECT status, platform, spec FROM agent_jobs WHERE id = $1 FOR UPDATE` (lock the
  row); not found → **404**; decode the dispatched `JobSpec`. The **`spec.mode` is AUTHORITATIVE**
  (the scalar `mode` column is NOT load-bearing — the agent routes by `spec.mode`, and a row can
  carry `spec.mode=LiveApply` with a different column mode — codex B1). Decide on `spec.mode`:
  `status != 'Leased'` → **409** (`Pending`→use-cancel / `Running`→reconcile-path / terminal);
  `Leased` + `spec.mode == LiveApply` → **409** (protect real infra); else CAS
  `UPDATE … SET status='Failed' WHERE id=$1 AND status='Leased'` (still Leased under the row lock).
  `spec.request_id` is the authoritative parent request for the audit/event/response;
- audit `"agent-job-force-failed"` (`leased` → `failed`) with `{job_id, request_id, platform,
  reason}` (reason audit-only);
- emit a NON-alerting `job.force_failed` event with `to_status: "admin-force-failed"` — deliberately
  NOT in `alert_worthy_statuses()` so the alert prefilter never fetches it (the cancel/reconcile
  precedent);
- commit; response `{job_id, request_id, status: "Failed", force_failed: true, note}`.
- JOB-SCOPED: the parent request stays in its prior state; the operator fails/retries it via
  `POST /api/requests/{id}/fail` (identical to cancel/reconcile). `Failed` is already a valid status
  → NO migration.

## Tests (agents.rs db tests; `Failed` is already allowed, so no CHECK widen)
- force-fail a `Leased OfflineDryRun` job → 200 `{status: Failed}`; row is `Failed`; one
  `agent-job-force-failed` audit row; one `job.force_failed` event with `to_status`
  `admin-force-failed` NOT in `alert_worthy_statuses()`; parent request still actionable; the status
  is now `Failed` (so the result CAS `status IN ('Leased','Running')` rejects a late result).
- force-fail a `Leased LiveApply` job → **409** (codex nit) and the row stays `Leased`, no audit.
- force-fail a `Running` job → 409.
- force-fail a `Pending` job → 409.
- unknown id → 404; non-admin → 403.

## Deferred: scoped-admin scope guard (codex B2 — SYSTEMIC, not force-fail-specific)

Codex flagged that the handler enforces only `check_permission("admin")` and does not
`scope_guard_or_404` the parent request, so a scoped admin (admin role + a `site_scope`) could
force-fail an out-of-scope job. This is REAL but SYSTEMIC: `agents.rs` does not import
`scope_guard_or_404`, and NONE of its ~13 admin handlers (reconcile, cancel, priority, dead-letter
requeue, queue-depth, result, …) scope-guard — the entire execution-plane admin surface treats
`admin` as platform-global. Adding a scope guard to force-fail ALONE would be inconsistent with its
12 siblings (including the already-shipped cancel/reconcile). Whether the execution-plane admin
surface should be site-scoped is a design decision affecting all of them — captured as a SEPARATE
run-5 follow-up (a dedicated agent-job-admin scope-guard sweep), not bolted onto this slice.

## Risk / rollback
Additive: one handler + route, one audit + one non-alerting event. No new status (Failed exists), no
migration, no change to dispatch/lease/result paths. Rollback = revert.
