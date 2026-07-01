# Operator resolution of a ReconcileRequired agent job — POST .../jobs/{id}/reconcile

Status: SHIPPED (run-3 discovery swarm, CONFIRMED H/M). codex plan APPROVE (3 MINORs folded in:
request_id in the response, the non-alerting resolution event, the request-stays-Executing test);
codex impl review APPROVE (no findings). The COMPANION to the just-shipped
reconcile-required ALERT (dcb8413): now that operators are alerted to a `ReconcileRequired` job,
they need the action to CLOSE it. Together these close both ReconcileRequired gaps (no event → no
exit). Additive admin endpoint, NO migration (`Failed` is already a terminal status).

## The gap (verified)
`expire_leases` moves a LiveApply job whose lease expired to `ReconcileRequired` (agents.rs:1569) —
the operator-recovery state for the HIGHEST-risk mode (real provider infra may be half-applied). But
there is NO route/handler to move a job OFF `ReconcileRequired`: `admin_requeue_dead_lettered_job`
(agents.rs:2591) deliberately REFUSES LiveApply ("it reconciles, it does not redispatch",
agents.rs:2635), and every other handler CASes on `Pending`/`DeadLettered`. So a job an operator has
reconciled out-of-band is a permanent dead-end — it lingers in admin lists / the alert feed forever
and can never be cleanly retired.

## Design — CAS ReconcileRequired → Failed, audited (mirror requeue/set_priority)
A new admin endpoint that resolves the job to a terminal status. `Failed` is the conservative,
correct terminal (the finder's recommendation, NO migration): the agent died mid-apply, so the CP
CANNOT verify the apply succeeded — `Failed` is the honest outcome, and the operator's out-of-band
reconciliation is recorded in the audited `reason`. (A new `Reconciled` terminal would claim more
than the CP can verify + needs a CHECK-widening migration — deferred / rejected.)

### Endpoint — POST /api/admin/agents/jobs/{job_id}/reconcile (admin)
`admin_resolve_reconcile_required_job(Path(job_id), Extension<AuthSession>, Json<ReconcileBody>)`,
mirroring `admin_set_job_priority` (agents.rs:2717) for the CAS + `admin_requeue_dead_lettered_job`
for the audit:
1. `check_permission(&session, "admin")` → 403.
2. `reason` (ReconcileBody) trimmed non-empty, ≤2000 (mirrors fail/rework/requeue reason rules).
3. parse uuid → 404; `get_db()` → 503.
4. CAS in one tx: `UPDATE agent_jobs SET status='Failed', updated_at=NOW() WHERE id=$1 AND
   status='ReconcileRequired' RETURNING request_id::text, platform`.
   - `Some((request_id, platform))` → proceed.
   - `None` → distinguish (a clean 404 vs 409): `SELECT status FROM agent_jobs WHERE id=$1` → no
     row = 404 not-found; a row = 409 `"job is in status '{status}'; only ReconcileRequired jobs can
     be resolved"` (idempotent: a second resolve 409s).
5. Audit: `record_audit_tx` + `security_audit("agent-job-reconcile-resolved",
   Some("reconcile-required"), "failed", { job_id, request_id, platform, reason })`. The free-text
   `reason` lives ONLY in the audit_log detail (operator-authored audit trail).
6. RESOLUTION EVENT (codex): the reconcile-required Critical alert is event-lifecycle-based (a
   `job.reconcile_required` domain event surfaced by the alert feed). To close that lifecycle, emit a
   NON-ALERTING `job.reconcile_resolved` domain event in the same tx (aggregate_type `agent_job`,
   `to_status` `"reconcile-resolved"` — NOT in the classifier / `alert_worthy_statuses()`, so it does
   NOT page). Payload: `{ to_status, platform, request_id, note }` — a STATIC note, NO free-text
   `reason` (the operator-authored reason stays audit-only; it could contain secrets a runbook tells
   operators not to paste). So the events feed shows required → resolved; the alert feed is not
   re-paged.
7. Commit. Return `{ job_id, request_id, status: "Failed", resolved: true, note: "the parent request
   remains Executing; conclude it with POST /api/requests/{id}/fail. A live-apply cannot be retried
   in place (its slot is permanently consumed); re-attempting requires a fresh request" }` —
   `request_id` so the operator's next `/fail` target is unambiguous (codex MINOR). NOTE (run-7): the
   note says **conclude with `/fail`**, NOT "retry" — there is no in-place live-apply retry (see
   "Out of scope" below); the original "fail or retry it separately" wording overpromised a
   capability that does not exist.

### Route
`.route("/api/admin/agents/jobs/{job_id}/reconcile", post(admin_resolve_reconcile_required_job))` —
a static `reconcile` suffix after the `{job_id}` param (same shape as the shipped
`/jobs/{job_id}/priority` and `/jobs/{job_id}/result`; route-tree smoke confirms no collision).

### Secret hygiene
The audit detail carries job_id / request_id / platform / the operator's reason — no spec /
live_context / credential / grant material (the same projection the dead-lettered list uses). The
operator `reason` is operator-authored audit text, the correct place for it.

## Tests (agents.rs db tests + a no-DB 403)
- happy (DB): seed a `ReconcileRequired` LiveApply job whose parent request is `Executing` → POST
  resolve → 200 `{status:"Failed", resolved:true, request_id}`; the job row is now `Failed`; the
  PARENT REQUEST is STILL `Executing` (job-scoped resolve does not touch it — codex); one
  `agent-job-reconcile-resolved` audit row with the reason + request_id; one non-alerting
  `job.reconcile_resolved` domain event (and it is NOT alert-worthy).
- wrong-status + double-resolve (DB): a `Pending` (or `Failed`) job → 409 (only ReconcileRequired
  resolvable); a SECOND resolve of the now-`Failed` job → 409 and writes NO second audit row
  (race-safe + non-duplicating — not "idempotent" in the API-result sense; codex).
- unknown (DB/no-DB): unknown job_id → 404; malformed id → 404.
- 403 (no-DB): a non-admin session → 403.
- empty reason → 400.

## Out of scope (the deferred companion)
- Atomically failing the STRANDED PARENT REQUEST (it stays `Executing`). The operator uses the
  existing `POST /api/requests/{id}/fail` separately; making resolve ALSO CAS the request
  Executing→Failed (requests→agent_jobs lock order, like requeue) is a follow-up — it crosses into
  the request-lifecycle that contracts.rs owns, so it warrants its own change.
- A `Reconciled`-success terminal (vs `Failed`) — needs a migration + claims more than the CP can
  verify.
- **Operator-gated live-apply RE-DISPATCH after reconcile (run-7 decision — DEFERRED owner
  decision).** A terminal non-Succeeded LiveApply permanently consumes the request's single
  live-apply slot (`idx_agent_jobs_unique_live_apply` spans ALL statuses; migration 057). So there is
  NO in-place retry today: the only in-place exit is `/fail`, and re-attempting requires a fresh
  request (a new lifecycle re-planned/re-approved against the CURRENT state). execution-agent.md §5's
  "operator … explicitly re-dispatches" half is NOT built — it overlaps the LiveRefused-recoverability
  / operator-re-approve decision and needs its own trust-model work (operator attestation that the
  prior apply left a known state, a new signed grant, a fresh plan-vs-current check). Until the owner
  decides, the contract is fail-closed: reconcile → `/fail` → fresh request. Do NOT narrow the index
  predicate to non-terminal statuses to enable retries — that turns the no-double-apply invariant
  fail-open.
