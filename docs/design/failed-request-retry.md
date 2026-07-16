# Operator-initiated retry of a FAILED request — POST /api/requests/{id}/retry

Status: **DEFERRED** (plan review NEEDS-CHANGES — 2 BLOCKERS). The gap is real, but the
"one pure fn + one rework-like handler" slice below is UNSAFE: retry of a Failed request is
entangled with the execution-attempt and approval-quorum machinery, and the *valuable* case
(execution failures) is exactly the entangled one. A correct retry is an L-effort,
security-critical change — NOT the small slice the swarm scoped. Recorded here for a proper
future slice; this session pivoted to the clean, fail-open notification-dispatch feature instead.

## Why deferred — plan BLOCKERS (must be solved first)
1. **Stale agent jobs go live again.** After Failed→Intake the request is no longer concluded,
   so an OLD dead-lettered job (correctly blocked while Failed by the agents.rs:2622 guard)
   becomes requeueable, and `poll_job` leases any Pending job by platform with no request
   lifecycle check. Worse, old Leased/Running jobs can still POST results — the result backlink
   only checks the request is currently `executing`, not that the job belongs to the current
   attempt — so a STALE result attaches to a later re-execution. Requires an **execution-attempt
   epoch/fence** (a generation column on agent_jobs; requeue + result-backlink + live-apply must
   reject jobs from a prior epoch), using `spec.request_id` as the source of truth.
2. **Stale approval quorum.** `request_approval_decisions` (the durable quorum ledger consumed by
   `apply_approval_decision_audited`, contracts.rs:14521) is NOT cleared by a →Intake transition.
   After retry→re-plan, OLD approvals would satisfy quorum WITHOUT fresh re-approval (security)
   or the idempotent-role short-circuit blocks a role from re-approving (availability). Requires
   clearing the active ledger in the SAME tx, or an attempt/generation key on the ledger. (Note:
   `rework` shares this latent issue from Approved/Locked — worth a separate audit.)
3. **MAJOR — LiveApply uniqueness.** A prior LiveApply row blocks any future live apply for the
   request (unique index + `prior_apply` check, contracts.rs:15438), so a live-apply failure
   cannot be cleanly re-applied. Either exclude LiveApply failures or design a reconcile path.
4. MINOR: retry reason/actor must go in AUDIT DETAIL (apply_transition_audited does not persist
   arbitrary Request.metadata — narrow payload allowlist). MINOR: non-Failed retry maps to 400
   via map_engine_error, not 409.

Review conclusions (still valid for the future slice): Failed-only is correct (do NOT fold in
Rejected/Cancelled); `execute` permission is defensible ONCE stale approvals/jobs are fenced;
single-only is a reasonable first slice. The blockers are about dependent state, not the gate.

---
ORIGINAL (UNSAFE) PROPOSAL — kept for reference; do not implement as-is:

Additive: NO migration, NO new agent-job path, ONE new pure engine fn + ONE
handler. The smallest cleanly-shippable slice.

## The gap (verified)
A request in terminal `Failed` cannot be re-run. The ONLY terminal-work recovery primitive is
`admin_requeue_dead_lettered_job` (agents.rs:2554) which (a) requeues an AGENT JOB only when it
is `DeadLettered` and (b) explicitly REFUSES when the parent request `is_concluded()`
(agents.rs:2622) — so it cannot help a `Failed` request. `fail_request`
(request_lifecycle.rs:851) has no inverse. `rework_request` (request_lifecycle.rs:882) is gated
to Validated|Planned|Approved|Locked ONLY and refuses concluded states. So an operator whose
request FAILED must manually re-create a brand-new request, losing the id and its history.

## Design — mirror the proven `rework` path (Failed → Intake), NOT a re-dispatch
Both `rework_request` and `fail_request` are STANDALONE pure fns that do NOT use the
invariant-tested `transition_status` allowlist table (request_lifecycle.rs:780). So retry is a
sibling fn in exactly that shape — it needs NO new edge in the transition table (the scout's
feared blast radius does not apply).

`retry_request` sends a `Failed` request back to `Intake` — the same non-running re-entry point
`rework` uses — so the operator re-runs the EXISTING validate → plan → approve → lock → execute
gates. It never un-concludes INTO a running/executing state, never re-fires `begin_execution`
directly, and never bypasses re-approval. The execute path rebuilds the JobSpec fresh from the
request (contracts.rs:16694), so re-running regenerates the agent job cleanly — no agent-job
manipulation here.

### Engine fn (ryuki-engine/src/request_lifecycle.rs) — pure
```
pub fn retry_request(request, actor, reason) -> Result<Request, String>:
  - reason must be non-empty (mirrors rework)
  - status MUST be Failed (else Err "Cannot retry a request in status {:?}. Retry is only
    valid from Failed." — Rejected/Cancelled are DELIBERATELY excluded, see below)
  - clone → status = Intake, updated_at = now
  - metadata: insert retry_reason + retried_by (failure_reason left as history, like rework
    preserves prior artifacts)
```

### Why Failed-only (not Rejected/Cancelled)
`is_concluded()` is true for Failed/Rejected/Cancelled/Completed/Protecting/Operational/Retired.
Retry deliberately un-concludes ONLY `Failed` — a Failed request is an *infrastructure/execution
failure* an operator legitimately wants to re-run. `Rejected` (a human SoD decision) and
`Cancelled` (a deliberate withdrawal) carry intent that must NOT be silently bypassed by a
retry; reopening those would need their own explicit, separately-authorised path. Slice 1 is
Failed-only.

### Un-conclude safety
Retry moves a *specific request* Failed → Intake. The `is_concluded()` CLASSIFIER is UNCHANGED
(`Failed.is_concluded()` stays true; the engine test at request_lifecycle.rs:1625 still holds).
Every `is_concluded()` consumer checks the request's CURRENT status, and each correctly
re-enables once the request is back at Intake (not concluded) and refuses while Failed:
- `fail_request:854` — can fail again after a re-run fails (correct; retry-able again).
- `create_live_apply_job` (agents.rs:1946) — refuses while Failed, allowed once re-run reaches
  the right stage (correct).
- dead-letter requeue (agents.rs:2622) — the stale dead-lettered job is irrelevant; retry
  rebuilds the JobSpec fresh.
- plan guard (contracts.rs:15498) — re-enabled at Intake (correct).
No consumer assumes "ever-Failed ⇒ forever-Failed"; none caches conclusion. So un-concluding
`Failed` is safe.

### Handler (ryuki-api/src/contracts.rs) — mirror `requests_rework` / `rework_one` EXACTLY
- `requests_retry(Path(id), AuthExtractor(session), Json(body): ReasonBody)`:
  `check_permission(&session, "execute")` → else `record_transition_denied(.., "request.retry")`
  + 403; reason trim non-empty + ≤2000; delegate to `retry_one`.
- `retry_one(session, id, reason)`: mirror `rework_one` — DB branch (load `DbRequestRow`,
  `scope_guard_or_404` immediately after load, `db_row_to_request`, `retry_request`,
  `apply_transition_audited` action `"request.retry"`, from `current.status` → db `"intake"`,
  detail `{reason}`, empty `TransitionArtifacts`); no-DB branch (in-memory store, same by-id
  scope guard, `retry_request`, `record_audit_local` action `"request.retry"`).
- Route: `.route("/api/requests/{id}/retry", post(requests_retry))` next to `/rework`.

### Permission tier — `execute` (PROPOSED)
Retry is the operational INVERSE of `fail` (which is `execute`-tier, contracts.rs:17571): the
operator who can fail a request can retry it — symmetric, no asymmetric lockout. Retry cannot
bypass any gate (it returns to Intake and re-runs the full gauntlet, including re-approval), so
it does not warrant a higher tier. `rework` is `approve`-tier, but rework bounces an
*already-approved/locked* request (undoing approval work); retry re-runs a *failed* one. If
`approve` is preferred for consistency with the other →Intake transition, that is a one-line
change.

## Tests
- Engine (request_lifecycle.rs): `retry_request` Failed→Intake sets metadata; rejects every
  non-Failed status (Draft/Intake/.../Completed/Rejected/Cancelled); rejects empty reason.
- API (contracts.rs db tests + no-DB): retry a Failed request → 200 Intake + audited
  (`request.retry`); retry a non-Failed request → 409 (map_engine_error); 403 without execute;
  by-id scope guard 404 for out-of-scope (DB + no-DB); unknown id → 404.

## Out of scope (follow-ups)
- Batch retry (`POST /api/requests/batch/retry`) — mirror `requests_batch_rework` (cap 100,
  dedup, partial success). Slice 1 is single-only.
- Retry from Rejected/Cancelled (different intent — needs its own authorised path).
- An automatic/scheduled retry-with-backoff policy (this slice is operator-initiated only).
