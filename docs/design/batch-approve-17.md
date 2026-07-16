# Batch approve (quorum-aware) — #17 final slice

Status: design (pre-plan-review). Completes the request batch-ops surface
(cancel + reject + rework + fail shipped; approve is the last + the only
quorum-sensitive one). Additive, NO migration, NO engine change. SECURITY-CRITICAL.

## Goal
Add `POST /api/requests/batch/approve` so an operator can sign off a cohort of
requests in one call. The load-bearing requirement: a batch must NOT let a single
approver BYPASS the multi-role quorum (#4) — a request with
`required_approval_roles > 1` must still require N distinct roles AND N distinct
approvers, exactly as single-approve enforces.

## The `approve_one` core (extract from `requests_approve`)
`requests_approve` (contracts.rs:16294) = capability check + denied audit, then a
DB branch (quorum) and a no-DB branch (single-approval). Extract everything AFTER the
capability check into `approve_one(session, request_id) -> Result<Value,
(StatusCode, Json<Value>)>` (returns the bare request JSON + its `quorum` sibling),
mirroring `reject_one`/`cancel_one`/`rework_one`/`fail_one`:
- DB branch: `Uuid::parse`→404; load row→404; `scope_guard_or_404`; `check_sod`
  (approver ≠ creator); `apply_approval_decision_audited(pool, &session, uid)` →
  `(row, quorum)` — this LOCKS the request row, re-runs the engine approval UNDER the
  lock, records THIS approver's ONE decision, and flips to `Approved` ONLY when
  `required_approval_roles` distinct roles + approvers have approved; otherwise it
  stays `Planned` and the decision is recorded (200, `quorum_met=false`). Return the
  request JSON + `quorum`.
- no-DB branch: SoD via the store; `approve_request` (single-approval — quorum is
  DB-only by design); store update; `record_local_transition`; synthesize the
  single-approval quorum; return.
`requests_approve` (single) keeps `check_permission("approve")` + denied audit, then
`approve_one(&session, &request_id).await.map(Json)`.

## QUORUM IS PRESERVED BY CONSTRUCTION (the security argument)
`apply_approval_decision_audited` records ONE approver's decision per request and
advances only when the quorum is met; `evaluate_quorum` counts DISTINCT roles AND
DISTINCT approvers (a single actor wearing many hats counts once). A batch loops
`approve_one` per id → each id receives THIS approver's single decision. So a
`required_approval_roles=2` request batch-approved by ONE approver yields
`quorum_met=false` and stays `Planned` (NOT Approved). The batch cannot bypass the
quorum because it reuses the same per-request decision-ledger core single-approve
uses — there is no batch-specific approval path.

## `requests_batch_approve` (mirror `requests_batch_reject`)
1. `check_permission("approve")` ONCE; lacking → a single 403 for the whole batch,
   audited EXACTLY ONCE with the non-id `"batch"` sentinel
   (`record_transition_denied(&session, "batch", "request.approve")`). `check_sod`
   stays the per-item gate inside `approve_one`.
2. body `BatchApproveRequest { ids: Vec<String> }` — approve takes NO reason (unlike
   cancel/reject/rework/fail), so no reason field / no length cap.
3. `ids` non-empty; ≤ 100; dedup preserving order.
4. loop `approve_one` per id; per-id result carries the QUORUM OUTCOME so the operator
   sees which advanced vs which still need more approvers:
   - `Ok(json)` → `{id, ok:true, status: json["status"], quorum_met:
     json["quorum"]["quorum_met"]}`.
   - `Err((s,b))` → `{id, ok:false, status: s.as_u16(), error: b}`.
5. counts: `succeeded` (ok), `failed`, `approved` (quorum_met=true). Always HTTP 200;
   items independent (a failure never rolls back the rest).

## Route + gate (NO gate change)
`.route("/api/requests/batch/approve", post(requests_batch_approve))` beside
batch/{cancel,reject,rework,fail}. `requests_route_permission` resolves by the LAST
path segment (`rsplit('/').next()` → `approve`) → `approve` tier, matching the
handler check (main.rs:596). Static 2-segment path; no matchit collision.

## Tests (no-DB + DB; mirror the batch-reject suite + quorum/SoD security cases)
1. **validates inputs** (no-DB): empty ids → 400; >100 ids → 400.
2. **forbidden for non-approver**, audited once: a VMwareOperator (holds `execute`,
   not `approve`) → a single 403 for the whole batch + exactly ONE `request.approve`
   `outcome:"denied"` audit (NULL request_id); nothing is approved.
3. **dedupes ids**: a duplicated id is acted on once.
4. **happy no-DB**: planned requests → all approved (single-approval, no-DB).
5. **DB happy** (required_approval_roles=1): planned requests → all `approved`,
   `quorum_met=true`, a `request.approve` audit row each.
6. **QUORUM NO BYPASS** (security, DB): a request with `required_approval_roles=2`
   batch-approved by ONE approver → its result is `quorum_met=false`, `status`
   still `planned`, and the row is NOT `approved` (a single approver cannot bypass
   the 2-role quorum via the batch). This is the load-bearing security test.
7. **DB partial**: valid + non-existent (404) + already-terminal (4xx) → partial
   success, HTTP 200, per-id statuses correct.
8. **DB SoD** (security): an approver batch-approving a request THEY created → that
   id fails per-item (SoD 403) while in-scope others succeed (per-item SoD preserved).
9. **DB site-scoped**: a scoped approver batching an out-of-scope id → that id 404s
   (no oracle) while the in-scope id is approved.

## Files
- sources/ryuki-api/src/contracts.rs (`approve_one` extraction, `requests_approve`
  rewire, `requests_batch_approve` + `BatchApproveRequest` + route + tests).
NO migration, NO engine change.

## Out of scope (follow-up)
- A policy SOURCE that raises `required_approval_roles` above 1 from offering/
  criticality at plan time (the #4 deferred follow-up — the column defaults to 1, so
  quorum enforcement is wired + tested but exercised only when a request sets it).
