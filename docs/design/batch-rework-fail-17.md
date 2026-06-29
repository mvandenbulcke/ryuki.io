# Batch request rework + fail (#17 slice 3)

Status: design (pre-codex-plan-review). Completes the request batch-ops surface:
cancel + reject already shipped; this adds rework + fail. Additive, NO migration,
no engine change, CI-verifiable. Reuses the proven `requests_batch_reject` template.

## Goal
`/api/requests/batch/{cancel,reject}` exist; the single `/api/requests/{id}/{rework,
fail}` handlers exist but have no batch form. Add `POST /api/requests/batch/rework`
and `POST /api/requests/batch/fail` so an operator can act on a cohort in one call
(mass re-intake for fixes; bulk terminal-fail of an infeasible cohort).

## The extract-a-`_one`-core pattern (mirror reject_one / cancel_one)
Today `requests_rework` (contracts.rs:17257) and `requests_fail` (17350) inline
their core. Like `reject_one`/`cancel_one`, extract a shared per-item core that BOTH
the single handler and the batch handler call, so the security-sensitive scope guard
+ the per-item transaction live in ONE place.

### `rework_one(session, request_id, reason) -> Result<Value, (StatusCode, Json<Value>)>`
- DB branch: `Uuid::parse_str`→404; load `DbRequestRow`→404; `scope_guard_or_404`;
  `request_lifecycle::rework_request(&request, &session.user_id, reason)`;
  `apply_transition_audited(.., "request.rework", &current.status, Intake-db-status,
  "intake", {reason}, artifacts{stages_json, approval_* = None})`; return entity JSON.
- no-DB branch: **CLOSES A LATENT GAP** — the current `requests_rework` no-DB path
  does NOT enforce the by-id scope guard (unlike `reject_one`'s no-DB branch at
  17204). The extracted core ADDS the same guard (`is_scoped(session) &&
  !row_scope_permits(session, site, env) => 404`) BEFORE the store mutation, then
  engine rework + `store[idx] = reworked` + `record_audit_local("request.rework",
  from_status, "intake", from_stage, "intake", {reason})`. Same hardening the
  batch-reject slice did for single reject.
- NO capability check and NO reason validation inside (the caller owns both).

### `fail_one(session, request_id, reason) -> Result<Value, (StatusCode, Json<Value>)>`
- DB branch: load→404; `scope_guard_or_404`; `request_lifecycle::fail_request(&
  request, reason)`; `failed_stage = current_stage_name(&request)` (fails AT its
  current stage, NOT a hardcoded "execute" — preserve the single handler's behavior);
  `apply_transition_audited(.., "request.fail", &current.status, Failed-db-status,
  &failed_stage, {reason}, artifacts{stages_json, approval_* = None})`.
- no-DB branch: **same scope-gap closure** + engine fail + store update +
  `record_audit_local("request.fail", from_status, "failed", from_stage, &from_stage,
  {reason})` (to_stage = from_stage, matching the single handler).
- NO capability/reason validation inside.

### Single handlers become thin wrappers
`requests_rework` keeps its `check_permission(&session,"approve")` +
record_transition_denied + reason validation (non-empty, ≤2000), then
`rework_one(&session,&request_id,reason).await.map(Json)`. `requests_fail` keeps its
`check_permission(&session,"execute")` + reason validation, then `fail_one(...)`.
SoD: the single rework/fail handlers do NOT call `check_sod` today (only
reject/approve do); preserve that — this slice changes NO authz behavior beyond
closing the no-DB scope gap.

## Batch handlers (mirror requests_batch_reject EXACTLY)
`requests_batch_rework` / `requests_batch_fail`:
1. Flat capability checked ONCE up front (rework→`approve`, fail→`execute`); a
   lacking caller gets ONE 403 for the whole batch, audited ONCE with the non-id
   `"batch"` sentinel via `record_transition_denied(&session,"batch",
   "request.rework"|"request.fail")` (never per-item — avoids waste + an existence
   oracle on a denied caller).
2. `reject_control_chars("rework reason"|"failure reason", &b.reason)`; trim;
   non-empty; ≤2000 (BATCH-ONLY cap, mirrors batch cancel/reject; the single
   handlers already cap at 2000 too).
3. `ids` non-empty; ≤100.
4. Dedup preserving order (HashSet) — so a repeated id is acted on once.
5. Loop `rework_one`/`fail_one` per id; collect `{id, ok}` / `{id, ok:false, status,
   error}`; `succeeded`/`failed` counts; **always HTTP 200** (clients inspect
   `failed`/`results`). Items are independent (one failure never rolls back others).

Bodies: `BatchReworkRequest{ids:Vec<String>, reason:String}` +
`BatchFailRequest{...}` (mirror `BatchRejectRequest`; the codebase uses a typed body
per op).

## Routes + gate (NO gate change)
Add beside cancel/reject (main.rs router ~line 150):
```
.route("/api/requests/batch/rework", post(requests_batch_rework))
.route("/api/requests/batch/fail",   post(requests_batch_fail))
```
`requests_route_permission` resolves by the LAST path segment (`rsplit('/').next()`),
which already maps `rework`→`approve` and `fail`→`execute` (main.rs:601/603). So the
batch routes inherit the correct coarse floor automatically, consistent with the
per-handler check. No central-gate edit.

## Tests (mirror the requests_batch_reject suite — no-DB + DB)
For EACH of rework + fail:
1. **validates inputs** (no-DB): empty reason→400, >2000 reason→400, empty ids→400,
   >100 ids→400.
2. **forbidden for wrong tier**, audited ONCE: rework by a non-approve principal
   (auditor) → 403 + exactly one `request.rework` `outcome:"denied"` audit with a
   NULL request_id (the "batch" sentinel); fail by a non-execute principal → 403 once.
3. **dedupes ids**: a batch with a duplicated id processes it once.
4. **happy no-DB**: a reworkable/failable request transitions; counts correct.
5. **DB happy** (db_tests): seed reworkable/failable requests → 200, all succeeded,
   rows transitioned (Intake / Failed), `request.rework`/`request.fail` audit rows.
6. **DB partial**: mix of valid + invalid-state ids → partial success, valid ones
   transitioned, invalid ones reported failed, no cross-item rollback.
7. **DB site-scoped**: a site-scoped session batching an out-of-scope id → that id
   fails (scope_guard_or_404), in-scope ids succeed.
Plus a regression proving the **no-DB scope-gap closure**: a site-scoped session
calling the SINGLE rework/fail on an out-of-scope request in no-DB mode → 404 (was a
silent cross-scope action before this slice).

### Codex plan-review additions (folded in — plan otherwise APPROVED)
- **(MAJOR) no-DB BATCH scope** (not just single): for both batch/rework + batch/fail,
  a site-scoped session with one in-scope + one out-of-scope id → the in-scope item
  succeeds, the out-of-scope item is a per-id 404, the out-of-scope row is UNCHANGED,
  and NO success audit is written for it. (Proves the batch wiring, not just `_one`.)
- **(MAJOR) fail per-item stage**: a DB batch fail with two failable requests at
  DIFFERENT current stages → each row AND each `request.fail` audit records THAT
  item's own prior stage (guards against a hardcoded "execute" or reusing item-0's
  stage).
- **(MAJOR) sharpened denial audit**: the wrong-tier denial test asserts EXACTLY ONE
  `outcome:"denied"` audit with a NULL request_id (the "batch" sentinel) — never
  per-item. (Handler-direct test, matching the shipped batch-reject convention: the
  in-handler capability check is defense-in-depth; the central segment-gate is the
  primary boundary, already covered by the #2 RBAC sweep.)
- **(MINOR) sharper validation/dedup**: control-char reason → 400 for both batch
  endpoints; the dedup test asserts ONE result entry + ONE state transition + ONE
  success audit for the duplicated id.

## Files
- sources/ryuki-api/src/contracts.rs (`rework_one`/`fail_one` extraction, the two
  batch handlers + bodies, the single-handler rewires, tests).
- sources/ryuki-api/src/main.rs (2 routes).
- docs/design/missing-features-tracker.md (#17 note → rework/fail shipped).
NO migration, NO engine change.

## Out of scope (follow-ups)
- Batch APPROVE (quorum-aware) — the remaining #17 item; deferred because quorum
  evaluation (multi-role, FOR UPDATE) is materially more complex than a flat
  transition and deserves its own slice.
- Adding SoD to single/batch rework (a behavior change to the existing handler).
