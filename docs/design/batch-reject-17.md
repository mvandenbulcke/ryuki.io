# #17 (slice 2) — Batch reject

Status: design — plan-review round 1 NEEDS-CHANGES, all fixed below. Extends
the existing batch-operations work (`requests_batch_cancel`, slice 1) with the
sibling terminal verb. Review fixes: (major) the ≤2000 reason cap is batch-only so
single reject is behavior-preserving; (major) the no-DB scope guard added to
`reject_one` is flagged as a DELIBERATE consistency-hardening change with tests;
(minor) batch permission denial is audited once with a non-id sentinel, not by
looping ids.

## Goal
`POST /api/requests/batch/cancel` already cancels up to 100 requests in one call
(slice 1). The natural completion for an APPROVER is a batch REJECT — clear a
backlog of stale/unwanted pending requests in one call instead of N round-trips.
Add `POST /api/requests/batch/reject` mirroring the proven batch-cancel pattern
exactly (dedupe, cap 100, shared reason, per-item independent transaction, partial
success, HTTP 200 even if all fail).

## Why reject (and NOT approve) in this slice
- `reject` is TERMINAL and quorum-trivial: the engine comment already notes "a
  single 'rejected' row makes evaluate_quorum return rejected=true
  unconditionally", and reject uses `apply_transition_audited` (not the quorum
  accumulator `apply_approval_decision_audited`). So a per-item reject is a clean,
  self-contained transition — identical risk profile to cancel.
- `approve` is DELIBERATELY OUT OF SCOPE: it flows through #4 quorum
  (`apply_approval_decision_audited`), so a batch approve would have to convey
  per-item partial-vs-met quorum state, and bulk-approving change requests is
  operationally unwise (each approval generally warrants its own review). Deferred
  as an explicit follow-up.

## Refactor: factor `reject_one` (mirror `cancel_one`)
`requests_reject` (contracts.rs:17054) does the per-request work inline; there is
no reusable core (unlike `cancel_one`, contracts.rs:17397). Extract everything
AFTER the caller-level checks into:
```rust
async fn reject_one(session: &AuthSession, request_id: &str, reason: &str)
    -> Result<Value, (StatusCode, Json<Value>)>
```
containing BOTH the DB path (load row → `scope_guard_or_404` → `check_sod` →
`reject_request` engine → `apply_transition_audited` with the rejection decision
row) and the no-DB path (store lookup → by-id scope guard → `check_sod` →
`reject_request` → `record_audit_local`), returning the rejected request JSON.
`requests_reject` then becomes: `check_permission("approve")` (+
`record_transition_denied` on deny) → `reject_control_chars` + non-empty reason
validation → `reject_one(&session, &request_id, reason)` wrapped in `Json`.
This keeps single and batch reject identical in SoD/scope/transition/audit —
exactly how `cancel_one` backs both single and batch cancel.

REVIEW FIX (major — reason length): reason validation stays in the CALLER, not in
`reject_one` (which takes an already-validated reason, like `cancel_one`). The
single handler keeps its EXACT current validation — `reject_control_chars` +
non-empty, NO `>2000` cap — so it is behavior-preserving. The `≤2000` cap is
applied ONLY in the batch handler (matching `requests_batch_cancel`'s cap); it is a
deliberate batch-only policy, not a change to the single endpoint.

REVIEW FIX (major — no-DB scope hardening, DELIBERATE behavior change): the CURRENT
no-DB `requests_reject` does NOT run the in-memory `is_scoped`/`row_scope_permits`
guard — only its DB path scopes (`scope_guard_or_404`). `reject_one` ADDS that
guard to the no-DB path, mirroring `cancel_one`, so an out-of-scope id 404s in
no-DB mode too. This is an INTENTIONAL consistency fix (the DB reject path and BOTH
cancel paths already scope; the no-DB reject path was the lone gap — a scoped
principal could reject an out-of-scope in-memory request). It is called out here as
a security-hardening change to single reject's no-DB path, covered by new tests
(single AND batch no-DB scoped reject), not a silent regression.

PERMISSION PLACEMENT (note vs cancel): `cancel_one` embeds its permission gate
(`cancel_permitted`) because cancel-permission is OWNERSHIP-based, i.e. per-item.
The `approve` capability for reject is a FLAT capability (not per-item), so it is
checked ONCE at the caller (single handler and batch handler each up front) — a
caller lacking `approve` gets a single 403 for the whole batch, never a per-item
403. `check_sod` (creator≠approver) remains PER-ITEM inside `reject_one`.

## API — `requests_batch_reject` (mirror `requests_batch_cancel`)
```rust
#[derive(Debug, Deserialize)]
struct BatchRejectRequest { ids: Vec<String>, reason: String }

async fn requests_batch_reject(AuthExtractor(session), Json(b): Json<BatchRejectRequest>)
    -> ApiResult
```
1. `check_permission(&session, "approve")` once → 403 (whole batch) if absent.
   REVIEW FIX (minor): audit the denial EXACTLY ONCE with a non-id sentinel —
   `record_transition_denied(&session, "batch", "request.reject")` — NOT by looping
   the ids (that would both be wasteful and risk an existence oracle on a denied
   caller). `"batch"` is a clear non-id placeholder for the `request_id` field.
2. `reject_control_chars("rejection reason", &b.reason)?`; `reason = trim`;
   non-empty (400); ≤2000 chars (400). The control-char + non-empty checks match
   the single handler; the ≤2000 cap is BATCH-ONLY (mirrors `requests_batch_cancel`;
   the single handler is left without a length cap, unchanged).
3. `b.ids` non-empty (400), ≤100 (400).
4. Dedupe ids preserving order (same `HashSet` filter as batch cancel).
5. Loop `reject_one(&session, id, reason)` per unique id; collect per-id
   `{id, ok:true}` or `{id, ok:false, status, error}`; count succeeded/failed.
6. Return `{ results, succeeded, failed }` (HTTP 200 even if all failed — clients
   MUST inspect `failed`/`results`, same contract as batch cancel).

Route: `.route("/api/requests/batch/reject", post(requests_batch_reject))` next to
the batch-cancel route (contracts.rs:149).

## Secret hygiene / scope / SoD
- `reject_one` runs `scope_guard_or_404` per item → an out-of-scope id 404s exactly
  like a missing one (no cross-scope reject, no existence oracle), identical to the
  single handler and to cancel.
- `check_sod` per item → a self-reject under LIVE identity is a 403 in that item's
  result (audited `denied`), while other items proceed.
- The shared `reason` is the only free text; `reject_control_chars` already strips
  control chars, and the reason is stored in the decision row + audit `detail` as
  today (no new sink).

## Tests (contracts.rs unit_tests + db_tests, mirroring the batch-cancel + reject tests)
1. **Happy batch** (DB): 3 planned requests → batch reject → all `ok:true`,
   each row `status='rejected'`, `succeeded=3 failed=0`, and a
   `request_approval_decisions` rejection row + audit row per id.
2. **Partial** (DB): mix a valid planned id, a non-existent id (404), and an
   already-terminal id (engine 4xx) → `succeeded=1 failed=2`, per-id statuses
   correct, HTTP 200.
3. **Permission**: a non-approver (e.g. auditor) → whole batch 403 (mirrors
   `requests_reject_rejected_for_auditor`), nothing rejected. (Review note: if the
   test asserts the denial audit row, assert by count/action/outcome — the durable
   audit parses the non-UUID `"batch"` sentinel to a NULL `request_id`, so don't
   assert `request_id = 'batch'`.)
4. **Reason validation**: empty reason → 400; control chars → 400 (mirrors the
   single-reject tests); >2000 chars → 400 (BATCH-only cap). Also assert the SINGLE
   reject still ACCEPTS a >2000 reason (it has no length cap — proves the cap stayed
   batch-only and single reject was not changed).
5. **Shape**: empty ids → 400; >100 ids → 400; duplicate ids deduped (acted once).
6. **Scope** (DB): an out-of-scope id for a scoped session → that item 404s
   (no oracle), in-scope item still rejected.
7. **No-DB scope hardening**: with no DB, a scoped session rejecting an
   out-of-scope in-memory request → 404 (single handler AND inside a batch),
   proving `reject_one` closed the no-DB scope gap consistently with `cancel_one`.
8. **Single reject unchanged otherwise**: the existing `requests_reject_*` tests
   must stay green after the `reject_one` extraction (regression guard — the only
   intended single-handler change is the no-DB scope guard in test 7).

## Files
- sources/ryuki-api/src/contracts.rs (extract `reject_one`; refactor
  `requests_reject` to call it; add `BatchRejectRequest` + `requests_batch_reject`;
  register the route; tests). NO engine/migration change.

## Out of scope (follow-ups)
- Batch APPROVE (quorum-aware partial results; operationally sensitive).
- Batch rework/fail (other lifecycle verbs).
- A max-batch-size config knob (the 100 cap matches batch cancel).
