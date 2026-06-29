# approve_one no-DB scope guard — close the lone batch-mutation scope gap

Status: implemented (codex plan APPROVE w/ one MINOR folded in — the test now asserts
the out-of-scope item's EXACT per-result 404, not merely "failed", so a 403/400 cannot
masquerade as the no-oracle contract). A verify-first analysis swarm flagged this and I
VERIFIED it against the code: it is a REAL scope-isolation gap in the batch-approve
slice (`6d4daf0`), not a false positive.

## The gap (verified)
`approve_one` (contracts.rs:16385) is the shared core for BOTH single approve
(`requests_approve`) and batch approve (`requests_batch_approve`, the #17 final slice).
- Its **DB branch** scope-guards immediately after load: `scope_guard_or_404(session,
  &current.site, &current.environment, request_id)` (contracts.rs:16401). ✓
- Its **no-DB / dry-run branch** (contracts.rs:16441-16505) runs `check_sod` then
  `request_lifecycle::approve_request` and writes `store[idx]` — with **NO scope guard
  anywhere**. ✗

Every sibling core closes this in its no-DB branch with the SAME idiom:
- `reject_one` (contracts.rs:17381), `rework_one` (17513), `fail_one` (17629),
  `cancel_one` (17738):
  ```rust
  if is_scoped(session)
      && !row_scope_permits(session, &store[idx].site, &store[idx].environment)
  {
      return Err(status_404(request_id));
  }
  ```
`approve_one` is the LONE missing one. So a site/env-scoped approver in no-DB/dry-run
mode can approve an OUT-OF-SCOPE request that should 404 — a cross-scope mutation AND an
existence oracle (the #2 RBAC contract: out-of-scope is indistinguishable from missing).
Because `requests_batch_approve` loops `approve_one`, the batch path inherits the gap:
out-of-scope ids are silently approved instead of counted as per-item 404 failures.

Impact is limited to the no-DB/dry-run deployment (the DB branch is correctly guarded),
but the no-DB path is a first-class product surface (the portal runs against it), and
the #2 invariant is "every no-DB branch enforces the same by-id scope guard as DB".

## Fix (one guard, mirroring the established codex-approved pattern)
Add the guard to `approve_one`'s FIRST brief-lock block (where it reads `requester`,
contracts.rs:16446-16453), AFTER the idx lookup and BEFORE `store[idx].requester.clone()`
— so an out-of-scope request 404s BEFORE any SoD/engine work, exactly mirroring the DB
branch ordering (scope before SoD) and `reject_one`:

```rust
let requester = {
    let store = request_store().lock().await;
    let idx = store
        .iter()
        .position(|r| r.id == request_id)
        .ok_or_else(|| status_404(request_id))?;
    // #2 (no-DB scope hardening): mirror the DB branch + reject/rework/fail/cancel —
    // an out-of-scope request 404s exactly like a missing one, so the dry-run approve
    // path is never a cross-scope approve or existence oracle. Closes the lone no-DB
    // approve gap from the batch-approve slice 6d4daf0.
    if is_scoped(session)
        && !row_scope_permits(session, &store[idx].site, &store[idx].environment)
    {
        return Err(status_404(request_id));
    }
    store[idx].requester.clone()
};
```
The `return Err` drops the lock guard `store` on the early return (same as `reject_one`).
No new helper, no migration, no engine change, no signature change. The DB branch and the
single-approve handler are unchanged. Placement inside the first lock block (not the
second) means the 404 precedes `check_sod` — no SoD lookup for an out-of-scope id.

## Test (no-DB process — runs WITHOUT RYUKI_DATABASE_URL)
`batch_approve_no_db_is_site_scoped`, mirroring `requests_batch_rework_fail_no_db_are_
site_scoped` (contracts.rs:37861):
- Seed two Planned requests via `seed_planned_request` (DEFRA/production, approvable:
  validated+planned with a completed plan stage + approval_route=["Datacenter Approver"]).
- Mark one request's site = "GBLON" (out of scope).
- Approver = a DEFRA-scoped DatacenterApprover (distinct from the "requester-1" creator,
  so SoD passes).
- `requests_batch_approve([in_scope, out_scope])` → 200; `succeeded == 1`, `failed == 1`.
- codex MINOR: the out-of-scope item's PER-RESULT entry must be `ok == false` AND
  `status == 404` (not just in the failed bucket — a 403/400 would also fail-and-leave-
  untouched, so only the exact 404 proves the no-oracle contract).
- In-scope row → status Approved (single-approval no-DB, proves the guard is PER-ITEM and
  the in-scope item still processes). Out-of-scope row → still Planned (never touched).
This proves: (a) the no-DB scope 404 exactly like a missing id, (b) per-item independence
(in-scope still approves), (c) no cross-scope mutation, (d) no existence oracle.

## Files
- sources/ryuki-api/src/contracts.rs (the one guard in `approve_one` no-DB + the test).
NO migration, NO engine change, NO new struct/helper.

## Out of scope
- The DB approve path (already scope-guarded at 16401).
- The other confirmed swarm gaps (GET approval-decisions, approval withdrawal, etc.) —
  separate slices.
