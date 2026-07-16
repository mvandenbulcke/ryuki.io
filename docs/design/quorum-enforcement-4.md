# #4 — Multi-role approval quorum ENFORCEMENT (reviewed design)

Status: design APPROVED-with-changes (the review changes below are folded in).
Approach **A** (single column + API-layer enforcement; engine `approve_request` unchanged).

## Goal
Today `requests_approve` flips Planned→Approved on a SINGLE approval; the quorum is
only *reported* (`requests_approval_quorum`, read-only) via `evaluate_quorum` over
`request_approval_decisions` (UNIQUE per (request_id, role)). Enforce it: a request
that requires N approving roles only reaches Approved once N distinct roles have
approved — WITHOUT breaking the default single-approval flow.

## Data model
- Migration **118** `requests.required_approval_roles INTEGER NOT NULL DEFAULT 1`,
  `CHECK (required_approval_roles BETWEEN 1 AND 10)`. Idempotent guarded DO block.
  DEFAULT 1 backfills every existing row → single-approval semantics unchanged.
- `DbRequestRow` (contracts.rs ~2643): add `required_approval_roles: i32` after
  `criticality`. Append to `REQUEST_COLUMNS` (~2681) — sqlx maps by name, so every
  SELECT/RETURNING hydrates it; no other SELECT edits.
- Engine `Request` struct: NO change. `approve_request` (request_lifecycle.rs:308)
  + its 11 call sites: NO change. (This is why A beats the engine-signature approaches.)

## Enforcement (DB arm of `requests_approve`, contracts.rs ~15881)
Keep: load row, `scope_guard_or_404`, `check_sod` (approver≠creator, per call).
Keep calling engine `approve_request(&request, &session.user_id)` to validate
from-status==Planned + completed plan stage and PRODUCE the completed approve stage /
evidence / approval_route. Do NOT assume it commits Approved.

New helper `apply_approval_decision_audited` (sibling of `apply_transition_audited`),
ALL in ONE tx, in this order (review fix #1 — row lock serializes quorum eval):
1. **`SELECT {REQUEST_COLUMNS} FROM requests WHERE id=$1 FOR UPDATE`** — lock the
   request row first; re-verify status is still `planned` (else 409 transition_conflict).
2. **Idempotent short-circuit (review fix #3):** if a decision row already exists for
   `(request_id, role=approval_role_for(session))` with decision='approved', do NOT
   re-run/re-audit/re-emit — re-read decisions, compute quorum, return the current
   `(row, QuorumStatus)` unchanged (no duplicate evidence/audit/event).
3. INSERT-ON-CONFLICT the decision row (role = approval_role_for, decision='approved')
   — reuse the existing 14116 SQL.
4. Re-SELECT all decisions (`SELECT role,decision,actor FROM request_approval_decisions
   WHERE request_id=$1`) → `Vec<ApprovalDecision>`.
5. `let req = current.required_approval_roles as usize;
   let q = evaluate_quorum(&decisions, req, req);` (required_approvers pinned to req —
   review fix #4: distinct-approver floor blocks one actor self-forming a quorum).
6. Branch:
   - `q.quorum_met` → CAS UPDATE status→'approved' (request_status_to_db(Approved))
     with the engine's stages_json/approval_route_json, expected_from='planned';
     write audit (action `request.approve`, to_status='approved'); emit the
     `request.approve` domain event + owner notification (the REAL approval).
   - else (partial; `q.rejected` impossible on an approve since reject is terminal) →
     UPDATE only stages/approval_route/updated_at (status stays 'planned'); write
     audit (action `request.approval_recorded`, to_status='planned'); emit a DISTINCT
     `request.approval_recorded` event and **NO "Request approved" owner notification**
     (review fix #2 — a partial approve must not tell the owner it's approved).
7. commit. Return `(DbRequestRow, QuorumStatus)`.

Refactor the shared inner audit+event+notification block out of `apply_transition_audited`
into a small private fn so both helpers keep audit/event PARITY; non-approve transitions
(lock/execute/verify/…) keep using `apply_transition_audited` unchanged.

`requests_approve` builds a 200 body = request JSON + the QuorumStatus block
(approved_roles/required_roles/distinct_approvers/required_approvers/quorum_met) so a
partial approve returns 200 with status still 'planned' (callers must read quorum_met).

Reject path: `reject_request` stays terminal Planned→Rejected; ensure it takes
the SAME request-row `FOR UPDATE` lock ordering (lock row → insert decision/transition)
to avoid a deadlock with the approve helper. A single 'rejected' row makes
`evaluate_quorum` return rejected=true unconditionally.

No-DB / in-memory arm (15970-15994): NO ledger → stays single-approval unconditionally;
add a one-line comment that quorum enforcement is DB-only (dry-run limitation).

Read-only `requests_approval_quorum` (~17539, review fix #6): default both thresholds to
`current.required_approval_roles` (instead of the hardcoded 2/2) when no query override,
so the reported quorum matches the enforced quorum.

## Tests (new *_db_tests, serialized + cleanup_request)
1. Default single-approval still Approves (required=1): create→validate→plan→approve →
   status='approved', quorum_met=true, one decision row.
2. 2-role holds then completes: set required=2; approve by a DatacenterApprover →
   status stays 'planned', quorum_met=false, approved_roles=1; approve by a DISTINCT
   PlatformAdmin → status flips 'approved', quorum_met=true, two rows.
3. Rejection blocks: required=2, one approve then reject by a third principal →
   'rejected' (terminal); subsequent approve refused by from-status guard.
4. SoD preserved every tier: creator approving own required=2 request → 403.
5. One actor cannot self-form quorum: required=2, same principal approves "twice" →
   stays 'planned' (idempotent re-approve + distinct-approver floor).
6. Idempotent re-approve: same role approves twice on a required=2 request → exactly
   one decision row, no duplicated audit/event, quorum unchanged.
7. Self-transition no false 409: the partial-approve Planned→Planned path returns 200,
   not a 409.
8. Migration idempotency: re-running 118 is a no-op.
Keep ALL existing approve/reject DB + engine tests green UNCHANGED.

## Files
- migrations/118_request_required_approval_roles.sql (new)
- sources/ryuki-api/src/contracts.rs (DbRequestRow, REQUEST_COLUMNS,
  apply_approval_decision_audited + shared inner block, requests_approve DB arm,
  requests_approval_quorum default)
- sources/ryuki-engine: NO change (approve_request/reject_request/approval_quorum reused)

## Deferred follow-up (NOT this slice)
Policy SOURCE that raises required_approval_roles above 1 (plan-time setter reading the
offering's `approvals` breadth / criticality), gated so default offerings stay at 1.
