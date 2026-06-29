# Second-swarm hardening of this session's work

Status: SHIPPED (codex plan NEEDS-CHANGES → 2 MINOR + the approval-quorum follow-up folded
in; codex impl APPROVE, no findings — codex swept for other /api/requests/{id}/* audit-handler
gaps and found NONE, so approval-decisions + approval-quorum are the complete set). The 2nd
verify-first analysis swarm (2026-06-29 run 2) found these gaps in features shipped THIS
session. Both are small, low-risk hardening. NO migration, NO engine change.

## A. approval-decisions read-gate consistency (defense-in-depth)
`GET /api/requests/{id}/approval-decisions` (shipped d75485b2) checks `audit` in the handler
(contracts.rs:18577). But `is_audit_read_path` (main.rs:765) — which makes the CENTRAL read
gate require `audit` specifically — covers only `/api/activity/audit` and `/api/requests/.../
audit|evidence`, NOT `/approval-decisions`. So the gate currently maps `/approval-decisions`
to the ORDINARY read tier (`read_authorized` = audit OR request), and a `request`-only
Requester passes the gate but is then 403'd by the handler's `audit` check. This is NOT a
security hole (the handler tightens to audit), but it is the SAME defense-in-depth
inconsistency the codebase deliberately closes for `/audit` + `/evidence`: the gate should
match the handler. The approval-decisions read is audit-grade (approver identities +
reasons), exactly like the per-request `/audit` trail and `/evidence` pack.

Fix: extend `is_audit_read_path`'s `/api/requests/` branch to also match
`path.ends_with("/approval-decisions")`. Then the gate requires `audit` (matching the
handler), so a Requester is cleanly rejected AT THE GATE — consistent with /audit + /evidence.
Test: add `assert!(is_audit_read_path("/api/requests/<id>/approval-decisions"))` to the
existing `is_audit_read_path` unit test (it already covers /audit + /evidence + negatives).

## B. migration-idempotency tests for the two new scan seeds
Migrations 119/120/122/123 each have a `migration_NNN_is_idempotent` test. The two
durable-scheduler scan migrations shipped this session — 125 (secret_rotation_due_scan) and
126 (legal_hold_expiry_scan) — have NO such test, so a future edit that breaks their seed
INSERT or the seeded-row contract would not be caught.

Fix: add `migration_125_is_idempotent` + `migration_126_is_idempotent` (scheduler.rs tests),
mirroring `migration_122_is_idempotent_and_index_dedups`:
- Re-run the seed `INSERT ... ON CONFLICT (id) DO NOTHING` → a clean no-op.
- Assert the seeded row matches the SHIPPED contract: name / job_kind / interval_secs (86400)
  / enabled (TRUE) / created_by ('system') for SECRET_SCAN_SEED_ID (66666666…) resp.
  LEGAL_HOLD_SCAN_SEED_ID (77777777…).
- Assert the partial unique index dedups a second OPEN item for the same
  item_type+source_ci_key (`secret-rotation-due` resp. `legal-hold-expiring`) — a direct
  second INSERT (bypassing enqueue_if_absent) hits the index and errors.
(These tests must re-enable the migration-seeded schedule if they disable it — but they only
re-run the seed + assert, they do not disable it, so no restore needed.)

## Files
- sources/ryuki-api/src/main.rs (is_audit_read_path + its unit test).
- sources/ryuki-api/src/scheduler.rs (migration_125/126 idempotency tests).
NO migration, NO engine change, NO handler change (the approval-decisions handler already
checks audit).

## Out of scope
- Broader is_audit_read_path coverage of other audit-grade reads (only the
  approval-decisions gap was flagged; a full sweep is separate).
