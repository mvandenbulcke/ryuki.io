# GET approval-decisions — surface the individual approval-decision ledger

Status: SHIPPED (codex plan APPROVE + codex impl APPROVE, no defects; an extra
test assertion added per a non-blocking codex impl note — the happy test now asserts
the two same-tx `decided_at` values are EQUAL, making explicit that the BIGSERIAL id
ASC tie-breaker is what orders them). 3 plan MINORs folded in — (1) deterministic
`ORDER BY decided_at ASC, id ASC` since Postgres now() is tx-scoped and same-tx rows
tie; (2) `reason` documented as audit-visible free text, write-side redaction is the
mitigation; (3) added a zero-decisions DB test asserting durable-but-empty
`{decisions:[],durable:true}`). From the verify-first swarm (2026-06-29, finding #2).
VERIFIED against the code: the gap is real.

## Gap (verified)
`request_approval_decisions` (mig 047) records the full per-decision ledger: `role`,
`decision` ('approved'|'rejected'), `actor` (verified principal), `decided_at`
(TIMESTAMPTZ), `reason` (TEXT, the mandatory reject reason; NULL for approve), with
`UNIQUE(request_id, role)` and an index on `(request_id, decided_at)`.

The only endpoint that reads this is `GET /api/requests/{id}/approval-quorum`
(`requests_approval_quorum`, contracts.rs:18450). It:
- requires **audit-tier** (`check_permission(&session, "audit")`, 18457),
- SELECTs only `role, decision, actor` (18522) and returns AGGREGATES (`QuorumStatus`:
  distinct-role/approver counts, satisfied-roles list, approvers list),
- never surfaces `decided_at` or `reason`.

So an operator/approver/auditor cannot see the per-decision detail — who decided what,
WHEN, and WHY (the reject reason). That detail exists in the DB but is unreachable.

## Tier decision — audit-tier (DIVERGES from the swarm's approve-tier, justified)
The swarm recommended approve-tier "so approvers see decisions without audit
privileges." That rests on a FALSE premise. The RBAC map (auth.rs `get_rbac_roles`):
- `DatacenterApprover` = [approve, audit]; `PlatformAdmin` = [admin, approve, audit];
- `Auditor` = [audit] ONLY; all `*Operator` = [execute, audit].
EVERY approve-holder ALSO holds audit — there is NO approve-without-audit role. So:
- approve-tier would NOT "avoid audit" (approvers already have it), and
- approve-tier would WRONGLY EXCLUDE the `Auditor` (audit-only) from an audit-grade
  decision ledger — the exact role meant to review it.

The data (approver identities + timestamps + reasons) is audit-trail-grade, and the
companion quorum endpoint already gates the same class of data (approver identities) at
audit-tier. So this endpoint is **audit-tier**, mirroring the quorum endpoint EXACTLY —
explicit in-handler `check_permission(&session, "audit")` + `scope_guard_or_404`. No
secret exposure: `actor` is already exposed by the quorum endpoint's approvers list;
`reason` is a justification string, not a secret.

## Endpoint (contracts.rs)
`GET /api/requests/{id}/approval-decisions` → `requests_approval_decisions`, a NEW
handler mirroring `requests_approval_quorum`'s guards step-for-step:
1. `check_permission(&session, "audit")` → 403 otherwise.
2. `Uuid::parse_str(&request_id)` → 404 on malformed (BOTH paths, same as quorum).
3. No-DB / dry-run (`get_db()` None): return `{ "decisions": [], "durable": false }`
   (shape parity — the dry-run approve arm writes no ledger).
4. DB: `SELECT site, environment FROM requests WHERE id = $1` → None ⇒ 404 (unknown
   request indistinguishable from out-of-scope: no oracle); then
   `scope_guard_or_404(&session, &site, &environment, &request_id)`.
5. `SELECT role, decision, actor, decided_at, reason FROM request_approval_decisions
   WHERE request_id = $1 ORDER BY decided_at` into a typed row
   (`decided_at: chrono::DateTime<Utc>`, `reason: Option<String>`).
6. Return `{ "decisions": [ {role, decision, actor, decided_at: <rfc3339>, reason} ],
   "durable": true }` (decided_at via `.to_rfc3339()`, the established pattern).

A small `#[derive(Serialize)]` record struct or inline `json!` per row. No migration,
no engine change, no new struct beyond the response record, no shared-helper change.

## Route
`.route("/api/requests/{id}/approval-decisions", get(requests_approval_decisions))`,
registered next to the existing `approval-quorum` route (~contracts.rs:164). Distinct
path segment → no matchit collision. SAFE method (GET) → the central read gate maps
`/api/requests/...` to the audit/request read tier; the in-handler audit check tightens
to audit exactly as the quorum endpoint does.

## Why a new endpoint (not extend the quorum response)
Keeps the quorum endpoint's response stable (no shape growth for its callers) and models
a distinct resource (the decision ledger vs the quorum verdict). The handler boilerplate
(permission + id + scope + existence) is the codebase's per-endpoint idiom, used
everywhere — consistency over DRY here.

## Tests (contracts.rs)
DB (quorum_enforcement_db_tests or the approval db-tests module, single-threaded):
1. **happy + ordering + reason**: create→validate→plan a request; record TWO decisions
   (one approve with NULL reason, one reject with a reason) via the existing approve/
   reject flow (or a direct ledger insert mirroring the quorum tests at ~46153); GET →
   200; assert `decisions` has both, in `decided_at` order, each carrying role/decision/
   actor/decided_at, and reason present for the reject / null for the approve;
   `durable == true`.
2. **audit-tier required**: a `request`-only session (Requester, NO audit) → 403; an
   audit-holder → 200. Mirror `approval_quorum_requires_audit_permission` (38513).
3. **scope**: an out-of-scope request for a scoped audit session → 404 (no oracle).
4. **404**: unknown id → 404; malformed id → 404.
No-DB (no-DB process, WITHOUT a DB URL):
5. **no-DB empty**: GET → 200 `{ "decisions": [], "durable": false }`.

## Files
- sources/ryuki-api/src/contracts.rs (handler + route + tests). NO migration, NO engine.

## Out of scope
- Pagination (a single request has ≤ a handful of decisions — UNIQUE(request_id, role),
  ≤10 roles by the 1..=10 quorum bound).
- Exposing decisions in the quorum endpoint (kept separate).
