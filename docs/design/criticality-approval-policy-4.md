# Criticality → required_approval_roles policy (the #4 quorum capstone)

Status: DESIGN-ONLY, DEFERRED (codex plan-reviewed twice; implementation deferred to
a dedicated session). The plan-time wiring below is APPROVED (codex round-2 APPROVE
option A) and the ordering-safety argument holds — BUT a verify-first check found this
is a 2-PART feature, not the single policy slice the swarm scoped:

> BLOCKER finding: the REQUESTS table `criticality` is `TEXT NOT NULL DEFAULT
> 'standard'` (migration 047) with NO value CHECK, and the create handler HARDCODES
> `criticality = "standard"` (contracts.rs:~14956) — `CreateRequest` has no criticality
> field. (The `Low/Medium/High/Critical` CHECK is on the CMDB table, mig 014, NOT
> requests.) So EVERY request is `"standard"` → `required_approval_roles_for_criticality
> ("standard") = 1` → the quorum would NEVER engage. Shipping the policy ALONE is an
> inert no-op.

To deliver real value this needs BOTH parts, as a dedicated change:
1. CREATE-SIDE criticality INPUT: add `criticality` to `CreateRequest` (the engine
   `create_request` ALREADY takes a `criticality` param — the API just hardcodes
   "standard"), validate it, thread it through the create INSERT. Keeps criticality
   immutable-after-create (so the ordering-safety below still holds). Backward-compat:
   existing `"standard"` rows map to 1.
2. PLAN-TIME policy: exactly the design below (codex-approved).

The original (part-2-only) design follows, retained for the dedicated session.

---

NO migration (mig 118's column + 1..=10 CHECK already exist). Distinct from the 6
recently-shipped features. Picked by the fresh analysis swarm.

## Goal
#4 wired the multi-role approval quorum (`required_approval_roles`, mig 118) and the
just-shipped batch-approve proved it cannot be bypassed — BUT the column DEFAULTS to 1
and NOTHING sets it, so the quorum NEVER engages: every request is single-approval.
Add a PLAN-TIME policy that raises `required_approval_roles` from the request's
`criticality`, so high-risk changes demand DUAL control (maker-checker breadth).

## Policy (pure engine fn — request_lifecycle.rs)
```rust
/// Number of DISTINCT approver roles a request of this criticality needs (the #4
/// quorum threshold). High-risk changes demand dual control; routine changes keep
/// single approval. CAPPED AT 2: only two distinct approve-holding roles exist
/// (DatacenterApprover + the PlatformAdmin superuser), so a higher threshold would
/// be PERMANENTLY UNSATISFIABLE (a real deadlock) — never return >2. Result is
/// within the mig-118 1..=10 CHECK. Case-insensitive; an unknown/blank criticality
/// is FAIL-SAFE single approval (criticality is validated at create — defensive only).
pub fn required_approval_roles_for_criticality(criticality: &str) -> i32 {
    match criticality.trim().to_ascii_lowercase().as_str() {
        "critical" | "high" => 2,
        _ => 1,
    }
}
```
(Request criticality is `CHECK IN ('Low','Medium','High','Critical')`.)

## Wiring (requests_plan, DB branch) — ORDERING-SAFE, no TOCTOU
Set the threshold BEFORE the plan transition, while the request is still `Validated`
(NOT yet approvable — `approve_request` requires Planned + a completed plan stage):
```sql
UPDATE requests SET required_approval_roles = $1
WHERE id = $2 AND status = $3        -- $3 = current.status ('validated')
```
THEN `apply_transition_audited(plan)` flips Validated→Planned. So the FIRST moment the
request is approvable (Planned) the threshold is ALREADY correct — there is NO window
where the request is Planned carrying the stale default 1. (`apply_transition_audited`
preserves `required_approval_roles`: its UPDATE only COALESCEs plan/validation/route,
not this column, so the step-1 value survives the plan transition.) A re-plan (after
rework→validate) re-applies the policy, so the threshold always reflects the CURRENT
criticality. The `status = $3` guard makes step 1 a no-op if the row already moved
(the plan CAS then also fails) — consistent.

WHY NOT a separate UPDATE AFTER plan: that would briefly leave the request Planned
with `required_approval_roles = 1` — a window where a concurrent approver could meet
the stale single-approval threshold and advance a high-criticality request with ONE
approver (a quorum bypass). Setting it while still Validated closes that window.

### Stale-criticality race (codex plan BLOCKER) — VERIFIED NOT REACHABLE TODAY
Codex flagged: a concurrent PUT changing criticality Low→High BETWEEN the load and
the plan-flip (the `enrich_plan_stages_with_terraform().await` window can be seconds)
would leave the request Planned as High with the stale threshold 1 — a bypass.
VERIFIED: `criticality` is IMMUTABLE after create — there is NO criticality edit/PUT
path (no `SET criticality` anywhere; no generic request field-edit endpoint; the only
write is the create INSERT). So `current.criticality` is invariant across the plan
flow → the threshold computed from it is always correct → the race is unreachable.

Two ways to close it, the second future-proofs against a criticality-edit endpoint
that does not exist yet:
- (A) SIMPLE: the before-plan UPDATE above (set threshold while Validated). Safe
  TODAY given immutability.
- (B) ATOMIC + FUTURE-PROOF: extend `apply_transition_audited` so the plan UPDATE
  ALSO does `required_approval_roles = COALESCE($threshold, required_approval_roles)`
  AND a `AND ($crit IS NULL OR criticality = $crit)` CAS (NULL for all non-plan
  callers — COALESCE/NULL-guard make them no-ops). `requests_plan` passes the
  Rust-computed threshold + the loaded criticality; if criticality somehow changed,
  the CAS yields 0 rows → the existing 409 conflict → the client re-plans from the
  new criticality. Unconditionally safe (does not depend on the immutability
  invariant holding forever), at the cost of touching the shared helper + its ~6
  callers (mechanical: add two `None` fields).

The no-DB / dry-run arm is UNCHANGED — quorum is DB-only; no-DB stays single-approval.

## Tests
PURE (request_lifecycle.rs): `required_approval_roles_for_criticality` — Critical→2,
High→2, Medium→1, Low→1, "critical"→2 (case-insensitive), ""/"bogus"→1 (fail-safe),
and the result NEVER exceeds 2.
DB (contracts.rs, the quorum test module — seed via create→validate→plan with a set
criticality):
1. **High activates the quorum**: create+validate+plan a HIGH-criticality request →
   `required_approval_roles == 2`; ONE approver → `quorum_met=false`, stays Planned
   (the quorum NOW engages); a DISTINCT second approver (PlatformAdmin) → Approved.
2. **Low stays single**: a LOW-criticality request planned → `required_approval_roles
   == 1`; a single approver → Approved.
3. **No stale window**: immediately after plan, the row is BOTH `planned` AND
   `required_approval_roles == 2` (the threshold was set before the approvable state).
4. **Re-plan reflects current criticality**: a request whose criticality is Low →
   threshold 1; (and a separate High seed → 2) — the policy is recomputed each plan.

## Files
- sources/ryuki-engine/src/request_lifecycle.rs (pure `required_approval_roles_for_criticality` + unit tests).
- sources/ryuki-api/src/contracts.rs (the pre-plan threshold UPDATE in `requests_plan` + DB tests).
NO migration, NO new struct, NO change to the shared `apply_transition_audited`.

## Out of scope (follow-ups)
- Per-OFFERING / per-environment overrides (criticality is the first policy source).
- Retroactively raising the threshold on already-Planned requests.
- More distinct approver roles (would let the threshold exceed 2 meaningfully).
