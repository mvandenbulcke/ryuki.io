# DR-plan general update (PUT) — CRUD edit

Status: design — round 1 review (1 blocker + 3 majors + 1 minor) → SCOPE NARROWED to
PUT-only (the blocker was DELETE-specific; DELETE deferred) → round 2 left only 2
LOWs, both folded in (axum deny_unknown_fields is 422 not 400; advertise PUT in
dr_contract). PUT concerns resolved: scalar-name sync, central /api/protect→execute
authz, immutability, same-read xmin CAS. Fresh-swarm finding (verified unbuilt).

## Goal
DR plans can be CREATED and READ but never generally EDITED: the router
(contracts.rs:1500-1503) has GET-list / POST-create / GET-by-id and an rpo-rto
SUB-update (`POST .../rpo-rto`), but no general PUT. So a typo'd plan name, a wrong
failover `targetSite`, or a changed system list cannot be fixed without
delete+recreate. Add `PUT /api/protect/dr/plans/{id}` to edit the descriptive
fields, mirroring the existing `dr_plan_update_rpo_rto` handler
(contracts.rs:31246) — the proven get→scope-guard→pure-transform→xmin-CAS→audit→
commit→write-through shape — so RBAC/scope/audit/concurrency stay identical.

## Why DELETE is deferred (review blocker)
A DELETE needs to protect dr_test_runs history, but `dr_test_runs.plan_id` has NO
FK (mig 088) and `dr_test_start` resolves the plan from the in-memory store
(get_plan_from_store) before inserting a run — so a concurrent start_test can
orphan history AFTER a NOT-EXISTS check. The race-free fix is an
`ON DELETE RESTRICT` FK, which interacts with the store/DB coupling in
`dr_test_start` (it would require the plan to be DB-resident, not just store-
resident). That deserves its own slice with the FK + dr_test_start handled
carefully; this slice ships the clean, race-free PUT. (Tracked as a follow-up.)

## What PUT may change (and what it must NOT)
Editable: `name`, `targetSite`, `systems`, `rpo`, `rto`. IMMUTABLE via PUT:
- `site` — it is the SCOPE key; editing it would move the resource across RBAC
  scopes. Like the connection-update HARDENING-1 rule, `site` cannot change;
  delete+recreate instead. Review confirmed this immutability design is correct.
- `status` — there is no DR-plan status-transition endpoint (plans are created
  `Draft`); a general PUT must NOT silently change lifecycle state.
- `id` / `last_tested` / `next_test_due` — server-owned; preserved.
`#[serde(deny_unknown_fields)]` on the body so a `site`/`status` smuggling
attempt is a 400, not silently ignored.

## Engine (`sources/ryuki-engine/src/dr_testing.rs`)
`update_dr_plan_pure(plan: &DrPlan, name, target_site, systems, rpo, rto) ->
Result<DrPlan, String>` — mirrors `update_rpo_rto_pure` + `build_dr_plan`'s
validation: trim-non-empty `name`/`target_site`, non-empty `systems`, `rpo>0`,
`rto>0`; clone the plan and set those 5 fields; PRESERVE `id`/`site`/`status`/
`last_tested`/`next_test_due`. Pure; unit-tested (happy + each validation +
field-preservation).

## Repo (`sources/ryuki-api/src/repos/dr_plans.rs`) — scalar `name` sync (major)
`transition` currently sets `status, plan_json, updated_at` but NOT the scalar
`name` column — fine for rpo-rto (name unchanged) but a general PUT that edits the
name would leave `dr_plans.name` stale (the denormalized scalar used by indexes/
queries). Extend `transition`'s UPDATE to also set `name = updated.name`. SAFE for
the existing rpo-rto caller (it passes the unchanged name). `site` stays out of the
UPDATE (immutable). A db test asserts the SCALAR `name` column (not just
plan_json) after a PUT.

## API (`sources/ryuki-api/src/contracts.rs`)
`PUT /api/protect/dr/plans/{id}` → `dr_plan_update` (mirror rpo-rto exactly):
- body `#[serde(deny_unknown_fields)] struct DrPlanUpdateRequest { name: String,
  #[serde(rename="targetSite")] target_site: String, systems: Vec<String>,
  rpo: u32, rto: u32 }` (NO `site`/`status` fields).
- `get(pool, id)` → 404 if absent; `guard_body_site_scope(&session, &plan.site)`
  (scope by the LOADED row's site — site immutable here);
  `update_dr_plan_pure(&plan, …)` → `status_400` on validation;
  `transition(&mut tx, id, version, &updated)` → `false` → 409 (concurrent
  modification — the xmin CAS uses the version from the SAME get, no TOCTOU);
  `record_audit_tx(security_audit("dr-plan-update", None, "updated",
  {plan_id, site}))`; commit; `upsert_plan(&updated)` (write-through); return the
  updated plan JSON.
- Route next to the existing DR-plan routes (contracts.rs ~1503):
  `.route("/api/protect/dr/plans/{id}", put(dr_plan_update))`.
- ALSO add `PUT /api/protect/dr/plans/{id}` to the `dr_contract` endpoint list
  (contracts.rs ~31462) so the self-describing contract advertises it.

## Permission / scope (authorization major — RESOLVED: central gate)
`/api/protect/*` is centrally capability-gated to the `execute` permission
(main.rs:498/700 + the check_permission layer at main.rs:928); the per-handler
`guard_body_site_scope` adds site-scope on top. So PUT is NOT "guarded by
consistency alone" — it inherits `execute` from the central route gate plus
site-scope in the handler, exactly like create/rpo-rto. No inline check_permission
is needed (it would be redundant with the central layer). Documented here so the
authz posture is explicit.

## No migration
No schema change — reuses `dr_plans` (`transition` already stamps `updated_at`).

## Tests (contracts.rs db tests + engine unit tests)
1. **Update happy** (DB): create a plan, PUT new name/targetSite/systems/rpo/rto →
   200; the row's plan_json AND the SCALAR `name` column reflect the new name;
   `status`/`site`/`id`/`last_tested`/`next_test_due` preserved; an audit
   `dr-plan-update` row exists.
2. **Validation**: empty name → 400; empty systems → 400; rpo=0 → 400 (engine unit
   + one DB 400).
3. **Unknown-field rejection**: a body carrying `site` or `status` → the
   axum `deny_unknown_fields` rejection, which is **422 Unprocessable Entity** for a
   plain `Json<T>` extractor in axum 0.8 (NOT 400). Assert 422 — unless the project
   wraps `Json` in a custom extractor that maps serde errors to 400, in which case
   assert that. The point: the smuggle is REJECTED (4xx), not silently ignored.
4. **404**: unknown id → 404.
5. **Concurrent** (DB): update with a stale version (simulate a between-read write)
   → 409 (transition false). Reuse the rpo-rto CAS test shape if present.
6. **Scope** (DB): an out-of-scope plan for a site-scoped session → the same
   guard_body_site_scope outcome as `dr_plan_get` (mirror its scope test).
7. **No-op PUT**: PUT identical values → 200 (idempotent; CAS still advances xmin).
8. **Engine**: `update_dr_plan_pure` happy + each validation + preserves
   id/site/status/last_tested/next_test_due.

## Out of scope (follow-ups)
- **DELETE** /api/protect/dr/plans/{id} — needs an `ON DELETE RESTRICT` FK
  (dr_test_runs.plan_id → dr_plans.id) + reconciling `dr_test_start`'s store-based
  plan resolution with DB residency, + a version-CAS delete distinguishing
  Deleted/HasHistory/StaleOrMissing. Its own slice.
- A DR-plan status lifecycle (Draft→Approved→Active→Expired) endpoint.
- A uniform per-handler capability gate (the central /api/protect→execute gate
  already covers these writes).
