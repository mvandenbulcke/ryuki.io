# DR-plan DELETE — CRUD completion (deferred half of dr-plan-update-delete)

Status: IMPLEMENTED (dedicated fresh-context session). Codex plan review = 3 rounds
(1 blocker + majors + the store-model blocker, all folded in below); codex
implementation review = 4 rounds (round 1: fail-open hydration + reconcile-test
overclaim; round 2: "unknown ≠ empty" for the store-backed reads; round 3: scoped
the FK pg_constraint guard + accurate lock comment; round 4: final APPROVE). The
DEFERRAL reasoning below is retained as the historical record of WHY this was a
multi-system change (live-data FK migration + the live-execution-adjacent
`dr_test_start` + making the DR store DB-authoritative) rather than the clean CRUD
slice it first appeared. Completes DR-plan CRUD (create/list/get/PUT/DELETE).

What shipped: migration 124 (seed backfill → fail-loud orphan guard → scoped,
NOT VALID/VALIDATE `ON DELETE RESTRICT` FK on `dr_test_runs.plan_id`);
`dr_testing::remove_plan` (delete write-through) + `replace_plans` (DB-authoritative
startup reconcile, replacing upsert-on-top so a deleted seed plan can't resurrect);
`repos::dr_plans::delete` (xmin CAS + NOT-EXISTS precheck + 23503 backstop →
`DeleteOutcome`); the `dr_plan_delete` handler + route + dr_contract entry; the
`dr_test_start` 23503→409 catch; fatal-on-failure DB-mode hydration. 8 new DR
DB-tests + 1 engine test, all green.

## Codex round-1 fixes (folded into the sections below)
- BLOCKER (FK safety): migration 124 must BACKFILL the 3 migration-087 `dr_plans`
  seed rows (INSERT … ON CONFLICT DO NOTHING) BEFORE any orphan handling — an older
  DB with 087 marked-applied-but-seed-rows-absent + the static `seed_data()` store
  would otherwise let `dr_test_start` resolve a store plan with no DB row and fail
  the FK.
- MAJOR (no silent history loss): do NOT silently `DELETE` orphan `dr_test_runs`.
  After the seed backfill, if any orphan remains (a run referencing a truly-unknown
  plan), the migration FAILS LOUDLY (a `DO` block that RAISEs) so an operator
  handles it — silent deletion of audit-relevant history is not an acceptable
  default.
- MAJOR (concurrent test-start ⇒ 500): a concurrent `dr_test_start` hitting the new
  FK currently maps through generic `db_error` ⇒ HTTP 500. `dr_test_start` must
  catch FK `23503` and return 409/404 ("plan was deleted concurrently; reload").
- MAJOR (delete race / 0-row ambiguity): the `DELETE … NOT EXISTS` can race a
  concurrent run insert and the FK can make the DELETE itself ERROR (not return 0
  rows). The repo `delete` must catch FK `23503` ⇒ `HasHistory`, AND re-read on 0
  rows ⇒ `NotFound`/`StaleVersion`. (Parent-row `SELECT … FOR UPDATE` is the
  alternative; the 23503-catch is simpler and codex-accepted.)

## Codex round-2 — the deeper blocker (why this needs a dedicated session)
Round 2 confirmed the four fixes above but found a STORE-MODEL major: DELETE is not
durable for SEED plans across a restart. `DR_STORE` is initialized from
`seed_data()` at every startup (`dr_testing.rs:105`) and hydration only UPSERTS DB
rows on top (`main.rs:1567`) — it never REMOVES store rows absent from `dr_plans`.
So deleting a seed plan (e.g. `drp-defra-001`) with no DB history is undone on the
next restart: `seed_data()` resurrects it into the store, which `dr_test_start`,
due-tests, and readiness still read. The FK + 23503 catches prevent orphaning/500s,
but the invariant "every store plan has a DB row" no longer holds after a seed
delete. The proper fix is to make DB-mode startup RECONCILE the store to be
DB-authoritative (replace, not just upsert-on-top-of-seed) — an architectural change
to the DR domain's bootstrap, plus a restart/hydration regression test. THIS is why
implementation is deferred to a dedicated session: across the PUT review + two DELETE
reviews, codex has peeled back three layers of store-vs-DB entanglement, and a
correct DELETE requires making the DR store DB-authoritative — not a CRUD add-on.

## Goal
`DELETE /api/protect/dr/plans/{id}` so an operator can remove a mistaken/stale DR
plan. A plan with test-run HISTORY must NOT be silently deletable (the runs are
audit-relevant), and a concurrent `dr_test_start` must never orphan a run against a
deleted plan.

## The race + why an FK is the fix (codex blocker from the PUT review)
`dr_test_runs.plan_id` has NO FK (mig 088), and `dr_test_start` resolves the plan
from the in-memory store (`get_plan_from_store`) then INSERTs a run — so a NOT-EXISTS
check in the DELETE cannot stop a concurrent test-start from inserting a run after
the check, orphaning history. The race-free fix is an `ON DELETE RESTRICT` foreign
key: it blocks deleting a plan that has runs AND blocks inserting a run for a
deleted plan (the test-start INSERT fails), closing both sides.

### FK safety — VERIFIED (the PUT slice's concern)
The worry was that `dr_test_start` could insert a run for a STORE-only plan absent
from `dr_plans`, which the FK would reject. Verified this cannot happen in DB mode:
- `seed_data()` seeds the store with exactly `{drp-defra-001, drp-gblon-001,
  drp-frpar-001}` — the SAME 3 ids migration 087 seeds into `dr_plans`.
- Startup hydration (`main.rs:1575`, `dr_plans::list` → store) loads DB plans into
  the store; `dr_plan_create` writes the DB row FIRST then `upsert_plan` (store).
- So every store plan has a `dr_plans` row; a test-start always references a
  DB-resident plan → the FK is always satisfied. (No-DB mode never inserts — it 503s
  at `get_db()`.) So the FK needs NO change to `dr_test_start`.

## Migration 124 (idempotent, guarded — codex-corrected)
```sql
-- 1. BACKFILL the 3 migration-087 seed plans first (covers an older DB where 087
--    is marked applied but its seed rows are absent), so static-store seed plans
--    have a dr_plans row and dr_test_start never fails the FK.
INSERT INTO dr_plans (id, name, site, status, plan_json) VALUES
  ('drp-defra-001', …087 values…), ('drp-gblon-001', …), ('drp-frpar-001', …)
  ON CONFLICT (id) DO NOTHING;
-- 2. FAIL LOUDLY on any REMAINING orphan run (do NOT silently delete history):
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM dr_test_runs r
             WHERE NOT EXISTS (SELECT 1 FROM dr_plans p WHERE p.id = r.plan_id))
  THEN RAISE EXCEPTION 'orphan dr_test_runs exist (plan_id not in dr_plans); '
                       'resolve before adding the FK — refusing to drop history';
  END IF;
END $$;
-- 3. Add the FK (re-runnable).
ALTER TABLE dr_test_runs DROP CONSTRAINT IF EXISTS fk_dr_test_runs_plan;
ALTER TABLE dr_test_runs ADD CONSTRAINT fk_dr_test_runs_plan
    FOREIGN KEY (plan_id) REFERENCES dr_plans(id) ON DELETE RESTRICT;
```
The ADD CONSTRAINT takes an ACCESS EXCLUSIVE lock on dr_test_runs, validating the
existing rows atomically — so no in-flight orphan insert can slip past (it blocks
on the lock, then fails the validated constraint). Backfill + fail-loud means zero
silent history loss; a healthy DB (seeds align) passes the DO block trivially.

## Engine (`sources/ryuki-engine/src/dr_testing.rs`)
`remove_plan(id: &str)` — remove the plan from the static store (mirror
`upsert_plan`), for the DELETE write-through, so a deleted plan can no longer be
resolved by `dr_test_start` (`get_plan_from_store`). Unit-tested (remove makes a
seeded plan un-resolvable).

## Repo (`sources/ryuki-api/src/repos/dr_plans.rs`)
`delete(executor, id, expected_version) -> Result<DeleteOutcome, sqlx::Error>`:
```sql
DELETE FROM dr_plans
WHERE id = $1 AND xmin = $2::xid
  AND NOT EXISTS (SELECT 1 FROM dr_test_runs WHERE plan_id = $1)
```
Returns `Deleted` when `rows_affected()==1`. When `0`, the caller re-reads to
disambiguate: `NotFound` (row gone), `HasHistory` (runs exist), or `StaleVersion`
(xmin changed). CODEX FIX (race): the repo ALSO catches an FK `23503` error from the
DELETE itself (a run inserted concurrently after the NOT-EXISTS snapshot makes the
RESTRICT block the delete) and maps it to `HasHistory`. So both the 0-row path
(re-read) AND the constraint-error path resolve to a precise outcome — the
`NOT EXISTS` is the friendly common-case precheck and the FK is the structural race
backstop (a concurrent test-start can't orphan; its INSERT fails the FK).

## `dr_test_start` (codex major — concurrent-delete must not 500)
A concurrent delete makes a racing `dr_test_start`'s run INSERT fail the new FK
(`23503`). Today that maps through generic `db_error` ⇒ HTTP 500. Add a targeted
catch in `dr_test_start`: an FK `23503` on the run insert ⇒ 409/404 ("plan was
deleted concurrently; reload and retry"), not 500. This is the one (small, reviewed)
change to the live-execution-adjacent handler the FK necessitates.

## API (`sources/ryuki-api/src/contracts.rs`)
`DELETE /api/protect/dr/plans/{id}` → `dr_plan_delete` (mirror the PUT handler's
load+scope shape):
- `get(pool, id)` → 404 if absent; `guard_body_site_scope(&session, &plan.site)`;
  `tx`; `delete(&mut tx, id, &version)`:
  - `Deleted` → `record_audit_tx(security_audit("dr-plan-delete", None, "deleted",
    {plan_id, site}))`; commit; `remove_plan(id)` (write-through); return
    `200 {"deleted": id}`.
  - `HasHistory` → 409 ("plan has test-run history; cannot delete").
  - `StaleVersion` → 409 ("plan was modified concurrently; reload and retry").
  - `NotFound` → 404.
- Route `.route("/api/protect/dr/plans/{id}", delete(dr_plan_delete))` next to the
  PUT route; add `DELETE /api/protect/dr/plans/{id}` to the `dr_contract` list.
- Authz: the central `/api/protect`→`execute` gate + the handler site-scope (same as
  create/PUT/rpo-rto). Reads are unchanged.

## Tests (contracts.rs db tests + engine units)
1. **Delete happy** (DB): create a plan with NO runs → DELETE → 200; a subsequent
   GET → 404; the store no longer resolves it (a follow-up test-start → 404); a
   `dr-plan-delete` audit row exists.
2. **Delete blocked by history** (DB): create a plan + a `dr_test_runs` row for it →
   DELETE → 409; the plan STILL exists (GET → 200) and the run is intact.
3. **FK blocks orphaning** (DB): the FK is proven by attempting to INSERT a
   `dr_test_runs` row for a non-existent plan_id → fails (23503); and after deleting
   a runless plan, a run can no longer reference it.
4. **Delete 404**: unknown id → 404.
5. **Delete scope** (DB): out-of-scope plan for a site-scoped session → the
   guard_body_site_scope rejection (mirror dr_plan_get).
6. **Stale version** (DB): a delete with a stale xmin (concurrent write bumped it)
   → 409 (repo-CAS regression, like the PUT slice's stale-version test).
7. **Migration 124 idempotency** (DB): re-running the SQL is a no-op; the FK exists
   (an orphan INSERT is rejected) after re-run.
8. **Engine**: `remove_plan` makes a seeded plan un-resolvable via
   `get_plan_from_store`.
9. **Second DELETE** (codex): a second DELETE after a successful one → 404 (and the
   store stays absent).
10. **Concurrent test-start vs delete** (codex): a `dr_test_start` racing a delete
    → 409/404 ("deleted concurrently"), NOT 500.
11. **Migration backfill** (codex): with `dr_test_runs` seeds present but a
    `dr_plans` seed row absent, migration 124 BACKFILLS the seed (history kept), and
    only a truly-unknown orphan makes it RAISE — it never silently drops history.

## Files
- migrations/124_dr_test_runs_fk.sql (new — seed BACKFILL + fail-loud orphan guard + FK)
- sources/ryuki-engine/src/dr_testing.rs (`remove_plan` + test)
- sources/ryuki-api/src/repos/dr_plans.rs (`delete` + `DeleteOutcome`, incl. 23503-catch)
- sources/ryuki-api/src/contracts.rs (`dr_plan_delete` + route + dr_contract +
  the `dr_test_start` 23503→409 catch + tests)

## Out of scope (follow-ups)
- A DR-plan status lifecycle (retire via Expired vs delete-for-mistakes).
- Cascade-delete of runs (this slice BLOCKS instead, protecting history).
