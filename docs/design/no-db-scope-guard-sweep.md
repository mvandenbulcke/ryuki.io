# No-DB-branch scope-guard sweep for request-lifecycle mutations (run-5)

## Problem

The #2 site/env-scoped RBAC sweep enforced `scope_guard_or_404` on the **DB branch** of every
request-lifecycle mutation, and a later patch (`approve_one`, commit 21aaa90 / batch-approve
6d4daf0) added the equivalent guard to the **no-DB (in-memory store) branch** of `approve` (and `verify`/
`protect` already guard their no-DB clone branch). But a run-5 analysis swarm + a read-verified
audit found that SIX other mutation handlers still lack the no-DB guard: their DB branch guards
immediately after load, but their no-DB branch clones/mutates
`request_store()[idx]` with NO scope check before the engine call. A scoped principal (e.g. a
GBLON-scoped operator) running against a DB-less deployment (the in-memory fallback / static-preview
mode) can therefore transition a DEFRA request it does not own — a cross-scope mutation and an
existence oracle, exactly what the #2 contract forbids.

Confirmed MISSING the no-DB guard (READ each branch — grep is unreliable for the multi-line
`scope_guard_or_404(` calls): **SIX** handlers.
- `requests_validate` (single-lock no-DB store @ 15766; engine call 15772; DB guard @ 15721)
- `requests_plan` (clone-then-rewrite, clone @ 16335; engine call 16345; DB guard @ 16277)
- `requests_lock` (single-lock store @ 16586; engine call 16592; DB guard @ 16562)
- `requests_execute` (single-lock store @ 16775; engine call 16781; DB guard @ 16667)
- `requests_publish` (clone-then-rewrite, clone @ 17126; engine call 17134; DB guard @ 17089)
- `requests_retire` (clone-then-rewrite, clone @ 17239; engine call 17247; DB guard @ 17202)

Already guarded (DO NOT touch): `approve` (`is_scoped` form @ 16480), `verify` (`scope_guard_or_404`
@ 16883, after clone), `protect` (`scope_guard_or_404` @ 17013, after clone), `reject` (17414),
`fail` (17662), `cancel` (17771). (Codex CORRECTED an earlier hand audit that wrongly flagged
verify/protect — those use a MULTI-LINE `scope_guard_or_404` the grep missed.)

## Severity

MEDIUM, not HIGH: the no-DB branch only runs when `get_db()` is `None` (a DB-less / demo / static
deployment); a production deployment with a DB always takes the (already-guarded) DB branch. But it
is a real authz/consistency gap that the project's own standard (the 4 already-guarded handlers)
treats as must-fix, and it completes the #2 sweep, which is otherwise documented as "complete".

## Approach (mirror the already-guarded `verify`/`protect` no-DB branches)

Use `scope_guard_or_404` (the SAME helper the DB branch and the guarded `verify`/`protect` no-DB
branches use), inserted BEFORE the engine call so an out-of-scope request 404s before any transition.
- **single-lock handlers** (`validate`/`lock`/`execute`): right after the `idx` lookup, before the
  `request_lifecycle::*` call, guarding on the in-store row:
  ```rust
  scope_guard_or_404(&session, &store[idx].site, &store[idx].environment, &request_id)?;
  ```
- **clone-then-rewrite handlers** (`plan`/`publish`/`retire`): right after the clone block, before
  the engine call, guarding on the clone (mirrors `verify` @ 16883 exactly):
  ```rust
  scope_guard_or_404(&session, &cloned_request.site, &cloned_request.environment, &request_id)?;
  ```
No engine change, no migration, no new helper. An unrestricted principal passes unchanged
(`scope_permits([])` permits all).

## Tests

One no-DB test (`requests_lifecycle_mutations_no_db_are_site_scoped`), mirroring
`requests_reject_no_db_is_site_scoped_single_and_batch` + `metrics_budget_is_site_scoped`:
**FAIL-CLOSED first** — `if get_db().is_some() { eprintln!("SKIP: no-DB scope test requires no-DB
mode"); return; }` so it can NEVER false-green via the DB branch (codex B2: `get_db()` reads the
process-global pool, not the env var — a prior DB test could have initialized it; a present pool
would take the DB branch and 404 as not-found). Then seed one DEFRA/Planned in-memory request; build
an execute-tier GBLON-scoped session (`static_dry_run()` + `APP_ROLE_VMWARE_OPERATOR` +
`site_scope = ["GBLON"]`); call each of the 6 handlers and assert `Err((NOT_FOUND, _))` (the scope
guard fires BEFORE the engine stage-check, so a Planned pre-state is fine for all 6); finally assert
the stored request is STILL `Planned` (no cross-scope mutation). The test is meaningful only in a
no-DB process (run via `make test` / no `RYUKI_DATABASE_URL`); it skips (never false-greens) under
`make test-db`.

## Risk / rollback
Purely additive guards; an unrestricted (unscoped) principal is unaffected (`is_scoped` false → the
guard is a no-op). The DB branch and every other path are untouched. Rollback = revert.
