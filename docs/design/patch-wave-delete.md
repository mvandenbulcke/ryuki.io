# Patch-wave DELETE — CRUD completion

Status: SHIPPED (plan review round 2 APPROVE — MAJOR under-auth + MINOR repo-guard folded
in; implementation review APPROVE — both MINORs closed: audit before/after-delta assertion +
explicit DELETE route-gate test). VERIFY-FIRST corrected the swarm's "patch-wave
CRUD" candidate: CREATE (`POST /api/maintain/patch/plan` → `patch_waves::insert`) and
UPDATE (the validate/approve/execute/verify lifecycle transitions) ALREADY EXIST —
only DELETE is genuinely missing. Additive, NO migration, NO engine change.

## Goal
The patch-wave lifecycle is plan→validate→approve→(schedule)→execute→verify, but
there is no way to REMOVE a mistaken / draft / to-be-cancelled wave — operators are
stuck with bad waves forever. Add `DELETE /api/maintain/patch/waves/{id}`.

## Status guard — only UNAPPROVED DRAFTS are deletable (review MAJOR)
`PatchWaveStatus` = Draft / Validated / Approved / Scheduled / InProgress / Completed
/ Failed. DELETE maps to `execute`-tier at the central gate (method-agnostic
last-segment fallthrough), so an Operator must NOT be able to delete an `Approved`
wave — that would CANCEL approver-reviewed work without approve-tier (review MAJOR).
And an executed wave carries evidence. So the boundary is the UNAPPROVED-draft set:
- DELETABLE (execute-tier, pre-approval, no evidence): `Draft`, `Validated` —
  cleanup of a mistaken wave BEFORE it is approved.
- BLOCKED (409): `Approved` / `Scheduled` (approver-reviewed — deleting them is an
  approval-tier cancellation, OUT OF SCOPE for this slice) AND `InProgress` /
  `Completed` / `Failed` (executed — evidence). The pure
  `patch_wave_status_deletable` classifier (Draft|Validated → true, else false) is the
  SINGLE SOURCE OF TRUTH, used by BOTH the handler AND the repo, and unit-tested over
  every variant.

`patch_wave_servers.wave_id REFERENCES patch_waves(id) ON DELETE CASCADE` (mig 010),
so the wave's server rows are removed atomically by the DB on delete — no orphan rows
and no separate cleanup. (Unlike DR-plan DELETE, no FK-RESTRICT history table exists;
the only child is the wave's own server list, which is wave-scoped and cascades.)

## Repo (repos/patch_waves.rs)
`delete(conn, id, expected_status) -> Result<DeleteOutcome, sqlx::Error>` mirroring the
repo's existing optimistic-lock `transition` (status CAS):
```sql
DELETE FROM patch_waves WHERE id = $1 AND status = $2   -- $2 = the loaded status
```
- `rows_affected()==1` → `Deleted`.
- `0` → re-read to disambiguate: row gone → `NotFound`; status changed → `StaleStatus`.
- (The deletability check is in the handler BEFORE the delete; the status CAS closes
  the race where a concurrent transition advances the wave to InProgress between the
  load and the delete — the delete then misses, 0 rows → StaleStatus → 409 reload.)
`DeleteOutcome { Deleted, NotFound, StaleStatus }`.

## Handler + route (contracts.rs) — mirror patch_wave_get + the patch mutation shape
```rust
async fn patch_wave_delete(Path(id): Path<String>, AuthExtractor(session)) -> ApiResult {
    let pool = get_db().ok_or_else(status_503_no_db)?;
    let wave = repos::patch_waves::get(pool, &id).await.map_err(db_error)?.ok_or_else(|| status_404(&id))?;
    // #2 scope: same multi_scope_guard_or_404(site_scope, environment_scope) the other
    // patch handlers use — an out-of-scope wave 404s (no oracle).
    multi_scope_guard_or_404(&session, &wave.site_scope, &wave.environment_scope, &id)?;
    if !patch_wave_status_deletable(&wave.status) {
        return Err(status_409("an executed patch wave (InProgress/Completed/Failed) cannot be deleted"));
    }
    let before = repos::patch_waves::status_str(&wave.status);
    let mut tx = pool.begin().await.map_err(db_error)?;
    match repos::patch_waves::delete(&mut tx, &id, before).await.map_err(db_error)? {
        Deleted => { record_audit_tx(security_audit("patch-wave-delete", Some(before), "deleted", {wave_id:id, site_scope})); commit; Ok(Json(json!({"deleted": id}))) }
        StaleStatus => { rollback; Err(status_409("wave changed concurrently; reload and retry")) }
        NotFound => { rollback; Err(status_404(&id)) }
    }
}
```
Route `.route("/api/maintain/patch/waves/{id}", delete(patch_wave_delete))` MERGED onto
the existing `get(patch_wave_get)` on the same path (method routing, no new path / no
matchit collision). Auth: the central gate maps `/api/maintain/patch/...{id}` →
`execute` (last-segment fallthrough) — operator-tier, matching the other patch
mutations; the handler adds the per-wave site/env scope guard.

## Tests (contracts.rs patch db-tests + an engine/repo unit)
1. **delete happy** (DB): insert a Draft (and an Approved) wave + a `patch_wave_servers`
   child → DELETE → 200 `{deleted}`; a subsequent GET → 404; the child server rows are
   gone (CASCADE); a `patch-wave-delete` audit row exists.
2. **delete blocked when executed** (DB): a Completed (and an InProgress) wave → 409;
   the wave STILL exists (GET → 200).
3. **delete 404**: unknown id → 404; a malformed id → 404/400.
4. **delete scope** (DB): an out-of-scope wave for a site-scoped session → 404 (no oracle).
5. **stale status** (DB / repo): delete with a stale expected_status (a concurrent
   transition bumped it) → `StaleStatus` (handler → 409).
6. **deletability classifier** (pure): Draft/Validated/Approved/Scheduled → true;
   InProgress/Completed/Failed → false (every variant covered).

## Files
- sources/ryuki-api/src/repos/patch_waves.rs (`delete` + `DeleteOutcome` +
  `patch_wave_status_deletable` if placed here, + a repo test).
- sources/ryuki-api/src/contracts.rs (`patch_wave_delete` + route + db tests).
NO migration, NO engine change.

## Out of scope (follow-ups)
- A generic wave field-UPDATE (the lifecycle transitions already cover state changes).
- Soft-delete / archival of executed waves (this slice BLOCKS deleting them to
  preserve evidence; an archive path is separate).
