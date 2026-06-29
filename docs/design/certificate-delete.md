# Certificate DELETE — terminal-cert cleanup (CRUD completion)

Status: implemented (codex plan APPROVE, no findings; one impl caveat folded in — the
cert `transition` UPDATE rewrites `site = $8`, so site IS mechanically mutable; the repo
delete therefore CASes on `site` too (`AND site = $3`, binding the loaded site) so a
concurrent site change between the scope check and the delete yields StaleStatus → 409,
never a cross-scope delete). Verify-first swarm 2026-06-29 finding #14.
VERIFIED: no `certificates_delete` handler, no `repos::certificates::delete`, no DELETE
route (only test cleanup runs `DELETE FROM certificates`). The cert lifecycle is
request→validate→approve→install→verify→(renew)→revoke (status transitions Active/
Expiring/Expired/Revoked), but there is no way to REMOVE a dead cert record. This is a
near-exact clone of the codex-approved patch-wave-delete (2acdc50-era), SIMPLER: NO FK
references certificates (leaf table → no cascade), and certs are SITE-ONLY scoped.
Additive: NO migration, NO engine change.

## Status guard — only TERMINAL certs are deletable (the patch-wave MAJOR lesson)
DELETE maps to `execute`-tier (the `/api/maintain` prefix, method-agnostic gate). An
operator must NOT be able to delete a LIVE cert from the execute tier:
- DELETABLE (terminal, dead): `Expired`, `Revoked` — operational cleanup of a record
  that no longer represents a usable certificate.
- BLOCKED (409): `Active`, `Expiring` — the cert is IN USE (serving or imminently
  expiring); removing its record would lose tracking of a live certificate. The pure
  `certificate_status_deletable` classifier (Expired|Revoked → true) is the SINGLE source
  of truth, used by BOTH the handler 409 gate AND the repo defense-in-depth guard.

No FK references `certificates` (verified — no `REFERENCES certificates` / `certificate_id`
in any migration), so there is no child cascade and no orphan concern.

## Repo (repos/certificates.rs) — mirror patch_waves
- `certificate_status_deletable(status: &CertificateStatus) -> bool` (Expired|Revoked).
- `DeleteOutcome { Deleted, NotFound, StaleStatus, BlockedStatus }`.
- `delete(conn: &mut PgConnection, id, expected: &CertificateStatus) -> Result<DeleteOutcome>`:
  BlockedStatus if `!deletable(expected)`; else `DELETE FROM certificates WHERE id=$1 AND
  status=$2` (`$2 = status_str(expected)` — the EXISTING repo `status_str`, PascalCase CAS);
  1 row → Deleted; 0 → re-read status (None → NotFound, Some → StaleStatus). A malformed
  (non-UUID) id → NotFound (uniform with `get`).

## Handler + route (contracts.rs) — mirror patch_wave_delete
`certificates_delete(AuthExtractor, Path(id))`: `get`→404; `scope_guard_or_404(&session,
&cert.site, "", &id)` (SITE-only, like `certificates_get` — out-of-scope 404s, no oracle);
`if !certificate_status_deletable(&cert.status) → 409`; tx; `delete`; match — Deleted →
tombstone audit `record_audit_tx(security_audit("certificate-delete", Some(before),
"deleted", {certificate_id, common_name, hostname, site}))` + commit + 200 `{deleted}`;
BlockedStatus/StaleStatus → 409; NotFound → 404. Route:
`.route("/api/maintain/certificates/{id}", get(certificates_get).delete(certificates_delete))`
(method-merge, no new path). Audit hygiene: common_name/hostname/site are identity (already
exposed by the cert read endpoints); the table stores NO private key/CSR/secret material.

## Tests (contracts.rs cert db-tests + a pure unit)
1. **classifier** (pure): Expired/Revoked → true; Active/Expiring → false (all 4).
2. **delete happy** (DB): seed an Expired (and a Revoked) cert → DELETE → 200 `{deleted}`;
   GET → 404; a `certificate-delete` audit row exists for the cert id (the id is a fresh
   gen_random_uuid, so the EXISTS check can't false-pass on a stale row).
3. **delete blocked** (DB): seed an Active (and an Expiring) cert → 409; the cert STILL
   exists (GET → 200).
4. **delete 404 + scope** (DB): unknown id → 404; an out-of-scope cert (wrong site) for a
   site-scoped session → 404 (no oracle).
5. **repo stale + blocked** (DB/repo): `delete` with a stale expected (a concurrent
   transition bumped the status) → StaleStatus; `delete` with a non-deletable expected →
   BlockedStatus.

## Files
- sources/ryuki-api/src/repos/certificates.rs (`delete` + `DeleteOutcome` +
  `certificate_status_deletable`; add `PgConnection` to the sqlx import).
- sources/ryuki-api/src/contracts.rs (`certificates_delete` + route + tests).
NO migration, NO engine change.

## Out of scope
- Soft-delete/archival of terminal certs (this slice removes the record; an archive path
  is separate).
- Deleting Active/Expiring certs (blocked — they are live; revoke them first, which lands
  Revoked → then deletable).

## Codex review (both rounds APPROVE)
Plan APPROVE (no findings; the site-CAS impl caveat folded in). Impl APPROVE (no
BLOCKER/MAJOR); one MINOR folded in — a dedicated repo test passes the right status but a
WRONG `expected_site` to PIN the site CAS (right status, wrong site → StaleStatus, never a
cross-scope delete).
