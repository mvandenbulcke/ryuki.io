# Integration connection mutation audit (create / update / set-credential-expiry)

## Problem

The run-3 discovery swarm confirmed: the integration-connection **mutation** surface in
`sources/ryuki-api/src/integration.rs` writes ZERO `audit_log` rows for the operations that
create or change credential-bearing infrastructure connections. Only `integration_test`
(a read-side reachability probe) and — as of commit `352c80b` — `integration_delete` write
audit rows.

The unaudited mutations:
- `integration_create` (L552) — establishes a new credential-bearing connection (db-encrypted
  secret minted, or vault/env-var reference recorded).
- `integration_update` (L839) — mutates connection config AND, for db-encrypted, **rotates the
  encrypted secret ciphertext** (L904-979). A secret rotation with no forensic trail.
- `integration_set_credential_expiry` (L1316) — sets/clears the tracked credential-expiry date.

For a compliance-relevant control plane, an irreversible / credential-bearing mutation that
leaves no forensic trail is a real audit-trail hole. This change closes it for the three
config-mutation handlers, completing the security fix the DELETE half started.

`integration_circuit_reset` (operational breaker reset, not a credential/config mutation) was a
SEPARATE, lower-priority concern — shipped as an immediate follow-up commit (same
`record_audit_tx`-before-commit pattern; it already had the tx + `FOR UPDATE` existence row +
`DELETE`). The reset audits the PRIOR state via `DELETE … RETURNING state`: detail carries
`previous_state` (the breaker's state before reset, or null when no row existed) and
`breaker_cleared` — true ONLY for a tripped prior state (`open`/`half_open`), since a row can be
persisted as healthy `closed`, so row-existence alone is not a real reset. With it, EVERY
integration mutation (create / update / delete / set-credential-expiry / circuit_reset) now writes
an atomic, secret-safe audit row.

## Approach

Mirror the shipped DELETE pattern exactly: the mutation and its audit row commit **atomically in
one transaction** (`record_audit_tx`, whose `?` aborts the tx) so a connection can never be
created/updated without its audit entry, and an audit row can never exist for a rolled-back
mutation. Reuse the existing `audit::security_audit(action, from_status, to_status, detail)`
helper (audit.rs:237) — it produces the `to_stage:"security"`, `request_id:None`,
`outcome:"success"` shape the DELETE handler hand-rolled.

### Secret hygiene (CRITICAL)

The audit `detail` carries ONLY non-secret identity, matching the DELETE precedent. It MUST NEVER
include: `inline_secret` (plaintext), `ciphertext` / `nonce` / `key_id`, or `credential_ref`
(a vault path / env-var key / secret-row id — a reference, but excluded to match DELETE and avoid
leaking vault layout). It MAY include: `connection_id`, `vendor_type`, `site_scope`,
`cred_source` (the TYPE name: `"vault"`/`"env-var"`/`"db-encrypted"`, never a value), and
for update a boolean `cred_rotated`, and for set-expiry the non-secret `cred_expires_at`
timestamp (or null).

### Redaction-safe detail keys (CRITICAL — #58 convention)

The audit READ surfaces (the `/api/activity/audit` feed, SIEM export) run `redact_detail`, which
blanks any value whose KEY contains a `SENSITIVE_KEY_PATTERNS` substring
(`{password, secret, token, credential, key, private, auth}` — substring match,
`evidence_pipeline.rs:6`). So a key named `credential_source` / `secret_rotated` /
`credential_expires_at` would have its value replaced with `***REDACTED***` on every read —
fail-SAFE (never leaks) but it DESTROYS the audit's observability. The #58 connection-usage-audit
feature already hit this and solved it by naming the key `cred_source` (test
`usage_audit_cred_source_survives_redaction_on_read`). This change follows that convention exactly:
`cred_source`, `cred_rotated`, `cred_expires_at` (none contain a pattern substring). `connection_id`,
`vendor_type`, `site_scope`, `cleared` are already pattern-free. A new test asserts the keys survive
`redact_detail` on the read path.

### Audit the PERSISTED row (blocker 2)

Mirror DELETE: the audit detail is built from `... RETURNING vendor_type, site_scope,
credential_source` (the row the DB actually persisted), NOT from caller-derived or pre-read state,
and the audit fires only on the returned row. For `update` this also closes a latent TOCTOU — today
the plain branch does `.execute(pool)`; if the row was concurrently deleted after the pre-read
SELECT, it updates 0 rows yet still returns 200. With `UPDATE … RETURNING … fetch_optional` + None →
404, a vanished row is a clean 404 with no audit row (empty tx rolls back). For `create` there is no
prior row to be stale against, but `INSERT … RETURNING` is used uniformly (it also sidesteps the
`body.*` move into the response `conn`).

### Per-handler plan

**`integration_create`** — 3 success branches, all get an audit row:
- db-encrypted DB path (currently commits its own tx at L645): add `record_audit_tx` BEFORE the
  existing `tx.commit()`. Already atomic — no new tx.
- vault/env-var DB path (currently a single `.execute(pool)` at L698): wrap the INSERT in a tx
  (`pool.begin()` → INSERT on `&mut *tx` → `record_audit_tx` → `tx.commit()`), so insert + audit
  are atomic.
- in-memory fallback (L742-755): `record_audit_local` after `create_connection` (mirrors DELETE's
  no-DB branch; best-effort, no tx available).
- action `"integration.connection.created"`, `from_status: None`, `to_status: "configured"`,
  detail `{connection_id, vendor_type, site_scope, cred_source}`.

**`integration_update`** — 2 DB success branches:
- db-encrypted secret-rotation path (commits its own tx at L973): add `record_audit_tx` before
  commit; detail `secret_rotated: true`.
- plain-update path (single `.execute(pool)` at L996): wrap in a tx; detail `secret_rotated: false`.
- in-memory path errors out (L1007) — no mutation, no audit.
- action `"integration.connection.updated"`, `from_status: None`, `to_status: "configured"`,
  detail `{connection_id, vendor_type, site_scope, cred_source, cred_rotated}`.

**`integration_set_credential_expiry`** — 1 success branch:
- currently `UPDATE … RETURNING` via `fetch_optional(pool)` (L1360): wrap in a tx (run the
  RETURNING on `&mut *tx`, then `record_audit_tx`, then commit); a missing row still rolls back
  the empty tx → clean 404 with no audit row.
- action `"integration.connection.credential_expiry_set"`, `from_status: None`,
  `to_status: "configured"`, detail `{connection_id, cred_expires_at, cleared: bool}`.

## Tests

DB tests (global_pool, DB_TEST_SERIAL), mirroring `integration_delete_writes_audit_without_secret`:
- create (db-encrypted) writes an `integration.connection.created` audit row, and the row's
  `detail` contains NO `inline_secret` / `ciphertext` / `credential_ref`.
- create (vault) writes a created audit row atomically.
- update (db-encrypted, with inline_secret) writes an `updated` row with `secret_rotated: true`
  and no secret material in detail.
- update (plain) writes `secret_rotated: false`.
- set_credential_expiry writes a `credential_expiry_set` row; unknown id → 404, no audit row.
- a unique vendor_type/site_scope per test isolates assertions (audit_log is append-only — no
  cleanup; query by the unique connection_id).

## Risk / rollback

Pure additive: new audit rows + two currently-pool-direct writes wrapped in transactions (no
behavior change to the mutation itself). No migration. No engine change. Rollback = revert the
commit. Append-only `audit_log` is unaffected structurally.
