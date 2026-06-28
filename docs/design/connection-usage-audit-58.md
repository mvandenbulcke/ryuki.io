# #58 — Connection usage audit trail

Status: design — codex plan-review APPROVE (round 2). Round 1 NEEDS-CHANGES fixed:
audit is now AUTHORITATIVE in DB mode (propagates failure), not best-effort; no
audit.rs change; chain-link + leak-risk + append + actor tests specified.

## Goal
When the control plane USES an integration connection — i.e. resolves its
credentials — there is no audit record of that access. `integration_test`
(`POST /api/integrations/{id}/test`, the connection-test handler) is the only
CP-side path that calls `resolve_credentials` (integration.rs:1063); it is
admin-gated and does resolve real credentials, but records nothing in the
hash-chained `audit_log`. So "who accessed which integration's credentials, when,
and did it succeed" is invisible — a security-observability gap for the most
sensitive integration operation.

Add a connection-usage audit row at that single CP usage site: each credential
resolution records ONE durable, hash-chained `audit_log` entry (actor from the
session, connection identity + outcome in `detail`, NEVER the secret).

## Why this is low blast radius
`resolve_credentials` is defined once (integration.rs:212) and called from exactly
ONE non-test site — `integration_test` (everything else is in
`integration_db_tests`, >line 1712). Live-execution credential use is the
owner-domain execution lane (out of scope). So a single hook at `integration_test`
captures all CP connection usage today.

## Reuse the existing audit infrastructure — AUTHORITATIVE recording (codex)
`audit.rs` already provides everything needed; NO audit.rs change:
- `record_audit(pool, session, record)` — hash-chained insert in its own short tx
  (`record_audit_tx` takes the chain lock, links `prev_hash` → `entry_hash`).
- `record_audit_local(session, record)` — the process-local store for no-DB/demo.
- `AuditRecord` (actor is NOT a field — taken only from the `AuthSession`, so a
  forged actor is impossible).

Codex correction: a credential-ACCESS trail must be AUTHORITATIVE, not best-effort.
`last_test_*` / `connection_health_checks` are health TELEMETRY (fine to swallow),
but credential resolution is the sensitive event — a swallowed audit-write failure
would let an access go unrecorded, defeating the feature. So in DB-backed mode the
audit insert PROPAGATES failure (the test call returns 500 rather than completing
an unaudited access); only no-DB/demo mode falls back to the local store. This is a
deliberate contract change from the surrounding best-effort writes, scoped to this
one security row.

## API — `integration_test` hook (integration.rs, after the resolve)
Right after `cred_result` is reduced to `(cred_status, cred_message)` and the stub
result is known, build and record ONE audit row:
```rust
let outcome = if cred_status == "resolved" { "success" } else { "failure" };
let detail = json!({
    "connection_id": id,
    "vendor_type": conn.vendor_type,
    "credential_source": conn.credential_source.as_str(), // TYPE only (vault/db-encrypted/env-var)
    "endpoint_status": test_result.status,
});
let record = audit::AuditRecord {
    action: "integration.connection.tested",
    request_id: None,
    from_status: None,
    to_status: cred_status,        // "resolved" | "error"
    from_stage: None,
    to_stage: "security",
    detail,
    outcome,                       // "success" | "failure"
};
// AUTHORITATIVE in DB mode (propagate failure → 500); local store in no-DB mode.
match get_db() {
    Some(pool) => audit::record_audit(pool, &session, &record).await.map_err(db_err)?,
    None => audit::record_audit_local(&session, &record).await,
}
```
SECRET HYGIENE: `detail` carries only the connection id, vendor type, credential
SOURCE type, and the stub endpoint status — NEVER `credential_ref`, never the
resolved secret (the `ResolvedCredentials` is already zeroized and never logged).
`redact_detail` on every read path is a second line of defence. The audit is
recorded in BOTH DB mode (`record_audit`, authoritative) and no-DB mode
(`record_audit_local`) via the `match get_db()` shown above.

Placement: right after `test_result` is computed and BEFORE the best-effort
`last_test_*` / `connection_health_checks` writes — so an audit-write failure 500s
the call without doing telemetry, and the access is never reported as completed
without its audit row. Record it whether or not the resolution succeeded (a failed
resolution is itself audit-worthy — an attempted credential access).

`cred_message` is DELIBERATELY NOT in `detail` (codex): `CredError`'s Display can
include env key names / vault-resolver text, so only the structured fields above
are stored.

## Tests (new `integration_db_tests`, serialized, cleaned up)
1. **Success path.** Seed a connection with a resolvable credential (the existing
   env-var fixture pattern) + an admin session; call `integration_test`; assert
   exactly one `audit_log` row with `action='integration.connection.tested'`,
   `actor_principal` = the session user, `to_status='resolved'`,
   `outcome='success'`, `to_stage='security'`, and `detail` carrying
   `connection_id` + `vendor_type` + `credential_source` (the TYPE).
2. **Failure path with leak risk (codex).** Seed an env-var connection whose ref
   names a MISSING key (e.g. `RYUKI_INTEGRATION__R58_MISSING`) so resolution fails;
   call `integration_test`; assert one row with `to_status='error'`,
   `outcome='failure'`, AND that `detail::text` contains NEITHER the credential_ref
   string, the (absent) env value, nor any `credential_message` text.
3. **No secret leak (success path).** For a resolvable connection, assert the
   stored `detail::text` does NOT contain the credential_ref value or secret.
4. **Hash chain linked (codex).** Capture the current chain tip (`SELECT entry_hash
   FROM audit_log ORDER BY id DESC LIMIT 1`, or genesis if empty) BEFORE the call;
   after the call assert the new row's `prev_hash` == that captured tip and its
   `entry_hash IS NOT NULL` (proves it chains the predecessor, not just "a hash
   exists").
5. **Append (codex).** Call `integration_test` twice for the same connection →
   exactly two `integration.connection.tested` rows (the trail accumulates).
6. Actor attribution is structurally guaranteed (AuditRecord has no actor field;
   the recorder reads the `AuthSession`) — assert `actor_principal` == the session
   user to lock it in.

## Files
- sources/ryuki-api/src/integration.rs (`integration_test` hook + tests). NO
  audit.rs change — `record_audit` / `record_audit_local` / `AuditRecord` are
  reused as-is.

## Out of scope (follow-ups)
- Auditing live-execution credential use (the agent/execution lane resolves
  credentials during apply — owner-domain; a follow-up when that path is CP-driven).
- A dedicated `GET /api/integrations/{id}/usage` read view (the entries are already
  visible via the existing `/api/activity/audit` feed filtered by
  `action='integration.connection.tested'`).
- Rate-of-access alerting / anomaly detection on credential access.
