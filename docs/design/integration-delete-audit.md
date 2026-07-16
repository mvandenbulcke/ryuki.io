# Audit integration-connection DELETE — close the destructive-mutation forensic gap

Status: SHIPPED (run-3 discovery swarm, CONFIRMED H/S). Plan review NEEDS-CHANGES → APPROVE (the
no-DB TOCTOU MAJOR fixed with an atomic engine `delete_connection_returning`; `from_status: None`;
cascade documented), implementation review APPROVE (the "exactly one" count assertion added). The
integration-connection MUTATION
handlers write NO audit_log row — only `integration_test` audits (integration.rs:1114). Slice 1
closes the WORST hole: `integration_delete` (an irreversible op on a credential-bearing provider
integration) leaves ZERO forensic trail. Additive audit, NO migration, NO behavior change beyond
the new audit row + making the delete atomic with it.

## The gap (verified)
`integration_delete` (integration.rs:1011) does a raw `DELETE FROM integration_connections WHERE
id=$1` and returns — NO `record_audit`. So "who deleted integration X, when, and why" is
unanswerable, for a row that gated provider calls and referenced credentials. (`integration_create`
/`integration_update`/`integration_circuit_reset`/`integration_set_credential_expiry` are also
unaudited — deferred, see Out of scope; `integration_test` already audits, integration.rs:1114.)

## Design — atomic DELETE + audit, mirroring the existing audit shape
The deletion and its audit row commit together (a destructive op must never leave the row gone with
no trace, nor a trace with no deletion).

### DB branch (integration.rs:1017)
Wrap in one tx:
```
let mut tx = pool.begin()?;
// RETURNING the deleted row's NON-SECRET identity for the audit detail.
let deleted: Option<(String, Option<String>)> = sqlx::query_as(
    "DELETE FROM integration_connections WHERE id = $1 RETURNING vendor_type, site_scope"
).bind(&id).fetch_optional(&mut *tx).await?;
let Some((vendor_type, site_scope)) = deleted else { return integration_not_found(&id) };  // (rolls back the empty tx)
audit::record_audit_tx(&mut tx, &session, &audit::AuditRecord {
    action: "integration.connection.deleted",
    request_id: None, from_status: None, to_status: "deleted",   // from_status None — we do not read a prior runtime status (MINOR)
    from_stage: None, to_stage: "security",
    detail: json!({ "connection_id": id, "vendor_type": vendor_type, "site_scope": site_scope }),
    outcome: "success",
})?;
tx.commit()?;
return Ok(Json(json!({"deleted": id})));
```
(Secret hygiene: the detail carries connection_id + vendor_type + site_scope ONLY — NEVER
`credential_ref` / `credential_source` value / vault path. If a `db-encrypted` connection had an
`integration_secrets` row, the FK CASCADE removes it with the connection — that is intentional and
NOT surfaced in the event (no secret name/ref). The `record_audit_tx` failure path aborts the whole
tx via `?`, so there is never a committed delete without its audit row.)

### No-DB branch (integration.rs:1030)
ATOMIC remove-and-return (MAJOR — avoid the `get_connection` then `delete_connection` TOCTOU
of two separate mutex acquisitions): add an engine `delete_connection_returning(id) ->
Option<IntegrationConnection>` that removes AND returns the deleted connection under ONE lock. On
`Some(conn)`: `record_audit_local` with the same AuditRecord (`vendor_type`/`site_scope` from the
returned conn). On `None`: 404.

## Tests (integration_db_tests + a no-DB)
- DB: seed a connection → DELETE via the handler → 200; the row is gone; exactly ONE
  `integration.connection.deleted` audit row whose detail has connection_id + vendor_type + site_scope
  and NO `credential_ref`/vault/secret field.
- DB: deleting an unknown id → 404 and writes NO audit row (the empty tx rolls back).
- No-DB: delete an in-memory connection → 200 + a local audit (best-effort); unknown → 404.
- 403: a non-admin session → 403 (require_admin, unchanged).

## Out of scope (the documented follow-up)
- Auditing `integration_create` / `integration_update` (multi-branch, tx-bearing, FK-ordered
  credential handlers — careful separate work) + `integration_circuit_reset` /
  `integration_set_credential_expiry`. Delete is the destructive, irreversible op that most needs the
  trail first.
- The companion run-3 "no site-scope guard" finding is MOOT (admin = superuser in this RBAC).
