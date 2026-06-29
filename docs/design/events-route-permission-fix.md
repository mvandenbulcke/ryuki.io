# Fix: /api/events POST mutations are accidentally admin-only

Status: SHIPPED (codex plan NEEDS-CHANGES → 3 MAJOR + 1 MINOR folded in; codex impl APPROVE,
no blocking findings — codex also swept for the same bug class and found NO remaining
instances, so these two were the only ones). Second verify-first analysis swarm (2026-06-29
run 2) found the /api/events INTEGRATION BUG; I VERIFIED both against the code — REAL, and the
/api/events one predates the bulk-alert-ack slice (the single-ack has it too).

## The bug (verified)
The auth middleware (main.rs:936-951) gates an UNSAFE, non-self-service method with
`route_permission_for(method, path)` then `check_permission(session, required)` → 403 on
failure. `route_permission_for` (main.rs:675) matches the path against `ROUTE_PERMISSIONS`,
falling back to `DEFAULT_ROUTE_PERMISSION = "admin"` (main.rs:567) when nothing matches.

`/api/events` is NOT in `ROUTE_PERMISSIONS` (verified — no `/api/events` prefix entry). So a
POST to `/api/events/alerts/{event_id}/ack` or `/api/events/alerts/batch/ack` resolves to
`admin` at the gate. But BOTH handlers (events_alert_ack contracts.rs:18940, and the new
events_alert_batch_ack:19019) check `check_permission(&session, "request")` — their INTENDED
tier. `is_self_service_mutation` (main.rs:808) covers only notifications + user-preferences,
NOT alert-ack. Net effect: a non-admin `request`-tier principal is 403'd at the MIDDLEWARE
("Missing required permission: admin") and never reaches the handler — alert ack is
accidentally ADMIN-ONLY, contradicting the handlers' `request`-tier design.

Why it was missed: the events ack routes are NOT in the `MUTATING_ROUTES` test list (so
`test_every_mutating_route_resolves_to_a_permission` never checked them), and every
handler-direct test uses `static_dry_run` (an admin superuser), which bypasses the
middleware AND satisfies the handler's `request` check via the admin-superuser rule.

## Scope (verified)
The ONLY POST routes under `/api/events` are the two ack endpoints (both `request`-tier
handlers). There is no event-CREATE/DELETE POST. So a single `/api/events → request` prefix
entry affects ONLY these two acks — it cannot loosen a more-privileged route.

## Tier — `request` (codex-resolved)
`request`, matching the handlers. NOT broadened to `audit`: codex verified that `events_list`
+ `events_alerts` (the alert READS) ALSO handler-check `"request"` (contracts.rs:18781/18850),
so the feed is request-tier end-to-end. Broadening ack to `audit||request` would let the
read-only `Auditor` mutate ack state — a policy change, out of scope.

## A SECOND same-class bug (codex MAJOR): /api/audit/log/verify
`POST /api/audit/log/verify` (contracts.rs:177) → `audit_log_verify` checks
`check_permission("audit")` (contracts.rs:19634), but no `/api/audit` mutating prefix exists
(only `/api/audit/compliance/*` specifics), so the middleware defaults it to `admin` — an
auditor cannot re-verify the hash chain. Same class, fixed in the same patch.

## Fix — a tight SHAPE MATCHER (codex MINOR — preserve fail-closed)
Mirror `approval_signoff_permission` (a special-case fn checked in `route_permission_for`
BEFORE the prefix table), NOT a method-agnostic `/api/events`/`/api/audit` prefix (which would
silently open FUTURE unsafe routes under those families). Add:
```rust
fn unclassified_family_mutation_permission(path: &str) -> Option<&'static str> {
    // Alert acknowledgement (events_alert_ack / events_alert_batch_ack check `request`).
    if path.starts_with("/api/events/alerts/") && path.ends_with("/ack") {
        return Some("request");
    }
    // Audit-chain verify (audit_log_verify checks `audit`).
    if path == "/api/audit/log/verify" {
        return Some("audit");
    }
    None
}
```
Called in `route_permission_for` after `approval_signoff_permission`, before the prefix
table. So `/api/events/alerts/{id}/ack` + `/api/events/alerts/batch/ack` → `request`,
`/api/audit/log/verify` → `audit`; any OTHER `/api/events/*` or `/api/audit/*` mutation stays
fail-closed (admin default).

## Tests (codex: the == assertions are NECESSARY — MUTATING_ROUTES alone isn't enough since
`admin` is a valid resolved permission)
- `route_permission_for(POST, "/api/events/alerts/e1/ack") == "request"`,
  `(... "/api/events/alerts/batch/ack") == "request"`, `(... "/api/audit/log/verify") ==
  "audit"`.
- FAIL-CLOSED preserved: `route_permission_for(POST, "/api/events/alerts/e1/suppress")` (a
  hypothetical non-ack) `== "admin"`, and `(... "/api/audit/log/rotate")` `== "admin"` — the
  shape matcher does NOT over-match.
- Add the 3 real paths to `MUTATING_ROUTES` so the resolves-to-a-permission sweep covers them.

## Files
- sources/ryuki-api/src/main.rs (the shape-matcher fn + its call in route_permission_for +
  MUTATING_ROUTES + the assertions). NO migration, NO engine change, NO handler change.

## Out of scope
- Auditing EVERY mutating route for an unregistered-prefix → admin-default mismatch (a
  broader hardening sweep; this fixes the confirmed /api/events case + adds the regression
  guard). A follow-up could assert every POST route in the router appears in MUTATING_ROUTES.
- Broadening alert-ack to the read tier (the tier question above) — deferred to product.
