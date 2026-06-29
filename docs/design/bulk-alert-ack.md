# Bulk alert acknowledge — POST /api/events/alerts/batch/ack

Status: SHIPPED (codex plan APPROVE + impl APPROVE, no defects; 3 plan MINORs folded in —
an explicit whole-batch 403 test with the ack-specific body; the dedup test asserts the
RESPONSE contract (results.len()==1, not just the upsert DB row); the note-validation test
uses an embedded control char "bad\nnote" that survives trim). Verify-first swarm
2026-06-29 finding #19.
VERIFIED: only SINGLE-event ack exists — `POST /api/events/alerts/{event_id}/ack`
(events_alert_ack, contracts.rs:18933), `request`-tier, with a per-event scope-visibility
check (`event_scope` → 404 if out-of-scope or missing, no oracle) then
`domain_events::ack_alert`. There is no batch ack — an operator clears alerts one-by-one.
Mirrors the shipped `requests_batch_*` (#17) pattern exactly. Additive: NO migration, NO
engine change.

## Refactor — extract `ack_alert_one` (shared single + batch core)
The single handler's body (scope-visibility check → 404; `ack_alert` → false → 404) becomes
a shared core, exactly as `approve_one`/`reject_one` were extracted for the request batches:
```rust
async fn ack_alert_one(
    session: &AuthSession,
    pool: &PgPool,
    event_id: i64,
    note: Option<&str>,
) -> Result<(), (StatusCode, Json<Value>)> {
    use ryuki_engine::auth::scope_permits;
    match crate::repos::domain_events::event_scope(pool, event_id).await.map_err(db_error)? {
        Some((site, environment)) => {
            let site_ok = site.is_none() || scope_permits(&session.site_scope, site.as_deref());
            let env_ok = environment.is_none()
                || scope_permits(&session.environment_scope, environment.as_deref());
            if !(site_ok && env_ok) { return Err(status_404(&event_id.to_string())); }
        }
        None => return Err(status_404(&event_id.to_string())),
    }
    if !crate::repos::domain_events::ack_alert(pool, event_id, &session.user_id, note).await.map_err(db_error)? {
        return Err(status_404(&event_id.to_string()));
    }
    Ok(())
}
```
`events_alert_ack` keeps its capability check + note validation + get_db, then calls
`ack_alert_one` once and wraps the existing `{acknowledged, event_id, acknowledged_by}`
response — NO behavior change to the single endpoint.

## Batch handler (mirror requests_batch_*)
`events_alert_batch_ack(AuthExtractor, Json<BatchAlertAckBody>)` where
`BatchAlertAckBody { event_ids: Vec<i64>, note: Option<String> }`:
1. `check_permission(&session, "request")` → 403 (the flat capability checked ONCE up front).
2. `event_ids` non-empty → else 400; `len() <= 100` → else 400 (the shared batch cap).
3. note: trim + `reject_control_chars` ONCE (shared by all items).
4. `get_db()` → 503 if absent.
5. DEDUP `event_ids` preserving order (HashSet on the i64).
6. Per item: `ack_alert_one(&session, pool, id, note)` → `{event_id, ok:true}` on Ok, or
   `{event_id, ok:false, status, error}` on Err (per-item independent; one bad id never
   aborts the batch).
7. Return `{results, succeeded, failed}`, HTTP 200 ALWAYS (partial success), like the
   request batches.

## Route
`.route("/api/events/alerts/batch/ack", post(events_alert_batch_ack))`. The static `batch`
segment coexists with `/api/events/alerts/{event_id}/ack` — proven by the shipped
`/api/requests/batch/*` routes coexisting with `/api/requests/{id}/*` (matchit: static wins;
the route-tree smoke test confirms no collision). `request`-tier via the central gate
(`/api/events` UNSAFE → … and the handler's own `request` check).

## Tests (contracts.rs events db-tests + a no-DB validation test)
1. **batch happy** (DB): seed 2-3 alert-worthy events (platform-wide); batch-ack all →
   `succeeded == N`, `failed == 0`; each is acknowledged in `alert_acks`.
2. **partial** (DB): one in-scope event + one OUT-OF-SCOPE event (tagged to a site the
   session can't see); a scoped session batch-acks both → `succeeded == 1`, `failed == 1`;
   the out-of-scope per-item result is `ok:false, status:404` (no oracle); the in-scope one
   is acked, the out-of-scope one is NOT.
3. **cap** (no-DB): `event_ids` of length 101 → 400; empty → 400 (both before the DB).
4. **dedup** (DB): duplicate ids → a single result/ack (idempotent).
5. **note validation** (no-DB): a note with a control char → 400.
6. **single unchanged** (DB): the existing single-ack test still passes (the refactor is
   behavior-preserving).

## Files
- sources/ryuki-api/src/contracts.rs (`ack_alert_one` + refactor `events_alert_ack` +
  `events_alert_batch_ack` + `BatchAlertAckBody` + route + tests). NO migration, NO engine.

## Out of scope
- Bulk SUPPRESS / maintenance-window silencing (a separate feature; this is ack only).
- A `{succeeded, failed, results}` envelope change to the single endpoint (kept as-is).
