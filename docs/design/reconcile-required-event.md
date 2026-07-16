# Emit a domain event when a LiveApply lease expires → ReconcileRequired

Status: SHIPPED (run-3 discovery swarm, CONFIRMED H/S). Review approved the event emission, then
approved it again after a MINOR expansion made `reconcile-required` genuinely
alert-worthy (Critical) — closing the risk-profile asymmetry where the costliest mode alerted
weaker than dead-letter. Additive, NO migration, NO schema change.

## The gap (verified)
`expire_leases` (agents.rs:1500) has three branches on lease expiry:
1. dead-letter at-cap non-mutating jobs → `RETURNING …` + emits one `job.dead_lettered` domain
   event per row (agents.rs:1520-1541) — alert-worthy operator visibility.
2. redispatch under-cap non-mutating jobs (no event — they retry).
3. **LiveApply → `ReconcileRequired`** (agents.rs:1569): updates ONLY `agent_jobs` via
   `.execute()` (rows_affected only) — emits NO domain event.

So a LiveApply job whose agent dies mid-run (the HIGHEST-risk mode — it touched real infra) is
moved to the operator-recovery state `ReconcileRequired` SILENTLY: nothing appears in the durable
event feed, unlike the less-risky dead-letter path. The costliest failure is the quietest.

## Fix — mirror the dead-letter event block (parity)
Change branch 3 to `RETURNING id::text, request_id::text, platform`, then emit one
`job.reconcile_required` domain event per row in the SAME transaction, copying the dead-letter
emission block:
```
let reconciled: Vec<ReconcileRequiredJobRow> = UPDATE … RETURNING id::text, request_id::text, platform;
for job in &reconciled {
    domain_events::insert(&mut *tx, NewEvent {
        event_type: "job.reconcile_required",
        aggregate_type: "agent_job", aggregate_id: &job.id,
        site: None, environment: None, actor: "system",
        payload: { to_status: "reconcile-required", platform, mode: "LiveApply", request_id,
                   note: "live-apply lease expired mid-run; operator reconciliation required" },
    }).await?;
}
let reconcile = reconciled.len() as u64;
```
- NO migration: `domain_events.event_type` is free TEXT (no CHECK); `job.dead_lettered` was added
  the same way.
- ALERT-WORTHY PARITY: the alert classifier `severity_for_agent_job_status`
  (ryuki-engine event_alerts.rs:83) is extended so `to_status = "reconcile-required"` ⇒ `Critical`
  (and `alert_worthy_statuses()` gains it, kept in lock-step by the existing union test). Without
  this, only `dead-lettered` surfaced in the alert feed as Critical — so the LESS-risky dead-letter
  path showed up while the COSTLIEST mode (a LiveApply lease expiry leaving real infra in an unknown
  state) was an unclassified feed entry. Now the reconcile event appears in the alert feed
  (`GET /api/events/alerts`, contracts.rs:18873) as Critical via the SAME downstream
  `domain_events` → `alert_worthy_statuses()` SQL prefilter + `classify` path the dead-letter event
  uses — no extra emit in `expire_leases`. (EXACT parity with dead-letter: like dead-letter, it does
  NOT auto-insert a `portal_notification` — those are explicit emitter-side
  `draft_for_alert`/`insert_draft_tx` inserts, a separate concern for both.)
- Secret hygiene: payload is platform / request_id / mode / a static note — no secrets (same shape
  as the dead-letter payload).
- `ReconcileRequiredJobRow { id, request_id, platform }` — `mode` is constant `LiveApply`, and
  reconcile never touches `delivery_attempts` (so the dead-letter struct's extra columns are omitted).

## Test
- Update `db_live_apply_never_dead_lettered` (agents.rs:3953): it already asserts status
  `ReconcileRequired`, attempts untouched, and `dead_letter_event_count == 0` (still true — reconcile
  emits NO dead-letter event). ADD `reconcile_required_event_count(pool, job_id) == 1` (a helper
  mirroring `dead_letter_event_count` with `event_type = 'job.reconcile_required'`) + update the doc
  comment ("no event" → "a reconcile_required event, never a dead-letter event"). NOTE:
  `cleanup_dead_letter_events` is a best-effort no-op — `domain_events` is append-only (mig 111
  blocks DELETE; the call `.ok()`-swallows the error). Test isolation comes from the per-test UNIQUE
  job id (the count helpers filter by `aggregate_id`), NOT from deletion.
- Engine: add a `severity_for_agent_job_status("reconcile-required") == Critical` assertion to the
  existing classifier test; the union lock-step test passes automatically once `reconcile-required`
  is in both the classifier and `alert_worthy_statuses()`.

## Out of scope (the companion run-3 gaps)
- `POST /api/admin/agents/jobs/{id}/reconcile` (CAS `ReconcileRequired`→`Failed`, audited) — the
  operator RESOLUTION endpoint; its own change.
- Auto-failing / surfacing the stranded parent request (it stays `Executing`) — a follow-up.
