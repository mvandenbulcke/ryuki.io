# #39 — Maintain lifecycle stage (recurring operational review)

Status: design (codex NEEDS-CHANGES round 1 → fixes folded in below). Reuses the
#40 durable-scheduler SAFE-INTERNAL-WRITE pattern (715f126).

## Goal
The lifecycle is Intake→…→Completed→Protecting→Operational→Retired. `Operational`
is a long-lived resting state (publish_request lands there; retire_request leaves
it). There is no recurring review of Operational requests. Add a scheduled
`maintain_review_scan` that periodically flags Operational requests due for review
by recording a domain event, so operators have a maintenance feedback loop.

## Design (codex fixes folded in)
1. **Migration 119**: `ALTER TABLE requests ADD COLUMN next_maintain_review_at
   TIMESTAMPTZ` (nullable, DEFAULT NULL); a partial index on
   `(next_maintain_review_at)` where status='operational' (or a plain index);
   seed one enabled scheduler row `job_kind='maintain_review_scan'`, daily
   (interval 86400), fixed id, ON CONFLICT DO NOTHING. Idempotent guarded DDL.
   NULL = **enrolled, initial review due** (a newly-Operational request gets one
   initial review-due event on the next scan, then every REVIEW_INTERVAL). No
   backfill, and NO change to requests_publish (avoids blast radius) — documented
   NULL semantics per codex.

2. **Engine** `scheduler.rs`: add `"maintain_review_scan"` to `job_is_schedulable`
   (explicit allowlist; safe-internal write — records domain events + advances a
   timestamp, NO provider/live call). Unit test: schedulable but NOT read_only.

3. **API** `scheduler.rs` `run_job` new arm `"maintain_review_scan"`, ALL on the
   tick tx — ATOMIC claim+advance to race a concurrent retire safely (codex fix):
   ```sql
   UPDATE requests SET next_maintain_review_at = NOW() + INTERVAL '90 days',
                       updated_at = NOW()
   WHERE id IN (
       SELECT id FROM requests
       WHERE status = 'operational'
         AND (next_maintain_review_at IS NULL OR next_maintain_review_at <= NOW())
       ORDER BY next_maintain_review_at NULLS FIRST, id
       LIMIT 100
       FOR UPDATE SKIP LOCKED
   )
   RETURNING id::text, site, environment
   ```
   Then for each returned (id, site, environment), insert a domain_event
   `event_type='request.maintain-review-due'`, aggregate_type='request',
   aggregate_id=id, site/environment from the row, actor='system', payload minimal
   (`{"request_id": id, "note": "operational review due"}` — NO sensitive fields,
   NO `to_status`, so it stays a NORMAL /api/events entry, not an alert — codex
   fix #1). Scheduler `detail` aggregate-only: `"queued N maintain review(s)"`.
   The UPDATE...RETURNING claims+advances atomically: a concurrent retire either
   ran first (row no longer 'operational' → not matched) or runs after (sees the
   advanced timestamp); FOR UPDATE SKIP LOCKED + the single-leader tick prevent
   double-emit. Lock order (requests row → domain_events) matches the existing
   apply_transition_audited order — no deadlock.

4. **No DbRequestRow / REQUEST_COLUMNS change** (codex): the scan uses its own
   targeted UPDATE...RETURNING, so the new column is never read through
   DbRequestRow — avoids an unread-private-field and keeps REQUEST_COLUMNS stable.

## Constants
`REVIEW_INTERVAL` = 90 days (the advance), scan cadence daily. Both are sensible
defaults; the interval is a single constant easy to retune.

## Tests (new *_db_tests, serialized, cleanup)
1. A due Operational request (next_maintain_review_at NULL) → after a tick, exactly
   one `request.maintain-review-due` domain_event exists for it AND its
   next_maintain_review_at is advanced ~90d into the future.
2. A not-due Operational request (next_maintain_review_at = NOW()+30d) → no event,
   timestamp unchanged.
3. A non-Operational request (e.g. completed/operational-sibling) is never selected
   (no event).
4. A second immediate tick does NOT re-emit (timestamp now in the future).
5. Engine job_is_schedulable matrix (maintain_review_scan schedulable, not read_only).
6. Migration 119 idempotency (re-run no-op).

## Files
- migrations/119_maintain_review.sql (new)
- sources/ryuki-engine/src/scheduler.rs (job_is_schedulable + test)
- sources/ryuki-api/src/scheduler.rs (run_job arm + tests)
- domain_events repo reused as-is.

## Out of scope (follow-ups)
- A manual "record maintain review" endpoint (resets the timer early).
- Promoting maintain-review-due to an alert-feed item with ack (needs an
  event_alerts classifier + SQL filter — engine change).
- Per-offering/criticality review intervals (the 90d constant suffices for now).
