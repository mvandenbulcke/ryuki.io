# Shift-queue authority rollout

Migration 170 replaces metadata-only queue deduplication with an immutable,
typed authority tuple. Resource work is identified by `item_type`,
`source_ci_key`, `site`, and nullable `environment`; explicit fleet-global work
uses `item_type` and `source_ci_key`. Quarantined rows are outside both
uniqueness domains.

## Required rollout order

1. Stop every pre-170 API and scheduler replica, then wait for all of their
   database sessions and transactions to drain. Do not rely on the migration
   lock as permission to leave an old reader or writer serving.
2. Apply migration 170 while no API or scheduler replica is running, before
   deploying the authority-aware binary.
3. Let the migration acquire its `ACCESS EXCLUSIVE` lock. Do not bypass the
   lock or create indexes separately: it fences old writers while all legacy
   metadata-expression indexes are dropped and both typed indexes are created.
4. Deploy only the API binary whose scheduler passes `ShiftQueueAuthority` from
   typed source columns.
5. Confirm the legacy index names are absent, the two typed indexes are valid,
   and new resource rows carry `scheduler-resource-v1` provenance.
6. Review `shift_queue_scope_reconciliation_reviews`; do not bulk-promote its
   candidates from metadata.

The defaults and capture trigger quarantine a stale writer that slips through
the operational drain, but they are a last-resort data fence rather than a
rolling-compatibility contract. Never start or leave an old binary against the
post-170 schema: old readers do not understand the typed uniqueness and
authority semantics. A new binary started before the schema exists fails
closed on missing columns; it must not retry through the old metadata writer.

## Reconciliation

For one quarantined row, a reviewer verifies the source relation outside the
queue metadata, then sets the complete approved visibility/source/site/
environment tuple together with reviewer identity, rationale, and timestamp in
`shift_queue_scope_reconciliation_reviews`. A matching update of the queue row
to `reviewed-reconciliation-v1` consumes that review atomically.

If the approved tuple already has an open item, the typed unique index rejects
the promotion and the transaction leaves `applied_at` unset. Resolve the
duplicate through normal queue lifecycle review; never delete, rename, or
weaken the authority index to force promotion.

## Rollback boundary

Do not downgrade only the schema or only the binary. Stop every authority-aware
replica, drain its database sessions, and restore the approved pre-170 database
and its matching old binary as one coupled unit. Validate that the restored
database contains no post-cutover work before starting the old generation.
Running an old binary against the typed schema, or restoring a metadata-only
unique index into the new data generation, would reintroduce cross-scope
suppression and is not an acceptable rollback.
