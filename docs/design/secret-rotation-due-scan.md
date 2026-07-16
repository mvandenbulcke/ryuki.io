# Scheduled secret-rotation-due scan — durable-scheduler job kind

Status: implemented (plan review required changes; all 3 major and 3 minor findings
were incorporated. See "## Plan-review fixes" at the end; they supersede the original
single-signal arm).
Verify-first swarm 2026-06-29 finding #7.
VERIFIED: `job_is_schedulable` (ryuki-engine/scheduler.rs:104) lists exactly 4 write
kinds (synthetic_health_run, maintain_review_scan, connection_health_sweep,
restore_overdue_scan) + read-only — NO secret-rotation scan. `GET /api/protect/secrets/
due` is on-demand only. Mirrors `restore_overdue_scan` (the closest sibling — enqueues
deduped shift_queue items). Additive: ONE migration (seed schedule + index), engine +
api.

## Goal
Secrets have a `next_rotation_due`, but nothing PROACTIVELY surfaces overdue rotations —
an operator must manually poll `/secrets/due`. Add a daily durable-scheduler job that
enumerates OVERDUE secrets and enqueues ONE deduped shift_queue work item per secret, so
overdue rotations show up in the operator work queue automatically (the proven
#19/#39/#52 SAFE-INTERNAL-WRITE pattern: read internal state, classify with a pure engine
fn, write only our own shift_queue — no provider/live call).

## Engine (ryuki-engine)
1. `scheduler.rs:104` — add `"secret_rotation_due_scan"` to the `job_is_schedulable`
   `matches!` (NOT to `job_is_read_only` — it writes shift_queue).
2. `secrets_rotation.rs` — a PURE classifier mirroring `backup_recency::
   classify_restore_recency`:
   ```rust
   #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
   #[serde(rename_all = "snake_case")]
   pub enum SecretRotationRecency { Current, Overdue }
   impl SecretRotationRecency {
       pub fn as_str(&self) -> &'static str { match self { Current => "current", Overdue => "overdue" } }
       pub fn is_due(&self) -> bool { matches!(self, SecretRotationRecency::Overdue) }
   }
   /// Overdue when now has reached/passed next_due (boundary = Overdue); else Current.
   pub fn classify_secret_rotation_recency(next_due_unix: i64, now_unix: i64) -> SecretRotationRecency {
       if now_unix >= next_due_unix { SecretRotationRecency::Overdue } else { SecretRotationRecency::Current }
   }
   ```
   (No `NeverTested` — `next_rotation_due` is `TEXT NOT NULL`, always set at registration.)

## API run_job arm (ryuki-api/scheduler.rs, run_job match)
`"secret_rotation_due_scan" =>` mirroring `restore_overdue_scan` (scheduler.rs:250):
- Load candidates on `&mut **tx` into a local `#[derive(sqlx::FromRow)]` struct (avoids the
  clippy type_complexity tuple):
  ```sql
  SELECT id, name, next_rotation_due, status, site, owner FROM managed_secrets
   WHERE status NOT IN ('retired', 'rotating') ORDER BY id
  ```
  Selects ONLY non-sensitive columns — NEVER `vault_path` (a Vault pointer) or
  `secret_type`. `retired` excluded (decommissioned); `rotating` excluded (a rotation is
  in flight — its stale past `next_rotation_due` would be a spurious duplicate). `expired`
  / `failed` are KEPT — they are overdue and need attention.
- Dueness in RUST, not SQL (implementation note): for each row, `chrono::DateTime::
  parse_from_rfc3339(&row.next_rotation_due)` — on `Err`, **SUPERSEDED by MAJOR 1
  below**: instead of silently skipping, enqueue a SECOND `secret-rotation-invalid-due`
  signal (the tick still never `?`-aborts on a bad row). Skip blank `id` too. On `Ok`,
  `classify_secret_rotation_recency(next_due_ms, now_ms)` (MILLIS — MINOR 3); if
  `is_due()`, enqueue the overdue item. (This avoids the `next_rotation_due::timestamptz`
  cast the on-demand handler uses, which would throw and abort the tick on a malformed value.)
- `enqueue_if_absent(&mut **tx, SECRET_ROTATION_DUE_ITEM_TYPE, &row.id, &title,
  &description, "P2", &metadata)` where:
  - dedup key (the `source_ci_key` arg) = `row.id` (stable, non-sensitive secret identity),
  - title = `format!("Secret rotation overdue: {}", row.name)`,
  - description = a human line with site/owner/due-date,
  - metadata JSON = `{ "source_ci_key": row.id, "name", "site", "owner",
    "next_rotation_due", "reason": "overdue" }` — NEVER `vault_path`/`secret_type`.
- Return `("succeeded", ...)` with an AGGREGATE-ONLY detail (privacy review finding; surfaced via
  /api/ops/scheduler/executions — never per-secret data). SHIPPED format is the TWO-count
  `"enqueued {overdue} overdue, {invalid} invalid secret rotation item(s)"` (MAJOR 1),
  not the single-count sketch.

## shift_queue item type (ryuki-api/repos/shift_queue.rs)
`pub const SECRET_ROTATION_DUE_ITEM_TYPE: &str = "secret-rotation-due";` PLUS (per
MAJOR 1) `pub const SECRET_ROTATION_INVALID_ITEM_TYPE: &str = "secret-rotation-invalid-due";`

## Migration 125 (migrations/125_secret_rotation_due_scan.sql)
Mirror 122. Latest migration is 124 → 125 is next. NOTE (MAJOR 1): the SHIPPED
migration has TWO partial unique indexes — the overdue one below AND a
`uq_shift_queue_open_secret_rotation_invalid` for the `secret-rotation-invalid-due` signal
(see the migration file). The single-index block below is the original sketch.
```sql
INSERT INTO schedules (id, name, job_kind, interval_secs, enabled, next_run_at, created_by)
VALUES ('66666666-6666-4666-8666-666666666666', 'Secret rotation due scan (all secrets)',
        'secret_rotation_due_scan', 86400, TRUE, NOW(), 'system')
ON CONFLICT (id) DO NOTHING;

CREATE UNIQUE INDEX IF NOT EXISTS uq_shift_queue_open_secret_rotation_due
    ON shift_queue (item_type, (metadata->>'source_ci_key'))
    WHERE resolved = false AND item_type = 'secret-rotation-due';
```

## Tests
PURE (ryuki-engine secrets_rotation.rs): `classify_secret_rotation_recency` —
now<due→Current, now==due→Overdue (boundary), now>due→Overdue; `is_due()`/`as_str()`.
PURE (ryuki-engine scheduler.rs): `job_is_schedulable("secret_rotation_due_scan")` is true
AND `!job_is_read_only("secret_rotation_due_scan")`.
DB (ryuki-api scheduler.rs tests, single-threaded, mirror `restore_scan_enqueues_overdue_
then_dedups`): seed 4 managed_secrets — (a) OVERDUE active, (b) FUTURE active, (c) OVERDUE
retired, (d) OVERDUE rotating — with fresh-UUID ids; disable the migration-125 schedule;
seed a due `secret_rotation_due_scan` schedule; `tick_once`. Assert: (a) enqueued exactly
once (per-id assertion, not a global count — other DB secrets may also be overdue), with
item_type/title/priority/metadata.source_ci_key/reason correct AND metadata has NO
`vault_path` key; (b)/(c)/(d) NOT enqueued (per-id absent); a 2nd tick does NOT duplicate
(a); the `job_executions.detail` matches the aggregate format `enqueued <N> overdue secret
rotation(s)` (assert the FORMAT, not the value — global overdue count is environment-
dependent). Cleanup the planted secrets + schedules; re-seed the migration schedule
(disabled), mirroring `restore_migration_restore_scan`.

## Files
- sources/ryuki-engine/src/scheduler.rs (allowlist), secrets_rotation.rs (classifier + tests)
- sources/ryuki-api/src/scheduler.rs (run_job arm + DB tests), repos/shift_queue.rs (const)
- migrations/125_secret_rotation_due_scan.sql

## Out of scope (follow-ups)
- "Due soon" (within N days) heads-up items (this slice enqueues only OVERDUE, matching
  the on-demand /secrets/due semantics).
- Auto-initiating rotation (this is enumeration → work queue only, no live call).
- A portal view of the secret-rotation queue.
- A dedicated "stuck rotation" detector for secrets parked in `rotating` (we EXCLUDE
  `rotating` here to avoid duplicate noise; surfacing a stuck rotation is a separate job).

## Plan-review fixes (SUPERSEDE the above where they conflict)
- **MAJOR 1 — surface malformed dates (no silent blind spot).** The arm is now TWO-signal
  (like `restore_overdue_scan`'s overdue+failed): on `parse_from_rfc3339` Err, instead of
  silently skipping, enqueue a SECOND deduped item `secret-rotation-invalid-due` (const
  `SECRET_ROTATION_INVALID_ITEM_TYPE`), dedup key = secret id, metadata
  `{source_ci_key, name, site, owner, invalid_next_rotation_due, reason:"invalid-due-date"}`
  (the bad value is a date string, not secret — useful for the operator to fix). The tick
  still does NOT abort (the parse Err routes to this signal, never `?`). Detail becomes two
  counts: `enqueued {overdue} overdue, {invalid} invalid secret rotation item(s)`. Migration
  125 gets a SECOND partial unique index for this item_type.
- **MAJOR 2 — dedup test must force the schedule due again.** `tick_once` advances
  `next_run_at`, so a naive 2nd tick would no-op and the dedup test would false-pass.
  Re-seed a due `secret_rotation_due_scan` schedule before the 2nd tick (mirror the restore
  test's `sched_id2`), THEN assert still exactly one open item per secret id.
- **MAJOR 3 — engine module export.** No new module: the classifier is ADDED to the
  EXISTING, already-exported `ryuki_engine::secrets_rotation` (lib.rs:78 `pub mod
  secrets_rotation;`), so the API arm can call it. Confirmed.
- **MINOR 1 — status coverage.** Keep `expired` + `failed` (overdue, need attention →
  enqueued). The DB test now seeds overdue `expired` and `failed` secrets too and asserts
  they ARE enqueued (alongside `active`), and `retired`/`rotating`/future are NOT.
- **MINOR 2 — honest count.** `enqueue_if_absent` returns the insert count (1 inserted / 0
  deduped); the arm SUMS those returns, so "enqueued N" reflects ACTUAL inserts (verified:
  the restore arm does `enqueued += enqueue_if_absent(...)`).
- **MINOR 3 — millis comparison.** `classify_secret_rotation_recency(next_due_ms, now_ms)`
  takes epoch MILLIS (via `DateTime::timestamp_millis()`), so a fractional-second
  `next_rotation_due` isn't marked overdue up to ~1s early. Pure; unit-tested at the
  boundary (now==due → Overdue).
