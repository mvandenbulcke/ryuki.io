# Metric series aggregation — time-bucketed rollups

Status: SHIPPED (plan review NEEDS-CHANGES → 1 MAJOR + 3 MINOR folded in; implementation review
NEEDS-CHANGES → 1 MAJOR + 1 MINOR folded in → impl round-2 APPROVE. Impl MAJOR: the
LIMIT must run NEWEST-first (the window lower-bound is not bucket-aligned, so a span×limit
window can straddle > limit labels) — fixed with an `ORDER BY bucket DESC LIMIT` subquery
re-sorted ASC, proven by a fixed-date `metric_aggregated_limit_keeps_newest_buckets` test.
Impl MINOR: the non-UTC test now uses `SET LOCAL TIME ZONE` in a rolled-back tx so it never
persists on the pooled connection. See "## Plan-review fixes" at the end.)
Verify-first swarm 2026-06-29 finding #10.
VERIFIED: `GET /api/metrics/series` (metrics_series, contracts.rs:19826) returns the most-
recent ≤10k RAW samples (fetch_metric_series_rows: `ORDER BY observed_at DESC LIMIT 10000`)
+ a forecast; there is NO time-bucketed aggregation (no `date_trunc`/`GROUP BY` anywhere in
the metrics handlers). `metric_samples` (mig 096): metric_key, site/environment (nullable),
value DOUBLE PRECISION, observed_at TIMESTAMPTZ. Multi-month trend analysis currently forces
the client to fetch raw points and aggregate by hand. Additive: NO migration, NO engine
change (SQL aggregation), NO change to the existing endpoints.

## Endpoint
`GET /api/metrics/series/aggregated` → `metrics_series_aggregated`, mirroring
`metrics_series`'s gating + scope handling step-for-step:
- `check_permission(&session, "request")` (SAME tier as the raw series endpoint — a metrics
  read) → 403 otherwise.
- `metric_key` required + validated via the shared `metric_key_rejection` allowlist
  (`[A-Za-z0-9._:-]`, 1..=200) → 400.
- `metric_scope_too_long` on site/environment → 400.
- `granularity` required, ALLOWLISTED to a client-friendly set mapped to the Postgres
  `date_trunc` field — `hourly→hour`, `daily→day`, `weekly→week`, `monthly→month`; any
  other value → 400. (Allowlist → a fixed `&'static str` field; NEVER raw client text in
  SQL — and it is BOUND, not interpolated, so it cannot be an injection vector even as
  defense-in-depth.)
- `enforce_scope_filters(&session, site, environment)` → the resolved (f_site, f_env), the
  same #2 scope push the raw series uses (a scoped principal is narrowed to its scope).

## Query (a new fetch fn, SQL aggregation)
```sql
SELECT bucket, min_value, max_value, mean_value, sample_count FROM (
  SELECT date_trunc($4, observed_at, 'UTC') AS bucket,
         MIN(value) AS min_value, MAX(value) AS max_value,
         AVG(value) AS mean_value, COUNT(*) AS sample_count
  FROM metric_samples
  WHERE metric_key = $1
    AND site IS NOT DISTINCT FROM $2
    AND environment IS NOT DISTINCT FROM $3
  GROUP BY bucket
  ORDER BY bucket DESC
  LIMIT $5
) recent
ORDER BY bucket ASC
```
- `date_trunc($4, observed_at, 'UTC')` — the 3-arg form buckets at UTC boundaries
  DETERMINISTICALLY (independent of the DB session timezone; a bare `date_trunc(field, ts)`
  would truncate in the session TZ — a real correctness bug). `$4` is the BOUND, allowlisted
  field.
- `IS NOT DISTINCT FROM` → coherent scope (a specific site/env OR the platform-wide NULL
  rows — never a mix), identical to fetch_metric_series_rows.
- `ORDER BY bucket DESC LIMIT $5` then re-sort ASC → the most-recent N buckets, ascending
  (mirrors the raw fetch's recent-N-then-ascending shape). `limit` default 365, cap 2000.
- A `#[derive(sqlx::FromRow)]` row struct `{ bucket: DateTime<Utc>, min_value: f64,
  max_value: f64, mean_value: f64, sample_count: i64 }`.

## Response (object, mirroring metrics_series's object shape)
```json
{ "metric_key": "...", "granularity": "daily",
  "buckets": [ {"bucket_start": "<rfc3339>", "min": <f64>, "max": <f64>,
                "mean": <f64>, "count": <i64>}, ... ] }
```
(bucket_start via `.to_rfc3339()`, ascending.) Empty samples → `buckets: []`, 200.

## Route
`.route("/api/metrics/series/aggregated", get(metrics_series_aggregated))` — a deeper static
path than `/api/metrics/series`, no matchit collision.

## Why SQL aggregation (not a pure engine bucketer)
The bucketing + min/max/mean/count are standard SQL aggregates; doing them in SQL is the
efficient, natural choice (no loading ≤10k raw points just to fold them), and the DB test
proves the buckets. The codebase's pure-engine philosophy is for COMPLEX domain logic
(forecasting/trend/classification — metric_forecast.rs), not basic GROUP BY aggregates. So
NO engine change.

## Tests (contracts.rs metrics db-tests + no-DB validation)
1. **bucketing** (DB): record samples for a fresh metric_key across 2 UTC days (e.g. 3 on
   day A, 2 on day B, with known values); GET `?granularity=daily` → 2 buckets ASCENDING;
   each bucket's min/max/mean/count matches the seeded values; bucket_start is the UTC day
   boundary.
2. **granularity validation**: `?granularity=fortnightly` → 400; missing granularity → 400.
3. **metric_key validation**: missing → 400; `?metric_key=<bad chars>` → 400.
4. **scope** (DB): record samples under site=GBLON and platform-wide (NULL); a GBLON-scoped
   session reading with no site filter → only the GBLON bucket(s) (coherent, narrowed); an
   out-of-scope (DEFRA-scoped) read → its own (empty) scope, never GBLON's.
5. **empty**: a metric_key with no samples → `buckets: []`, 200.
Use a fresh-UUID metric_key prefix to isolate from shared-DB samples.

## Files
- sources/ryuki-api/src/contracts.rs (MetricAggregatedParams + the granularity allowlist +
  fetch_metric_buckets + metrics_series_aggregated + route + tests). NO migration, NO engine.

## Out of scope
- A pure-engine bucketer (SQL is the right tool here).
- Per-bucket forecasting (the raw /series endpoint already forecasts; aggregation is for
  historical trend, not projection).
- `sum`/percentiles per bucket (min/max/mean/count is the swarm's spec; extensible later).
- A rollup/materialized-aggregate layer — a future optimization for very
  high-cardinality metrics; the window bound below makes the on-read scan bounded enough.
- Explicit `from`/`to` window params — the default bounded lookback covers the "last N
  buckets" use case; an explicit window is a follow-up.

## Plan-review fixes (SUPERSEDE the body where they conflict)
- **MAJOR — bound the scan (no all-history aggregation).** `LIMIT` after `GROUP BY` caps
  returned buckets but NOT rows scanned; on an append-only table with only the series index,
  the original query would aggregate ALL history for a metric/scope on every read. FIX: add a
  TIME-WINDOW lower bound to the WHERE — `observed_at >= $lower` where `$lower = now -
  bucket_span_secs(granularity) * limit` (computed in Rust, bound as a param). The metric_key
  + observed_at index then bounds the scan to the last `limit` buckets' worth of time. So the
  query is:
  ```sql
  SELECT date_trunc($4, observed_at, 'UTC') AS bucket, MIN(value), MAX(value),
         AVG(value), COUNT(*)
  FROM metric_samples
  WHERE metric_key = $1 AND site IS NOT DISTINCT FROM $2 AND environment IS NOT DISTINCT FROM $3
    AND observed_at >= $5            -- the window lower bound (now - span*limit)
  GROUP BY bucket ORDER BY bucket ASC LIMIT $6   -- $6 = limit (safety cap)
  ```
  `bucket_span_secs`: hour=3600, day=86400, week=604800, month=2_678_400 (31d upper bound).
  The window contains ≤ `limit` buckets of that span, so the LIMIT is a redundant safety cap.
- **MINOR — response includes effective scope.** The body carries `site` + `environment`
  (the resolved f_site/f_env), matching `metrics_series`, so scope narrowing is observable.
- **MINOR — `limit` validation.** `limit` is `Option<usize>` (a negative/malformed value
  fails Query deserialization → 400 by axum); the handler clamps it to `1..=2000` (default
  365), so `limit=0` → 1 and an over-large value → 2000. Tested.
- **MINOR — bucket semantics documented.** Buckets are NON-EMPTY only — there is NO gap
  filling (a period with no samples produces no bucket). `weekly` uses PostgreSQL's
  ISO-8601 Monday-start week, truncated at UTC.

## Test additions from review
- A **non-UTC DB-session** test: on a connection with `SET TIME ZONE` to a non-UTC zone,
  bucket a sample whose UTC calendar day differs from its local day, and assert the bucket
  start is the UTC day — proving the 3-arg `date_trunc(field, ts, 'UTC')` ignores the
  session timezone (a bare 2-arg form would bucket in the session TZ).
- An explicit **out-of-scope 403** (a scoped principal naming a site outside its scope), in
  addition to the narrowed-empty-scope read.
- `limit` validation (0 → clamped to 1; an over-large value → clamped to 2000).
- Seed `observed_at` at fixed MID-DAY UTC instants (not near midnight) to avoid wall-clock
  bucket-edge flakiness.
