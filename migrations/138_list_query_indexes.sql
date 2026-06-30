-- 138_list_query_indexes.sql — supporting indexes for three list queries that
-- previously scanned a growing table (run-7/8 schema-integrity finding).
--
-- Each index below matches an EXISTING query's filter + ORDER BY exactly (the SQL
-- is unchanged; this migration only adds indexes). All are additive and guarded
-- with IF NOT EXISTS so re-application is a no-op. Built in-transaction (NOT
-- CONCURRENTLY) per the repo's migration convention — these tables are not yet at
-- a scale that requires a concurrent build, and a concurrent build cannot run
-- inside the migration transaction. GPT-5 Codex reviewed the index design.
--
-- DEPLOY NOTE: a plain (non-CONCURRENT) CREATE INDEX takes a SHARE lock that lets
-- concurrent SELECTs proceed but BLOCKS writes (INSERT/UPDATE/DELETE) on each table
-- until this migration's transaction commits. At the current table sizes the builds
-- are fast; once these tables grow large, run this migration in a maintenance window
-- (or split each index into its own CONCURRENTLY build outside a transaction).

-- ── requests: the scoped-principal list (the hottest authenticated read path) ──
-- requests_list filters `($2 IS NULL OR site=$2) AND ($3 IS NULL OR environment=$3)
-- ...` and defaults to `ORDER BY created_at DESC`. A SCOPED principal ALWAYS has
-- its site (+ environment) injected by enforce_scope_filters, so its list and its
-- per-page `COUNT(*)` both currently full-scan `requests` (the core operational
-- table — archived, never pruned). This composite lets a scoped list seek to one
-- site/environment range and emit rows already in created_at-DESC order (no sort),
-- and turns its COUNT into a selective index range scan. (A site-only principal
-- still benefits from the leading `site` column.)
-- NOTE: the `($n IS NULL OR col=$n)` predicate shape can fall back to a seq scan
-- under a generic prepared plan; the common scoped path passes concrete values, so
-- a custom plan uses this index. The deeper fix (dynamic SQL with only the active
-- predicates) is a separate, larger change tracked as a follow-up. A status-only
-- index was deliberately deferred (status changes on every lifecycle transition =
-- write amplification; ship the scoped index first and measure — codex).
CREATE INDEX IF NOT EXISTS idx_requests_site_env_created_at
    ON requests (site, environment, created_at DESC);

-- ── domain_events: the alert feed ──────────────────────────────────────────────
-- The alert feed query is `WHERE payload->>'to_status' = ANY($1) ... ORDER BY
-- occurred_at DESC, id DESC LIMIT $5`. alert_worthy_statuses() is a SMALL minority
-- of all events, and domain_events is append-only with no prune (unbounded), so the
-- planner otherwise scans occurred_at DESC applying the JSONB filter row-by-row
-- until it collects N alerts — most of the table in steady state. This PARTIAL
-- EXPRESSION index keeps it small (only rows with a to_status key) and lets the
-- planner BITMAP-scan ONLY the alert-worthy rows (a small minority) for the
-- `= ANY($1)` filter, then sort that small matched set for `occurred_at DESC, id
-- DESC LIMIT` — instead of scanning the whole table. (A multi-value `= ANY` cannot
-- be an ordered btree scan, so a small sort of the matched rows remains; the win is
-- not reading the non-alert majority.) Verified with EXPLAIN: bitmap index scan on
-- this index. The trailing occurred_at/id columns also give an ordered scan for the
-- single-value case. The predicate is a concrete bound array (NOT the OR-NULL shape).
CREATE INDEX IF NOT EXISTS idx_domain_events_to_status_occurred_id
    ON domain_events ((payload->>'to_status'), occurred_at DESC, id DESC)
    WHERE payload->>'to_status' IS NOT NULL;

-- ── agent_jobs: the dead-lettered admin list ───────────────────────────────────
-- The admin dead-letter list is `WHERE status='DeadLettered' ORDER BY updated_at
-- DESC LIMIT 500`. None of the existing agent_jobs indexes leads with status alone
-- + updated_at. DeadLettered is rare (delivery-attempt threshold), so a tiny PARTIAL
-- index on just those rows supports the filter + sort at negligible size and write
-- cost. The `status='DeadLettered'` predicate is a literal (NOT OR-NULL), so the
-- planner uses it directly.
CREATE INDEX IF NOT EXISTS idx_agent_jobs_dead_lettered_updated_at
    ON agent_jobs (updated_at DESC)
    WHERE status = 'DeadLettered';
