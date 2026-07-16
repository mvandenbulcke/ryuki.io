\set ON_ERROR_STOP on

-- This regression is read-only with respect to application tables. The large
-- fixture, its indexes, helper functions, and plan receipts are all temporary;
-- ROLLBACK also makes the no-persistence guarantee explicit.
BEGIN;

DO $migration_contract$
DECLARE
    global_oid REGCLASS := to_regclass('public.idx_requests_metering_created_at_id');
    scoped_oid REGCLASS := to_regclass('public.idx_requests_metering_site_created_at_id');
    global_definition TEXT;
    scoped_definition TEXT;
    global_ready BOOLEAN;
    scoped_ready BOOLEAN;
BEGIN
    IF global_oid IS NULL THEN
        RAISE EXCEPTION 'migration 191 global metering index is missing';
    END IF;
    IF scoped_oid IS NULL THEN
        RAISE EXCEPTION 'migration 191 site-scoped metering index is missing';
    END IF;

    SELECT pg_get_indexdef(global_oid), index.indisvalid AND index.indisready
    INTO global_definition, global_ready
    FROM pg_index AS index
    WHERE index.indexrelid = global_oid;

    SELECT pg_get_indexdef(scoped_oid), index.indisvalid AND index.indisready
    INTO scoped_definition, scoped_ready
    FROM pg_index AS index
    WHERE index.indexrelid = scoped_oid;

    IF NOT global_ready THEN
        RAISE EXCEPTION 'migration 191 global metering index is not ready and valid';
    END IF;
    IF NOT scoped_ready THEN
        RAISE EXCEPTION 'migration 191 site-scoped metering index is not ready and valid';
    END IF;
    IF global_definition !~ 'USING btree \(created_at DESC, id DESC\)$' THEN
        RAISE EXCEPTION 'unexpected global metering index definition: %', global_definition;
    END IF;
    IF scoped_definition !~ 'USING btree \(site, created_at DESC, id DESC\)$' THEN
        RAISE EXCEPTION 'unexpected site-scoped metering index definition: %', scoped_definition;
    END IF;
END
$migration_contract$;

CREATE TEMPORARY TABLE metering_usage_plan_probe (
    id UUID PRIMARY KEY,
    site TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
) ON COMMIT DROP;

-- Mirror the migration's exact access paths on an isolated relation. The
-- catalog assertions above tie these probe definitions to the installed DDL;
-- this avoids modifying or ANALYZE-ing application data just to prove a plan.
CREATE INDEX metering_usage_plan_probe_global_idx
    ON metering_usage_plan_probe (created_at DESC, id DESC);
CREATE INDEX metering_usage_plan_probe_scoped_idx
    ON metering_usage_plan_probe (site, created_at DESC, id DESC);

-- Adversarial distribution: 380,000 retained rows sit outside the admitted
-- 90-day window, while 20,000 recent rows share only 86,400 timestamp values
-- across 64 sites and 17 statuses. This exercises range selectivity, timestamp
-- ties, grouping cardinality, and a selective site prefix in one fixture.
INSERT INTO metering_usage_plan_probe (id, site, status, created_at)
SELECT
    md5(series::TEXT)::UUID,
    'SITE-' || lpad((series % 64)::TEXT, 3, '0'),
    (ARRAY[
        'draft', 'intake', 'validated', 'planned', 'approved', 'locked',
        'executing', 'executed', 'verifying', 'verified', 'completed',
        'protecting', 'operational', 'retired', 'failed', 'rejected',
        'cancelled'
    ])[1 + (series % 17)],
    CASE
        WHEN series <= 380000
            THEN CURRENT_TIMESTAMP - INTERVAL '365 days'
                 - make_interval(secs => series % 86400)
        ELSE CURRENT_TIMESTAMP - make_interval(secs => series % 86400)
    END
FROM generate_series(1, 400000) AS fixture(series);

ANALYZE metering_usage_plan_probe;

CREATE OR REPLACE FUNCTION pg_temp.explain_analyze_json(statement TEXT)
RETURNS JSONB
LANGUAGE plpgsql
AS $function$
DECLARE
    plan JSON;
BEGIN
    EXECUTE 'EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ' || statement INTO plan;
    RETURN plan::JSONB;
END
$function$;

CREATE OR REPLACE FUNCTION pg_temp.plan_uses_index(plan JSONB, expected_index TEXT)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
AS $function$
    WITH RECURSIVE plan_nodes(node) AS (
        SELECT plan -> 0 -> 'Plan'
        UNION ALL
        SELECT child.value
        FROM plan_nodes AS parent
        CROSS JOIN LATERAL jsonb_array_elements(
            COALESCE(parent.node -> 'Plans', '[]'::JSONB)
        ) AS child(value)
    )
    SELECT COALESCE(bool_or(node ->> 'Index Name' = expected_index), FALSE)
    FROM plan_nodes
$function$;

CREATE TEMPORARY TABLE metering_usage_plan_receipts (
    query_shape TEXT PRIMARY KEY,
    expected_index TEXT NOT NULL,
    plan JSONB NOT NULL
) ON COMMIT DROP;

-- Match the application transaction-local budget exactly. EXPLAIN ANALYZE
-- executes each real aggregate, so a timeout aborts the regression instead of
-- merely estimating that it would finish.
SET LOCAL statement_timeout = '2s';

INSERT INTO metering_usage_plan_receipts (query_shape, expected_index, plan)
VALUES (
    'global',
    'metering_usage_plan_probe_global_idx',
    pg_temp.explain_analyze_json(
        $query$
        SELECT site, status, COUNT(*)
        FROM metering_usage_plan_probe
        WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '90 days'
          AND created_at <= CURRENT_TIMESTAMP
        GROUP BY site, status
        $query$
    )
), (
    'site-scoped',
    'metering_usage_plan_probe_scoped_idx',
    pg_temp.explain_analyze_json(
        $query$
        SELECT site, status, COUNT(*)
        FROM metering_usage_plan_probe
        WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '90 days'
          AND created_at <= CURRENT_TIMESTAMP
          AND site = 'SITE-000'
        GROUP BY site, status
        $query$
    )
);

DO $plan_contract$
DECLARE
    receipt RECORD;
BEGIN
    IF current_setting('statement_timeout')::INTERVAL <> INTERVAL '2 seconds' THEN
        RAISE EXCEPTION 'metering regression did not run under the 2-second local statement budget';
    END IF;

    FOR receipt IN SELECT * FROM metering_usage_plan_receipts LOOP
        IF NOT pg_temp.plan_uses_index(receipt.plan, receipt.expected_index) THEN
            RAISE EXCEPTION
                'metering % aggregate did not use expected index %; plan=%',
                receipt.query_shape,
                receipt.expected_index,
                receipt.plan;
        END IF;
        IF (receipt.plan -> 0 ->> 'Execution Time')::NUMERIC >= 2000 THEN
            RAISE EXCEPTION
                'metering % aggregate exceeded its 2-second budget; plan=%',
                receipt.query_shape,
                receipt.plan;
        END IF;
    END LOOP;
END
$plan_contract$;

SELECT
    query_shape,
    expected_index,
    round((plan -> 0 ->> 'Execution Time')::NUMERIC, 3) AS execution_time_ms
FROM metering_usage_plan_receipts
ORDER BY query_shape;

ROLLBACK;
