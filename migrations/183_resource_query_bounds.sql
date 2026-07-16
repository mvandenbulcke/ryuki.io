-- 183_resource_query_bounds.sql — exact access paths for bounded status reads.
--
-- C234/C235 select no more than 101 enabled definitions in a stable
-- `(created_at,id)` order. Scoped callers execute a finite set of per-scope
-- LATERAL probes, so each probe needs the scope tuple before the same order and
-- unique tie-break. Metric work then walks a single coherent series newest
-- first and stops at a fixed LIMIT; `id` is required to make equal timestamps
-- deterministic and `value` is included so the bounded aggregate need not read
-- unrelated heap rows.
--
-- The original schemas accepted unbounded TEXT even though every canonical API
-- writer caps these identities at 200 bytes. PostgreSQL counts both btree keys
-- and INCLUDE payloads toward its per-index-tuple limit, so one oversized legacy
-- row could otherwise abort index creation with an opaque tuple-size error. Add
-- the future-write checks first as NOT VALID, report exact legacy violation
-- counts, then validate before any index DDL. SQLx applies the file in one
-- transaction: a failed preflight rolls back every constraint addition and no
-- partial index cutover remains. Operators must review and explicitly normalize,
-- delete, or move violating rows to an approved quarantine before rerunning;
-- this migration never truncates or hash-rewrites authority identifiers.

ALTER TABLE metric_samples
    ADD CONSTRAINT metric_samples_status_identity_bounds
    CHECK (
        octet_length(id) BETWEEN 1 AND 200
        AND octet_length(metric_key) BETWEEN 1 AND 200
        AND (site IS NULL OR octet_length(site) BETWEEN 1 AND 200)
        AND (environment IS NULL OR octet_length(environment) BETWEEN 1 AND 200)
    ) NOT VALID;

ALTER TABLE metric_budgets
    ADD CONSTRAINT metric_budgets_status_identity_bounds
    CHECK (
        octet_length(id) BETWEEN 1 AND 200
        AND octet_length(metric_key) BETWEEN 1 AND 200
        AND (site IS NULL OR octet_length(site) BETWEEN 1 AND 200)
        AND (environment IS NULL OR octet_length(environment) BETWEEN 1 AND 200)
    ) NOT VALID;

ALTER TABLE slo_definitions
    ADD CONSTRAINT slo_definitions_status_identity_bounds
    CHECK (
        octet_length(id) BETWEEN 1 AND 200
        AND octet_length(name) BETWEEN 1 AND 200
        AND octet_length(good_metric_key) BETWEEN 1 AND 200
        AND octet_length(total_metric_key) BETWEEN 1 AND 200
        AND (site IS NULL OR octet_length(site) BETWEEN 1 AND 200)
        AND (environment IS NULL OR octet_length(environment) BETWEEN 1 AND 200)
    ) NOT VALID;

DO $$
DECLARE
    invalid_samples BIGINT;
    invalid_budgets BIGINT;
    invalid_slos BIGINT;
BEGIN
    SELECT COUNT(*) INTO invalid_samples
    FROM metric_samples
    WHERE NOT (
        octet_length(id) BETWEEN 1 AND 200
        AND octet_length(metric_key) BETWEEN 1 AND 200
        AND (site IS NULL OR octet_length(site) BETWEEN 1 AND 200)
        AND (environment IS NULL OR octet_length(environment) BETWEEN 1 AND 200)
    );

    SELECT COUNT(*) INTO invalid_budgets
    FROM metric_budgets
    WHERE NOT (
        octet_length(id) BETWEEN 1 AND 200
        AND octet_length(metric_key) BETWEEN 1 AND 200
        AND (site IS NULL OR octet_length(site) BETWEEN 1 AND 200)
        AND (environment IS NULL OR octet_length(environment) BETWEEN 1 AND 200)
    );

    SELECT COUNT(*) INTO invalid_slos
    FROM slo_definitions
    WHERE NOT (
        octet_length(id) BETWEEN 1 AND 200
        AND octet_length(name) BETWEEN 1 AND 200
        AND octet_length(good_metric_key) BETWEEN 1 AND 200
        AND octet_length(total_metric_key) BETWEEN 1 AND 200
        AND (site IS NULL OR octet_length(site) BETWEEN 1 AND 200)
        AND (environment IS NULL OR octet_length(environment) BETWEEN 1 AND 200)
    );

    IF invalid_samples > 0 OR invalid_budgets > 0 OR invalid_slos > 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'check_violation',
            MESSAGE = format(
                'migration 183 resource-bound preflight failed: metric_samples=%s, metric_budgets=%s, slo_definitions=%s out-of-bounds row(s)',
                invalid_samples,
                invalid_budgets,
                invalid_slos
            ),
            HINT = 'Review and explicitly normalize, delete, or quarantine every violating row, then rerun migration 183; identifiers are never truncated automatically.';
    END IF;
END;
$$;

ALTER TABLE metric_samples
    VALIDATE CONSTRAINT metric_samples_status_identity_bounds;
ALTER TABLE metric_budgets
    VALIDATE CONSTRAINT metric_budgets_status_identity_bounds;
ALTER TABLE slo_definitions
    VALIDATE CONSTRAINT slo_definitions_status_identity_bounds;

CREATE INDEX idx_metric_samples_status_series
    ON metric_samples (
        metric_key,
        (site IS NOT NULL),
        (COALESCE(site, '')),
        (environment IS NOT NULL),
        (COALESCE(environment, '')),
        observed_at DESC,
        id DESC
    )
    INCLUDE (value);

CREATE INDEX idx_metric_budgets_status_global
    ON metric_budgets (created_at DESC, id DESC)
    WHERE enabled;

CREATE INDEX idx_metric_budgets_status_site
    ON metric_budgets (
        (site IS NOT NULL),
        (COALESCE(site, '')),
        created_at DESC,
        id DESC
    )
    WHERE enabled;

CREATE INDEX idx_metric_budgets_status_environment
    ON metric_budgets (
        (environment IS NOT NULL),
        (COALESCE(environment, '')),
        created_at DESC,
        id DESC
    )
    WHERE enabled;

CREATE INDEX idx_metric_budgets_status_site_environment
    ON metric_budgets (
        (site IS NOT NULL),
        (COALESCE(site, '')),
        (environment IS NOT NULL),
        (COALESCE(environment, '')),
        created_at DESC,
        id DESC
    )
    WHERE enabled;

CREATE INDEX idx_slo_definitions_status_global
    ON slo_definitions (created_at DESC, id DESC)
    WHERE enabled;

CREATE INDEX idx_slo_definitions_status_site
    ON slo_definitions (
        (site IS NOT NULL),
        (COALESCE(site, '')),
        created_at DESC,
        id DESC
    )
    WHERE enabled;

CREATE INDEX idx_slo_definitions_status_environment
    ON slo_definitions (
        (environment IS NOT NULL),
        (COALESCE(environment, '')),
        created_at DESC,
        id DESC
    )
    WHERE enabled;

CREATE INDEX idx_slo_definitions_status_site_environment
    ON slo_definitions (
        (site IS NOT NULL),
        (COALESCE(site, '')),
        (environment IS NOT NULL),
        (COALESCE(environment, '')),
        created_at DESC,
        id DESC
    )
    WHERE enabled;
