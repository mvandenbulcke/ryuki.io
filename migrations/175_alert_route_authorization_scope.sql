-- 175_alert_route_authorization_scope.sql
--
-- Alert routes are site-and-environment resources.  The original table had no
-- ownership axes, so assigning existing rows a scope would be a guess.  Keep
-- those rows quarantined until an administrator deliberately recreates them
-- through the scoped API; only rows created with verified dual-axis provenance
-- are eligible for reads, resolution, or mutation.

ALTER TABLE alert_routes
    ADD COLUMN IF NOT EXISTS site TEXT,
    ADD COLUMN IF NOT EXISTS environment TEXT,
    ADD COLUMN IF NOT EXISTS scope_classification TEXT NOT NULL
        DEFAULT 'legacy_unclassified';

ALTER TABLE alert_routes
    DROP CONSTRAINT IF EXISTS alert_routes_scope_classification_check,
    DROP CONSTRAINT IF EXISTS alert_routes_scope_shape_check;

ALTER TABLE alert_routes
    ADD CONSTRAINT alert_routes_scope_classification_check
        CHECK (scope_classification IN ('legacy_unclassified', 'site_environment')),
    ADD CONSTRAINT alert_routes_scope_shape_check
        CHECK (
            (
                scope_classification = 'legacy_unclassified'
                AND site IS NULL
                AND environment IS NULL
            )
            OR
            (
                scope_classification = 'site_environment'
                AND site IS NOT NULL
                AND btrim(site) <> ''
                AND site = btrim(site)
                AND environment IS NOT NULL
                AND btrim(environment) <> ''
                AND environment = btrim(environment)
            )
        );

ALTER TABLE alert_routes
    ADD CONSTRAINT alert_routes_site_registry_fk
        FOREIGN KEY (site) REFERENCES site_registry(unlocode)
        ON UPDATE RESTRICT ON DELETE RESTRICT;

-- Scope is immutable application provenance.  Reclassification/backfill must
-- be an explicit reviewed migration, never an ordinary route update.
CREATE OR REPLACE FUNCTION enforce_alert_route_scope_immutable()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.site IS DISTINCT FROM OLD.site
       OR NEW.environment IS DISTINCT FROM OLD.environment
       OR NEW.scope_classification IS DISTINCT FROM OLD.scope_classification THEN
        RAISE EXCEPTION 'alert route authorization scope is immutable';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS enforce_alert_route_scope_immutable_trigger ON alert_routes;
CREATE TRIGGER enforce_alert_route_scope_immutable_trigger
BEFORE UPDATE OF site, environment, scope_classification ON alert_routes
FOR EACH ROW
EXECUTE FUNCTION enforce_alert_route_scope_immutable();

CREATE INDEX IF NOT EXISTS idx_alert_routes_scoped_list
    ON alert_routes (site, environment, created_at, id)
    WHERE scope_classification = 'site_environment';

CREATE INDEX IF NOT EXISTS idx_alert_routes_scoped_resolve
    ON alert_routes (
        site,
        environment,
        trigger_name,
        severity,
        host_group,
        created_at,
        id
    )
    WHERE scope_classification = 'site_environment' AND enabled = TRUE;
