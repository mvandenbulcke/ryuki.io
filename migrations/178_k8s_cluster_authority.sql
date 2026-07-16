-- Migration 178: authoritative cluster/site/environment binding for Kubernetes
-- namespace governance.
--
-- The registry is deliberately provider-neutral.  A trusted inventory process
-- owns these rows; request bodies and namespace naming conventions are never an
-- authority source.  Namespace rows without explicit provenance remain
-- quarantined and are excluded from application reads and mutations.
--
-- CUTOVER CONTRACT: this migration and the API release that consumes it require
-- a non-overlapping cutover.  Drain every pre-178 API replica and its open
-- transactions before applying the migration, then start only replicas that
-- enforce the current active site_registry relation.  An old replica must not
-- overlap this schema or be reintroduced during rollback: it does not perform
-- the active-site join and can therefore serve or mutate stale site authority.

CREATE TABLE k8s_cluster_registry (
    id TEXT PRIMARY KEY,
    cluster_name TEXT NOT NULL UNIQUE,
    site TEXT NOT NULL,
    provider_kind TEXT NOT NULL DEFAULT 'provider-neutral',
    lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN ('Active', 'Inactive')),
    inventory_source TEXT NOT NULL,
    authority_version BIGINT NOT NULL DEFAULT 1 CHECK (authority_version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (btrim(cluster_name) <> ''),
    CONSTRAINT k8s_cluster_registry_site_canonical
        CHECK (site = upper(btrim(site)) AND site <> ''),
    CHECK (btrim(provider_kind) <> ''),
    CHECK (btrim(inventory_source) <> ''),
    CONSTRAINT k8s_cluster_registry_site_fk
        FOREIGN KEY (site)
        REFERENCES site_registry (unlocode)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    UNIQUE (id, cluster_name, site)
);

CREATE TABLE k8s_cluster_environment_scopes (
    id TEXT PRIMARY KEY,
    cluster_id TEXT NOT NULL,
    cluster_name TEXT NOT NULL,
    site TEXT NOT NULL,
    environment TEXT NOT NULL CHECK (environment IN ('Dev', 'Test', 'Staging', 'Prod')),
    lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN ('Active', 'Inactive')),
    inventory_source TEXT NOT NULL,
    authority_version BIGINT NOT NULL DEFAULT 1 CHECK (authority_version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT k8s_cluster_environment_scope_site_canonical
        CHECK (site = upper(btrim(site)) AND site <> ''),
    CHECK (btrim(inventory_source) <> ''),
    FOREIGN KEY (cluster_id, cluster_name, site)
        REFERENCES k8s_cluster_registry (id, cluster_name, site)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    UNIQUE (cluster_id, environment),
    UNIQUE (id, cluster_name, site, environment)
);

-- This is an explicit fixture authority manifest for migration 081's synthetic
-- clusters.  It is not derived from cluster or namespace names.  Real
-- deployments must reconcile these tables from a trusted cluster inventory.
INSERT INTO k8s_cluster_registry
    (id, cluster_name, site, provider_kind, lifecycle_state, inventory_source)
VALUES
    ('cluster-defra-aks-01', 'defra-aks-01', 'DEFRA', 'provider-neutral', 'Active', 'migration-081-curated-fixture'),
    ('cluster-defra-aks-02', 'defra-aks-02', 'DEFRA', 'provider-neutral', 'Active', 'migration-081-curated-fixture'),
    ('cluster-gblon-k8s-01', 'gblon-k8s-01', 'GBLON', 'provider-neutral', 'Active', 'migration-081-curated-fixture'),
    ('cluster-gblon-k8s-02', 'gblon-k8s-02', 'GBLON', 'provider-neutral', 'Active', 'migration-081-curated-fixture'),
    ('cluster-frpar-k8s-01', 'frpar-k8s-01', 'FRPAR', 'provider-neutral', 'Active', 'migration-081-curated-fixture');

INSERT INTO k8s_cluster_environment_scopes
    (id, cluster_id, cluster_name, site, environment, lifecycle_state, inventory_source)
VALUES
    ('cluster-scope-defra-aks-01-dev', 'cluster-defra-aks-01', 'defra-aks-01', 'DEFRA', 'Dev', 'Active', 'migration-081-curated-fixture'),
    ('cluster-scope-defra-aks-02-prod', 'cluster-defra-aks-02', 'defra-aks-02', 'DEFRA', 'Prod', 'Active', 'migration-081-curated-fixture'),
    ('cluster-scope-gblon-k8s-01-prod', 'cluster-gblon-k8s-01', 'gblon-k8s-01', 'GBLON', 'Prod', 'Active', 'migration-081-curated-fixture'),
    ('cluster-scope-gblon-k8s-02-test', 'cluster-gblon-k8s-02', 'gblon-k8s-02', 'GBLON', 'Test', 'Active', 'migration-081-curated-fixture'),
    ('cluster-scope-frpar-k8s-01-staging', 'cluster-frpar-k8s-01', 'frpar-k8s-01', 'FRPAR', 'Staging', 'Active', 'migration-081-curated-fixture'),
    ('cluster-scope-frpar-k8s-01-prod', 'cluster-frpar-k8s-01', 'frpar-k8s-01', 'FRPAR', 'Prod', 'Active', 'migration-081-curated-fixture');

ALTER TABLE k8s_namespaces
    ADD COLUMN cluster_scope_id TEXT,
    ADD COLUMN environment TEXT,
    ADD COLUMN scope_state TEXT NOT NULL DEFAULT 'Quarantined'
        CHECK (scope_state IN ('Verified', 'Quarantined')),
    ADD COLUMN scope_provenance TEXT NOT NULL DEFAULT 'legacy-unverified';

ALTER TABLE container_requests
    ADD COLUMN cluster_scope_id TEXT,
    ADD COLUMN scope_state TEXT NOT NULL DEFAULT 'Quarantined'
        CHECK (scope_state IN ('Verified', 'Quarantined')),
    ADD COLUMN scope_provenance TEXT NOT NULL DEFAULT 'legacy-unverified';

-- Only these migration-081 namespace IDs have an explicitly reviewed
-- environment mapping.  Any other pre-migration namespace remains quarantined.
WITH reviewed_namespace_scope (namespace_id, cluster_scope_id, environment) AS (
    VALUES
        ('k8s-defra-app-001', 'cluster-scope-defra-aks-01-dev', 'Dev'),
        ('k8s-defra-data-001', 'cluster-scope-defra-aks-02-prod', 'Prod'),
        ('k8s-gblon-obs-001', 'cluster-scope-gblon-k8s-01-prod', 'Prod'),
        ('k8s-gblon-build-001', 'cluster-scope-gblon-k8s-02-test', 'Test'),
        ('k8s-frpar-api-001', 'cluster-scope-frpar-k8s-01-staging', 'Staging'),
        ('k8s-frpar-edge-001', 'cluster-scope-frpar-k8s-01-prod', 'Prod')
)
UPDATE k8s_namespaces AS n
SET cluster_scope_id = reviewed.cluster_scope_id,
    environment = reviewed.environment,
    scope_state = 'Verified',
    scope_provenance = 'migration-081-curated-fixture@cluster-v1/scope-v1'
FROM reviewed_namespace_scope AS reviewed
JOIN k8s_cluster_environment_scopes AS scope
  ON scope.id = reviewed.cluster_scope_id
 AND scope.environment = reviewed.environment
WHERE n.id = reviewed.namespace_id
  AND n.cluster = scope.cluster_name
  AND n.site = scope.site;

-- Only these four migration-081 request rows were explicitly reviewed.  A
-- matching cluster/site/environment tuple is insufficient authority: arbitrary
-- pre-178 requests could carry the same caller-controlled text.  Require the
-- exact fixture ID and every immutable fixture attribute before promotion.
WITH reviewed_request_scope (
    request_id,
    cluster_scope_id,
    expected_requester,
    expected_namespace_name,
    expected_cluster,
    expected_site,
    expected_cpu_request,
    expected_memory_gb,
    expected_storage_gb,
    expected_environment,
    expected_purpose,
    expected_status
) AS (
    VALUES
        ('cr-defra-001', 'cluster-scope-defra-aks-01-dev',
         'alice.platform', 'defra-risk-dev', 'defra-aks-01', 'DEFRA',
         4, 12, 100, 'Dev', 'Risk model development', 'Validated'),
        ('cr-gblon-001', 'cluster-scope-gblon-k8s-02-test',
         'bob.sre', 'gblon-chaos-test', 'gblon-k8s-02', 'GBLON',
         6, 16, 120, 'Test', 'Chaos testing sandbox', 'Draft'),
        ('cr-frpar-001', 'cluster-scope-frpar-k8s-01-staging',
         'carla.apps', 'frpar-payments-staging', 'frpar-k8s-01', 'FRPAR',
         8, 24, 200, 'Staging', 'Payments pre-prod validation', 'Approved'),
        ('cr-defra-002', 'cluster-scope-defra-aks-02-prod',
         'diego.data', 'defra-analytics-prod', 'defra-aks-02', 'DEFRA',
         16, 64, 500, 'Prod', 'Analytics production workloads', 'Approved')
)
UPDATE container_requests AS request
SET cluster_scope_id = reviewed.cluster_scope_id,
    scope_state = 'Verified',
    scope_provenance = 'migration-081-curated-fixture@cluster-v1/scope-v1'
FROM reviewed_request_scope AS reviewed
JOIN k8s_cluster_environment_scopes AS scope
  ON scope.id = reviewed.cluster_scope_id
 AND scope.cluster_name = reviewed.expected_cluster
 AND scope.site = reviewed.expected_site
 AND scope.environment = reviewed.expected_environment
WHERE request.id = reviewed.request_id
  AND request.requester = reviewed.expected_requester
  AND request.namespace_name = reviewed.expected_namespace_name
  AND request.cluster = reviewed.expected_cluster
  AND request.site = reviewed.expected_site
  AND request.cpu_request = reviewed.expected_cpu_request
  AND request.memory_gb = reviewed.expected_memory_gb
  AND request.storage_gb = reviewed.expected_storage_gb
  AND request.environment = reviewed.expected_environment
  AND request.purpose = reviewed.expected_purpose
  AND request.status = reviewed.expected_status;

ALTER TABLE k8s_namespaces
    ADD CONSTRAINT k8s_namespaces_verified_scope_complete CHECK (
        scope_state = 'Quarantined'
        OR (
            cluster_scope_id IS NOT NULL
            AND environment IS NOT NULL
            AND environment IN ('Dev', 'Test', 'Staging', 'Prod')
            AND btrim(scope_provenance) <> ''
        )
    ),
    ADD CONSTRAINT k8s_namespaces_cluster_scope_fk
        FOREIGN KEY (cluster_scope_id, cluster, site, environment)
        REFERENCES k8s_cluster_environment_scopes (id, cluster_name, site, environment)
        ON UPDATE RESTRICT ON DELETE RESTRICT;

ALTER TABLE container_requests
    ADD CONSTRAINT container_requests_verified_scope_complete CHECK (
        scope_state = 'Quarantined'
        OR (cluster_scope_id IS NOT NULL AND btrim(scope_provenance) <> '')
    ),
    ADD CONSTRAINT container_requests_cluster_scope_fk
        FOREIGN KEY (cluster_scope_id, cluster, site, environment)
        REFERENCES k8s_cluster_environment_scopes (id, cluster_name, site, environment)
        ON UPDATE RESTRICT ON DELETE RESTRICT;

CREATE INDEX idx_k8s_namespaces_authorized_scope
    ON k8s_namespaces (site, environment, id)
    WHERE scope_state = 'Verified';
CREATE INDEX idx_k8s_namespaces_cluster_scope
    ON k8s_namespaces (cluster_scope_id)
    WHERE scope_state = 'Verified';
CREATE INDEX idx_container_requests_authorized_scope
    ON container_requests (site, environment, id)
    WHERE scope_state = 'Verified';
CREATE INDEX idx_k8s_cluster_environment_active
    ON k8s_cluster_environment_scopes (cluster_name, environment)
    WHERE lifecycle_state = 'Active';

-- Identity and scope coordinates are immutable.  Lifecycle and authority
-- version can change as trusted inventory disables or refreshes an entry.
CREATE FUNCTION prevent_k8s_cluster_identity_rebind()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(NEW.id, NEW.cluster_name, NEW.site)
        IS DISTINCT FROM ROW(OLD.id, OLD.cluster_name, OLD.site) THEN
        RAISE EXCEPTION 'Kubernetes cluster identity coordinates are immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_k8s_cluster_identity_immutable
BEFORE UPDATE ON k8s_cluster_registry
FOR EACH ROW EXECUTE FUNCTION prevent_k8s_cluster_identity_rebind();

CREATE FUNCTION prevent_k8s_cluster_scope_rebind()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(NEW.id, NEW.cluster_id, NEW.cluster_name, NEW.site, NEW.environment)
        IS DISTINCT FROM ROW(OLD.id, OLD.cluster_id, OLD.cluster_name, OLD.site, OLD.environment) THEN
        RAISE EXCEPTION 'Kubernetes cluster environment scope coordinates are immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_k8s_cluster_scope_immutable
BEFORE UPDATE ON k8s_cluster_environment_scopes
FOR EACH ROW EXECUTE FUNCTION prevent_k8s_cluster_scope_rebind();

CREATE FUNCTION prevent_verified_k8s_resource_rebind()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    derived_scope_id TEXT;
    derived_site TEXT;
    derived_provenance TEXT;
BEGIN
    -- INSERT provenance is always database-derived from the locked, active
    -- inventory hierarchy.  A caller may choose the cluster/environment it is
    -- authorized to provision into, but cannot mint Verified state, bind a
    -- different scope/site, or supply its own provenance string.
    IF TG_OP = 'INSERT' THEN
        SELECT cluster_scope.id,
               registry.site,
               format(
                   'cluster=%s:v%s;scope=%s:v%s;source=%s',
                   registry.id,
                   registry.authority_version,
                   cluster_scope.id,
                   cluster_scope.authority_version,
                   cluster_scope.inventory_source
               )
        INTO derived_scope_id, derived_site, derived_provenance
        FROM k8s_cluster_registry AS registry
        JOIN k8s_cluster_environment_scopes AS cluster_scope
          ON cluster_scope.cluster_id = registry.id
         AND cluster_scope.cluster_name = registry.cluster_name
         AND cluster_scope.site = registry.site
        JOIN site_registry AS current_site
          ON current_site.unlocode = registry.site
         AND current_site.active = TRUE
        WHERE registry.cluster_name = NEW.cluster
          AND cluster_scope.environment = NEW.environment
          AND registry.lifecycle_state = 'Active'
          AND cluster_scope.lifecycle_state = 'Active'
        FOR SHARE OF registry, cluster_scope, current_site;

        IF NOT FOUND THEN
            RAISE EXCEPTION
                'active Kubernetes cluster scope authority is required for insert';
        END IF;

        NEW.cluster_scope_id := derived_scope_id;
        NEW.site := derived_site;
        NEW.scope_state := 'Verified';
        NEW.scope_provenance := derived_provenance;
        RETURN NEW;
    END IF;

    IF OLD.scope_state = 'Verified'
       AND ROW(NEW.scope_state, NEW.cluster_scope_id, NEW.cluster, NEW.site, NEW.environment, NEW.scope_provenance)
           IS DISTINCT FROM
           ROW(OLD.scope_state, OLD.cluster_scope_id, OLD.cluster, OLD.site, OLD.environment, OLD.scope_provenance) THEN
        RAISE EXCEPTION 'verified Kubernetes scope provenance is immutable';
    END IF;
    IF OLD.scope_state = 'Quarantined' AND NEW.scope_state <> 'Quarantined' THEN
        RAISE EXCEPTION
            'quarantined Kubernetes rows require a separately governed inventory reconciliation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_k8s_namespace_scope_immutable
BEFORE INSERT OR UPDATE ON k8s_namespaces
FOR EACH ROW EXECUTE FUNCTION prevent_verified_k8s_resource_rebind();

CREATE TRIGGER trg_container_request_scope_immutable
BEFORE INSERT OR UPDATE ON container_requests
FOR EACH ROW EXECUTE FUNCTION prevent_verified_k8s_resource_rebind();
