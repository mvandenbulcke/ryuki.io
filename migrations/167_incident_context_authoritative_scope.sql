-- Bind incident contexts to an authoritative canonical site.
--
-- The legacy JSON stored caller-supplied CI names and sites without a closed,
-- reviewed provenance record. Neither value is sufficient to reconstruct an
-- authorization boundary. Every pre-column row therefore remains NULL and is
-- quarantined; only a new binding-aware writer may create a bound row.

ALTER TABLE incident_contexts
    ADD COLUMN site TEXT;

ALTER TABLE incident_contexts
    ADD CONSTRAINT incident_contexts_site_canonical_check
    CHECK (
        site IS NULL
        OR (site <> '' AND site = upper(btrim(site)))
    );

ALTER TABLE incident_contexts
    ADD CONSTRAINT incident_contexts_site_registry_fk
    FOREIGN KEY (site) REFERENCES site_registry(unlocode) ON UPDATE RESTRICT;

CREATE INDEX idx_incident_contexts_site_status
    ON incident_contexts(site, status, created_at DESC)
    WHERE site IS NOT NULL;

-- A NULL site remains the fail-closed rolling-deployment quarantine for rows
-- written by a pre-binding binary. This makes the rolling cohorts non-overlap:
-- an old writer may continue changing only invisible NULL-site rows, cannot
-- promote one, and its site-less JSON cannot update a bound row. Once a row has
-- a proven binding, neither an old writer nor a later request may change or
-- remove that provenance. New CI bindings may only be appended and must resolve
-- exactly through the current CMDB to the same active canonical site. FOR SHARE
-- serializes every bound insert/update with site or CMDB authority changes until
-- the writer's transaction ends.
CREATE OR REPLACE FUNCTION enforce_incident_context_authority_binding()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    affected_binding JSONB;
    invalid_binding BOOLEAN;
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.site IS DISTINCT FROM OLD.site THEN
        RAISE EXCEPTION
            'incident context canonical site provenance is immutable'
            USING ERRCODE = '23514';
    END IF;

    -- Pre-binding rolling writers omit `site`. Their rows stay quarantined and
    -- cannot later be promoted because the UPDATE branch above is immutable.
    IF NEW.site IS NULL THEN
        RETURN NEW;
    END IF;

    IF NEW.site = '' OR NEW.site <> upper(btrim(NEW.site)) THEN
        RAISE EXCEPTION
            'incident context site must be an exact canonical key'
            USING ERRCODE = '23514';
    END IF;

    PERFORM 1
    FROM site_registry registry
    WHERE registry.unlocode = NEW.site
      AND registry.active = true
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION
            'incident context site must be currently active'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.incident_json->>'incident_id' IS DISTINCT FROM NEW.incident_id
       OR NEW.incident_json->>'site' IS DISTINCT FROM NEW.site
       OR NEW.incident_json->>'status' IS DISTINCT FROM NEW.status
       OR jsonb_typeof(NEW.incident_json->'affected_ci') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION
            'incident context JSON must preserve its canonical relational authority'
            USING ERRCODE = '23514';
    END IF;
    IF jsonb_array_length(NEW.incident_json->'affected_ci') = 0 THEN
        RAISE EXCEPTION
            'incident context JSON must preserve its canonical relational authority'
            USING ERRCODE = '23514';
    END IF;

    SELECT count(*) <> count(DISTINCT affected.item->>'ci_name')
    INTO invalid_binding
    FROM jsonb_array_elements(NEW.incident_json->'affected_ci') affected(item);
    IF invalid_binding THEN
        RAISE EXCEPTION
            'incident context affected CI bindings must be unique'
            USING ERRCODE = '23514';
    END IF;

    -- Lock every exact CMDB tuple in a deterministic order. This makes the
    -- trigger's validation a transaction-stable provenance assertion instead
    -- of a check-then-change race with CI moves, renames, or deletes.
    FOR affected_binding IN
        SELECT affected.item
        FROM jsonb_array_elements(NEW.incident_json->'affected_ci') affected(item)
        ORDER BY affected.item->>'ci_name'
    LOOP
        PERFORM 1
        FROM configuration_items ci
        WHERE ci.ci_name = affected_binding->>'ci_name'
          AND ci.ci_type = affected_binding->>'ci_type'
          AND affected_binding->>'site' = NEW.site
          AND ci.site = NEW.site
        FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION
                'incident context affected CIs must match exact same-site CMDB bindings'
                USING ERRCODE = '23514';
        END IF;
    END LOOP;

    IF TG_OP = 'UPDATE' AND OLD.site IS NOT NULL THEN
        SELECT EXISTS (
            SELECT 1
            FROM jsonb_array_elements(OLD.incident_json->'affected_ci')
                WITH ORDINALITY AS old_ci(item, ordinality)
            WHERE NOT EXISTS (
                SELECT 1
                FROM jsonb_array_elements(NEW.incident_json->'affected_ci')
                    WITH ORDINALITY AS new_ci(item, ordinality)
                WHERE new_ci.ordinality = old_ci.ordinality
                  AND new_ci.item->>'ci_name' = old_ci.item->>'ci_name'
                  AND new_ci.item->>'ci_type' = old_ci.item->>'ci_type'
                  AND new_ci.item->>'site' = old_ci.item->>'site'
            )
        ) INTO invalid_binding;
        IF invalid_binding THEN
            RAISE EXCEPTION
                'incident context CMDB provenance may be appended but not changed or removed'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER incident_context_authority_binding_guard
BEFORE INSERT OR UPDATE ON incident_contexts
FOR EACH ROW
EXECUTE FUNCTION enforce_incident_context_authority_binding();

COMMENT ON COLUMN incident_contexts.site IS
    'Immutable canonical authorization site derived from exact trusted CMDB/site-registry relations; NULL means a quarantined rolling-writer row and must never be returned or promoted.';
