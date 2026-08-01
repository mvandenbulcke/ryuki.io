-- Enforce the incident affected-CI cap at the durable authority boundary.
--
-- API assembly already limits one request to 100 names, but repeated add-CI
-- mutations could cumulatively grow the persisted JSON without bound. Replace
-- the existing authority trigger function so it rejects an oversized bound
-- incident using jsonb's container length before any jsonb_array_elements call.
-- All canonical-site, CMDB provenance, immutability, and append-only checks
-- from migration 167 remain authoritative and unchanged below.

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

    -- Apply the fixed-cost container check to bound and quarantined rows alike.
    -- It must precede both the rolling-writer return and every set-returning
    -- jsonb expansion so neither cohort can persist or process an unbounded
    -- affected-CI array.
    IF jsonb_typeof(NEW.incident_json->'affected_ci') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION
            'incident context affected_ci must be an array containing between 1 and 100 bindings'
            USING ERRCODE = '23514';
    END IF;
    IF jsonb_array_length(NEW.incident_json->'affected_ci') NOT BETWEEN 1 AND 100 THEN
        RAISE EXCEPTION
            'incident context must contain between 1 and 100 affected CI bindings'
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

-- Retain the invariant in table metadata as well as procedural trigger code.
-- NULL-site rows remain the migration-167 rolling-writer quarantine for
-- authorization, but quarantine must not become a storage/trigger-work bypass.
-- Validation fails the migration if any current row violates the explicit cap.
ALTER TABLE incident_contexts
    ADD CONSTRAINT incident_contexts_affected_ci_cardinality_check
    CHECK (
        CASE
            WHEN jsonb_typeof(incident_json->'affected_ci') IS DISTINCT FROM 'array' THEN false
            ELSE jsonb_array_length(incident_json->'affected_ci') BETWEEN 1 AND 100
        END
    )
    NOT VALID;

ALTER TABLE incident_contexts
    VALIDATE CONSTRAINT incident_contexts_affected_ci_cardinality_check;

COMMENT ON FUNCTION enforce_incident_context_authority_binding() IS
    'Enforces canonical incident site and append-only CMDB provenance, including a pre-expansion 1..100 affected-CI cardinality bound.';
