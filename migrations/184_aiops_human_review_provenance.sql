-- AIOps review attribution is human evidence, not a generic principal label.
-- Preserve typed actor provenance beside the reviewer so a workload-owned API
-- token cannot leave a human-looking `reviewer` value. Existing attributed rows
-- predate this admission proof and are explicitly quarantined as unknown; they
-- cannot be accepted by the repository's verified-human CAS predicate.

ALTER TABLE aiops_suggestions
    ADD COLUMN reviewer_actor_class TEXT;

UPDATE aiops_suggestions
SET reviewer_actor_class = 'unknown'
WHERE reviewer IS NOT NULL;

ALTER TABLE aiops_suggestions
    ADD CONSTRAINT aiops_reviewer_actor_class_known
        CHECK (
            reviewer_actor_class IS NULL
            OR reviewer_actor_class IN ('verified-human', 'workload', 'simulated', 'unknown')
        ),
    ADD CONSTRAINT aiops_reviewer_provenance_complete
        CHECK (
            (reviewer IS NULL AND reviewer_actor_class IS NULL)
            OR (reviewer IS NOT NULL AND reviewer_actor_class IS NOT NULL)
        );

CREATE FUNCTION prevent_aiops_reviewer_provenance_rebind()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.reviewer IS NOT NULL
       AND (
           NEW.reviewer IS DISTINCT FROM OLD.reviewer
           OR NEW.reviewer_actor_class IS DISTINCT FROM OLD.reviewer_actor_class
       ) THEN
        RAISE EXCEPTION 'AIOps reviewer provenance is immutable'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_aiops_reviewer_provenance_immutable
BEFORE UPDATE OF reviewer, reviewer_actor_class ON aiops_suggestions
FOR EACH ROW
EXECUTE FUNCTION prevent_aiops_reviewer_provenance_rebind();
