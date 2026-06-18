-- P2-12 defense-in-depth: forbid NULL elements in aiops_suggestions.affected_components.
-- The column is `TEXT[] NOT NULL DEFAULT '{}'`, but NOT NULL only guards the array
-- itself, NOT its elements: ARRAY['a', NULL]::text[] passes. The repo
-- (sources/ryuki-api/src/repos/aiops.rs) decodes it into Vec<String>, so a single
-- NULL element would fail the decode and 500 an entire list/savings/stats read.
-- No application write path inserts affected_components (generate_suggestions is a
-- read; the lifecycle mutations never touch it) and the seed has no NULL elements,
-- so this only closes an out-of-band corruption hole. array_position returns NULL
-- when the search value (NULL) is not found, so the constraint holds iff there is
-- no NULL element.

ALTER TABLE aiops_suggestions
    ADD CONSTRAINT aiops_affected_components_no_null_elements
    CHECK (array_position(affected_components, NULL) IS NULL);
