-- Site identifiers default to UN/LOCODE but may use an operator-defined code.
-- The existing `unlocode` column name remains the canonical key for backward
-- compatibility; `code_system` makes the identifier's semantics explicit.
ALTER TABLE site_registry
    ADD COLUMN code_system TEXT NOT NULL DEFAULT 'unlocode';

ALTER TABLE site_registry
    ADD CONSTRAINT site_registry_code_system_check
    CHECK (code_system IN ('unlocode', 'custom'));

-- Earlier seed data used the human-readable `CC LLL` presentation for some
-- entries. Canonical storage is compact, upper-case and URL-safe.
UPDATE site_registry
SET unlocode = replace(upper(unlocode), ' ', '')
WHERE code_system = 'unlocode';
