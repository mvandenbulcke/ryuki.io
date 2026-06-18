-- Migration 068: add site to baseline_results + CHECK constraints on baseline_checks.
ALTER TABLE baseline_results ADD COLUMN site TEXT;
UPDATE baseline_results SET site =
    CASE
        WHEN server_name ILIKE '%defra%' THEN 'DEFRA'
        WHEN server_name ILIKE '%gblon%' THEN 'GBLON'
        WHEN server_name ILIKE '%frpar%' THEN 'FRPAR'
        WHEN server_name ILIKE '%nlams%' THEN 'NLAMS'
        WHEN server_name ILIKE '%deber%' THEN 'DEBER'
        ELSE 'UNKNOWN'
    END;
ALTER TABLE baseline_results ALTER COLUMN site SET NOT NULL;
CREATE INDEX idx_baseline_results_site ON baseline_results(site);
ALTER TABLE baseline_checks
    ADD CONSTRAINT baseline_checks_category_check
        CHECK (category IN ('Security', 'Patching', 'Monitoring', 'Agent', 'Tools', 'Configuration')),
    ADD CONSTRAINT baseline_checks_severity_check
        CHECK (severity IN ('Critical', 'High', 'Low'));
