-- Migration 065: normalize log_forwarders status/source_type to PascalCase serde
-- variant names and replace the lowercase CHECK constraints with PascalCase ones.

-- 1. Drop the OLD lowercase CHECK constraints FIRST. The normalization UPDATEs
--    below set PascalCase values, which would transiently violate the original
--    lowercase CHECK (e.g. status='NotConfigured' is not in the old
--    ('not-configured',...) set) if the old constraint were still in force.
ALTER TABLE log_forwarders
    DROP CONSTRAINT IF EXISTS log_forwarders_status_check,
    DROP CONSTRAINT IF EXISTS log_forwarders_source_type_check;

-- 2. Normalize existing rows: status.
UPDATE log_forwarders SET status = 'NotConfigured' WHERE status = 'not-configured';
UPDATE log_forwarders SET status = 'Configured'    WHERE status = 'configured';
UPDATE log_forwarders SET status = 'Active'        WHERE status = 'active';
UPDATE log_forwarders SET status = 'Failed'        WHERE status = 'failed';

-- 3. Normalize existing rows: source_type.
UPDATE log_forwarders SET source_type = 'WindowsEventLog' WHERE source_type = 'windows-event-log';
UPDATE log_forwarders SET source_type = 'Syslog'          WHERE source_type = 'syslog';
UPDATE log_forwarders SET source_type = 'Auditd'          WHERE source_type = 'auditd';
UPDATE log_forwarders SET source_type = 'IIS'             WHERE source_type = 'iis';
UPDATE log_forwarders SET source_type = 'Apache'          WHERE source_type = 'apache';

-- 4. Add the PascalCase CHECK constraints (data is now normalized to satisfy them).
ALTER TABLE log_forwarders
    ADD CONSTRAINT log_forwarders_status_check
        CHECK (status IN ('NotConfigured', 'Configured', 'Active', 'Failed')),
    ADD CONSTRAINT log_forwarders_source_type_check
        CHECK (source_type IN ('WindowsEventLog', 'Syslog', 'Auditd', 'IIS', 'Apache'));

-- 5. Align the column default with the PascalCase serde name.
ALTER TABLE log_forwarders
    ALTER COLUMN status SET DEFAULT 'NotConfigured';
