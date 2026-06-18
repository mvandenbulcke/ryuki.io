-- Migration 069: zabbix_drift persistence — add remediation_steps + metadata,
-- normalize severity/status to PascalCase (matches engine serde), add CHECKs,
-- add UNIQUE (site, host_id) for the detect upsert.
ALTER TABLE drift_reports
    ADD COLUMN remediation_steps TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN metadata          JSONB  NOT NULL DEFAULT '{}';
UPDATE drift_reports SET drift_severity = 'Critical' WHERE drift_severity = 'critical';
UPDATE drift_reports SET drift_severity = 'High'     WHERE drift_severity = 'high';
UPDATE drift_reports SET drift_severity = 'Medium'   WHERE drift_severity = 'medium';
UPDATE drift_reports SET drift_severity = 'Low'      WHERE drift_severity = 'low';
UPDATE drift_reports SET drift_severity = 'Info'     WHERE drift_severity = 'info';
UPDATE drift_reports SET status = 'Detected'   WHERE status = 'detected';
UPDATE drift_reports SET status = 'Planned'    WHERE status = 'planned';
UPDATE drift_reports SET status = 'Validated'  WHERE status = 'validated';
UPDATE drift_reports SET status = 'Remediated' WHERE status = 'remediated';
UPDATE drift_reports SET status = 'Verified'   WHERE status = 'verified';
UPDATE drift_reports SET status = 'Failed'     WHERE status = 'failed';
ALTER TABLE drift_reports
    ADD CONSTRAINT drift_reports_severity_check
        CHECK (drift_severity IN ('Critical','High','Medium','Low','Info')),
    ADD CONSTRAINT drift_reports_status_check
        CHECK (status IN ('Detected','Planned','Validated','Remediated','Verified','Failed'));
ALTER TABLE drift_reports
    ALTER COLUMN drift_severity SET DEFAULT 'Medium',
    ALTER COLUMN status SET DEFAULT 'Detected';
ALTER TABLE drift_reports
    ADD CONSTRAINT drift_reports_site_host_id_key UNIQUE (site, host_id);
