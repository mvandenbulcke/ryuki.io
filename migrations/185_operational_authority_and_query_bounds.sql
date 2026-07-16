-- 185_operational_authority_and_query_bounds.sql
--
-- Close two operational-authority gaps without guessing legacy ownership:
--   * certificates must reference an exact active canonical site at creation;
--   * snapshot stale-claim and inventory queries need indexes matching their
--     bounded work order.

-- Preserve invalid legacy certificate rows for explicit operator review while
-- removing them from active governance and expiry scheduling. No site string is
-- truncated, normalized, or rebound to a different authority.
CREATE TABLE certificate_site_authority_quarantine (
    certificate_id UUID PRIMARY KEY,
    common_name TEXT NOT NULL,
    subject TEXT,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_to TIMESTAMPTZ NOT NULL,
    service_type TEXT NOT NULL,
    hostname TEXT NOT NULL,
    source_site TEXT NOT NULL,
    original_status TEXT NOT NULL,
    original_created_at TIMESTAMPTZ NOT NULL,
    quarantine_reason TEXT NOT NULL CHECK (
        quarantine_reason IN ('invalid-site-shape', 'unknown-site', 'inactive-site')
    ),
    quarantined_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO certificate_site_authority_quarantine (
    certificate_id,
    common_name,
    subject,
    valid_from,
    valid_to,
    service_type,
    hostname,
    source_site,
    original_status,
    original_created_at,
    quarantine_reason
)
SELECT
    certificate.id,
    certificate.common_name,
    certificate.subject,
    certificate.valid_from,
    certificate.valid_to,
    certificate.service_type,
    certificate.hostname,
    certificate.site,
    certificate.status,
    certificate.created_at,
    CASE
        WHEN NOT (octet_length(certificate.site) BETWEEN 1 AND 32)
            THEN 'invalid-site-shape'
        WHEN registry.unlocode IS NULL THEN 'unknown-site'
        ELSE 'inactive-site'
    END
FROM certificates AS certificate
LEFT JOIN site_registry AS registry
       ON registry.unlocode = certificate.site
WHERE NOT (octet_length(certificate.site) BETWEEN 1 AND 32)
   OR registry.unlocode IS NULL
   OR registry.active = false;

DELETE FROM certificates AS certificate
USING certificate_site_authority_quarantine AS quarantine
WHERE quarantine.certificate_id = certificate.id;

-- The quarantine leaves only canonical active-site rows, so both the existing
-- query-shape constraint and the new referential authority can be validated.
ALTER TABLE certificates
    VALIDATE CONSTRAINT certificates_site_query_bounds;

ALTER TABLE certificates
    ADD CONSTRAINT certificates_site_registry_fk
    FOREIGN KEY (site)
    REFERENCES site_registry(unlocode)
    ON UPDATE RESTRICT
    ON DELETE RESTRICT;

-- Application creation holds the same site row FOR SHARE. Repeat the invariant
-- at the database boundary so direct writers and future callers cannot bypass
-- active-site authority.
CREATE OR REPLACE FUNCTION enforce_certificate_active_site()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM 1
    FROM site_registry
    WHERE unlocode = NEW.site
      AND active = true
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'certificate site must reference an active canonical site'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_certificates_active_site
BEFORE INSERT OR UPDATE OF site
ON certificates
FOR EACH ROW
EXECUTE FUNCTION enforce_certificate_active_site();

-- Global authorized snapshot pages order independently of configuration item;
-- the older CI-leading index cannot serve that order. Stale claims use the
-- oldest eligible row first and transition claimed rows out of the partial
-- index, providing queue-like keyset progress without OFFSET.
CREATE INDEX idx_snapshots_authorized_created_page
    ON snapshots(created_at DESC, id DESC)
    WHERE configuration_item_id IS NOT NULL;

CREATE INDEX idx_snapshots_stale_claim
    ON snapshots(created_at ASC, id ASC)
    WHERE configuration_item_id IS NOT NULL
      AND status IN ('Draft', 'ReviewRequested', 'ExpiryApproved');
