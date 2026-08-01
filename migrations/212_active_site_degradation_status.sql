-- Every active canonical site must have a fail-closed degradation-status row.
-- Migration 086 made DEBER and FRPAR active after migration 025 had seeded
-- status only for DEFRA, GBLON, and NLAMS.  The authoritative status reader
-- consequently rejected the entire set as incomplete.  Backfill every active
-- gap so upgraded databases and pristine installs converge on the invariant.
--
-- Migration 198 requires newly introduced status authority to begin in
-- recovery.  Keep every health component explicitly non-authoritative until a
-- real health observation promotes the site.
INSERT INTO site_status (
    site,
    state,
    api_status,
    db_status,
    degradation_reason,
    last_check,
    updated_at
)
SELECT
    registry.unlocode,
    'recovering',
    'down',
    'down',
    'awaiting canonical health observation',
    statement_timestamp(),
    statement_timestamp()
FROM site_registry AS registry
WHERE registry.active = TRUE
  AND NOT EXISTS (
      SELECT 1
      FROM site_status AS status
      WHERE status.site = registry.unlocode
  );

INSERT INTO component_status (site, adapter_name, status, last_check)
SELECT
    status.site,
    adapter.adapter_name,
    'down',
    statement_timestamp()
FROM site_status AS status
CROSS JOIN (
    VALUES
        ('vmware'),
        ('hyperv'),
        ('proxmox'),
        ('nutanix'),
        ('xen'),
        ('kvm'),
        ('veeam'),
        ('zabbix'),
        ('servicenow'),
        ('commvault'),
        ('rubrik'),
        ('cohesity'),
        ('netbackup')
) AS adapter(adapter_name)
JOIN site_registry AS registry
  ON registry.unlocode = status.site
 AND registry.active = TRUE
WHERE NOT EXISTS (
    SELECT 1
    FROM component_status AS component
    WHERE component.site = status.site
      AND component.adapter_name = adapter.adapter_name
);
