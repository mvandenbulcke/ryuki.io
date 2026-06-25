-- 099_ipam_subnet_checks.sql — durable constraints on ipam_subnets (#56).
--
-- The IPAM subnet CRUD API validates vlan_id (1..=4094) and status
-- (Available/Exhausted/Reserved) in ryuki_engine::dns_ipam, but migration 050
-- created the table without these CHECKs, so a row written outside the API path
-- could carry an out-of-range vlan (which the update handler reads back as u16)
-- or a bogus status. Enforce both durably. The four seed subnets from 050 all
-- satisfy these, so the constraints validate cleanly on add.

ALTER TABLE ipam_subnets
    DROP CONSTRAINT IF EXISTS ipam_subnets_vlan_range;
ALTER TABLE ipam_subnets
    ADD CONSTRAINT ipam_subnets_vlan_range
        CHECK (vlan_id BETWEEN 1 AND 4094);

ALTER TABLE ipam_subnets
    DROP CONSTRAINT IF EXISTS ipam_subnets_status_valid;
ALTER TABLE ipam_subnets
    ADD CONSTRAINT ipam_subnets_status_valid
        CHECK (status IN ('Available', 'Exhausted', 'Reserved'));
