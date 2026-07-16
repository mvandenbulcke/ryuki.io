-- 172_certificate_query_bounds.sql — bounded certificate inventory/expiry reads.
--
-- The inventory API pages by newest-first creation order after applying an
-- optional site scope. The expiry API pages by earliest validity deadline after
-- applying the same optional site scope. These indexes match those exact
-- predicates and ordering keys so PostgreSQL can stop at LIMIT instead of
-- sorting or transferring the complete certificate population.
--
-- `certificates.site` was historically unconstrained TEXT. A legacy value can
-- therefore exceed PostgreSQL's btree tuple limit and make a site-leading index
-- deployment fail even though the API's canonical site namespace is at most 32
-- octets. Keep such legacy rows intact for explicit operator reconciliation:
-- the NOT VALID check rejects every new out-of-bounds direct write, while the
-- partial indexes and their identical read predicates quarantine old invalid
-- rows from bounded inventory/expiry traversal. Operators can review
-- `NOT (octet_length(site) BETWEEN 1 AND 32)`, normalize or move each row under
-- an approved process, and then validate the named constraint. This migration
-- never truncates or silently rewrites a site authority value.

ALTER TABLE certificates
    ADD CONSTRAINT certificates_site_query_bounds
    CHECK (octet_length(site) BETWEEN 1 AND 32) NOT VALID;

CREATE INDEX idx_certificates_inventory_page
    ON certificates (created_at DESC, id DESC)
    WHERE octet_length(site) BETWEEN 1 AND 32;

CREATE INDEX idx_certificates_site_inventory_page
    ON certificates (site, created_at DESC, id DESC)
    WHERE octet_length(site) BETWEEN 1 AND 32;

CREATE INDEX idx_certificates_expiry_page
    ON certificates (valid_to ASC, id ASC)
    WHERE octet_length(site) BETWEEN 1 AND 32;

CREATE INDEX idx_certificates_site_expiry_page
    ON certificates (site, valid_to ASC, id ASC)
    WHERE octet_length(site) BETWEEN 1 AND 32;
