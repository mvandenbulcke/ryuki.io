-- P2-12 defense-in-depth: durable CHECK constraints for the network_readiness
-- tables. The app layer (sources/ryuki-api/src/repos/network_readiness.rs)
-- already enforces these (i32::try_from + the reserve/release status flow), so
-- this is belt-and-suspenders that prevents out-of-band SQL or any future code
-- path from committing a row the engine's invariants forbid:
--   * vlans.available_ips can never go negative (the atomic decrement guards it,
--     but a corrupt/wrapped write must not be able to inflate capacity).
--   * switch_ports.status / port_reservations.status & resource_type are confined
--     to the documented domains the repo decodes.
-- All existing rows already satisfy these (migration 019 seeds switch_ports with
-- only Available/InUse/Disabled, seeds no port_reservations, and available_ips
-- defaults to a non-negative value).

ALTER TABLE vlans
    ADD CONSTRAINT vlans_available_ips_nonneg CHECK (available_ips >= 0);

ALTER TABLE switch_ports
    ADD CONSTRAINT switch_ports_status_domain
    CHECK (status IN ('Available', 'InUse', 'Reserved', 'Disabled'));

ALTER TABLE port_reservations
    ADD CONSTRAINT port_reservations_status_domain
    CHECK (status IN ('reserved', 'released'));

ALTER TABLE port_reservations
    ADD CONSTRAINT port_reservations_resource_type_domain
    CHECK (resource_type IN ('ports', 'ips'));
