-- 100_storage_volumes_array_fk.sql — enforce storage_volumes → storage_arrays
-- referential integrity (#38 follow-up).
--
-- Migration 080 left storage_volumes.storage_array as a plain TEXT column
-- ("array ID string, not FK-enforced"). That made array decommission (#38)
-- racy: the delete's "refuse while volumes reference it" count check could be
-- bypassed by a volume provisioned during the delete window (no lock tied the
-- two together), orphaning the volume.
--
-- Add the FK with ON DELETE RESTRICT. This (a) makes the refusal DB-enforced
-- (the array delete cannot succeed while a volume references it) and (b) closes
-- the race: a concurrent volume INSERT now takes a KEY SHARE lock on the
-- referenced storage_arrays row, which conflicts with the delete's
-- `SELECT ... FOR UPDATE` on that row, so the two serialize. The seeded volumes
-- all reference seeded arrays, so the constraint validates cleanly.

ALTER TABLE storage_volumes
    DROP CONSTRAINT IF EXISTS fk_storage_volumes_array;
ALTER TABLE storage_volumes
    ADD CONSTRAINT fk_storage_volumes_array
        FOREIGN KEY (storage_array) REFERENCES storage_arrays (id)
        ON DELETE RESTRICT;
