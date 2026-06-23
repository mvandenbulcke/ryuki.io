-- 092_shift_queue_assigned_by.sql — record WHO performed a shift-queue assignment.
--
-- `shift_queue.assigned_to` is the ASSIGNEE (the user the item is assigned TO).
-- It does not record the actor who performed the assignment. `shift_acknowledge`
-- already records `acknowledged_by = session.user_id`; mirror that for the assign
-- action so the audit trail names the real principal. Nullable: existing rows
-- (and the migration 029 seed) have no recorded assigner.
ALTER TABLE shift_queue ADD COLUMN IF NOT EXISTS assigned_by TEXT;
