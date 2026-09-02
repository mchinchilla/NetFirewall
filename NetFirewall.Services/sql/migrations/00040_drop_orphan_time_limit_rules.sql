-- 00040_drop_orphan_time_limit_rules.sql
-- Time-limit (TIME-LIMIT) drops are created by "Apply to devices" and exist
-- only as the schedule's effect. fw_filter_rules.schedule_id is ON DELETE
-- SET NULL, so deleting a window used to leave those drops enabled with
-- no schedule — a 24/7 block that survived every nft apply.
--
-- Wipe the leftovers. ScheduleService.DeleteAsync now removes TIME-LIMIT
-- rows with the schedule, and the generator skips any that still have no
-- live window.

DELETE FROM fw_filter_rules
 WHERE log_prefix = 'TIME-LIMIT'
   AND schedule_id IS NULL;
