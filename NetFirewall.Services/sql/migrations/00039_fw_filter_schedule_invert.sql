-- 00039_fw_filter_schedule_invert.sql
-- A scheduled rule normally lives in the ruleset only while its schedule is
-- active. Invert flips that: the rule is emitted while the schedule is idle.
--
-- Parental-control pattern: DROP kids' objects at priority 2 (before the
-- established-allow), invert=true, schedule=KIDS_ONLINE 06:00–22:00.
-- During the window the drop is gone and they browse; outside it the drop
-- sits in front of established so existing streams actually stop.

ALTER TABLE fw_filter_rules
    ADD COLUMN IF NOT EXISTS schedule_invert boolean NOT NULL DEFAULT false;
