-- 00019_fw_schedules.sql
-- Time-based filter rules. A schedule defines a window (days-of-week +
-- start/end time + timezone). Filter rules can attach to a schedule via
-- schedule_id; null = always active.
--
-- Generation rule: at apply time, the daemon queries which schedules are
-- "active now" (in their timezone). Rules attached to inactive schedules
-- are skipped. A background watcher in the daemon re-applies whenever the
-- active set changes (cron-style minute tick).
--
-- We keep windows simple — single contiguous start→end inside one day. For
-- "split shifts" the operator creates two schedules and attaches the rule
-- to one of them via a parent group of rules (future). That keeps the
-- model simple and the watcher's "is active now" check trivial.

CREATE TABLE IF NOT EXISTS fw_schedules (
    id            uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    name          varchar(80)  UNIQUE NOT NULL,
    description   text,
    days_of_week  int[]        NOT NULL DEFAULT '{0,1,2,3,4,5,6}',  -- 0=Sun .. 6=Sat (Postgres dow)
    start_time    time         NOT NULL DEFAULT '00:00',
    end_time      time         NOT NULL DEFAULT '23:59',
    timezone      varchar(64)  NOT NULL DEFAULT 'UTC',
    enabled       boolean      NOT NULL DEFAULT true,
    created_at    timestamptz  NOT NULL DEFAULT NOW(),
    updated_at    timestamptz  NOT NULL DEFAULT NOW()
);

ALTER TABLE fw_filter_rules
    ADD COLUMN IF NOT EXISTS schedule_id uuid REFERENCES fw_schedules(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_fw_filter_rules_schedule ON fw_filter_rules(schedule_id);
