-- 00041_diag_runs.sql
-- History of every Diagnostics tool run (ping, traceroute, route oracle,
-- conntrack lookup, drop-log explorer, interface health, sysctl sanity, VPN
-- doctor / probe / compare). The daemon writes a row before the tool starts
-- (status = running) and completes it when the tool finishes; the Web reads
-- the table directly for the History page, so yesterday's report is readable
-- even while the daemon is down.
--
-- params/result are the request/result records serialised as JSON. Secrets
-- (wg private/preshared keys in a pasted config) are redacted BEFORE they
-- reach this table. Results above the size cap are stored as a small
-- {"truncated":true} object with result_truncated = true.

CREATE TABLE IF NOT EXISTS diag_runs (
    id               uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    tool             varchar(40)  NOT NULL,
    status           varchar(16)  NOT NULL DEFAULT 'running'
                     CHECK (status IN ('running', 'ok', 'warn', 'fail', 'error', 'timeout')),
    started_at       timestamptz  NOT NULL DEFAULT now(),
    finished_at      timestamptz,
    duration_ms      int,
    requested_by     varchar(100),
    target           varchar(255),
    params           jsonb        NOT NULL DEFAULT '{}'::jsonb,
    result           jsonb,
    result_truncated boolean      NOT NULL DEFAULT false,
    summary          varchar(500)
);

CREATE INDEX IF NOT EXISTS idx_diag_runs_started      ON diag_runs (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_diag_runs_tool_started ON diag_runs (tool, started_at DESC);
