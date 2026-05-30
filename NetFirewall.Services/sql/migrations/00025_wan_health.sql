-- Absorb WanMonitor into the daemon. We need persistent state (so a daemon
-- restart doesn't lose the "ens192 has been failing for 2 cycles" counter)
-- and a transition log (for the dashboard's Recent activity panel).
--
-- Per-interface config goes here too — we don't shove it into fw_interfaces
-- because monitor_targets is a multi-row concept and we want to keep the
-- main interface table lean.


-- ───────────── per-interface health config ─────────────
CREATE TABLE IF NOT EXISTS wan_health_config (
    id                   uuid                     PRIMARY KEY DEFAULT gen_random_uuid(),
    interface_id         uuid                     NOT NULL UNIQUE REFERENCES fw_interfaces(id) ON DELETE CASCADE,
    -- Lower = preferred. priority=1 is the default WAN; 2..N are backups.
    priority             int                      NOT NULL DEFAULT 100,
    -- Comma-separated IPs to ping. Empty → use gateway.
    monitor_targets      text[]                   NOT NULL DEFAULT '{}',
    -- N consecutive failed cycles before this WAN is marked unhealthy.
    failover_threshold   int                      NOT NULL DEFAULT 3,
    -- N consecutive successful cycles before this WAN is marked healthy again.
    recovery_threshold   int                      NOT NULL DEFAULT 5,
    enabled              boolean                  NOT NULL DEFAULT true,
    created_at           timestamp with time zone NOT NULL DEFAULT now(),
    updated_at           timestamp with time zone NOT NULL DEFAULT now()
);

-- ───────────── current health state (one row per interface) ─────────────
CREATE TABLE IF NOT EXISTS wan_health_state (
    interface_id         uuid                     PRIMARY KEY REFERENCES fw_interfaces(id) ON DELETE CASCADE,
    is_up                boolean                  NOT NULL DEFAULT true,
    consecutive_failures int                      NOT NULL DEFAULT 0,
    consecutive_successes int                     NOT NULL DEFAULT 0,
    last_check_at        timestamp with time zone NOT NULL DEFAULT now(),
    last_transition_at   timestamp with time zone NOT NULL DEFAULT now(),
    last_rtt_ms          double precision,
    last_target          text,
    last_error           text
);

-- ───────────── transition log (only state changes, not every probe) ─────────────
CREATE TABLE IF NOT EXISTS wan_health_events (
    id                   bigserial                PRIMARY KEY,
    occurred_at          timestamp with time zone NOT NULL DEFAULT now(),
    interface_id         uuid                     NOT NULL REFERENCES fw_interfaces(id) ON DELETE CASCADE,
    -- "down" (transitioned to failed), "up" (transitioned back to healthy),
    -- "failover" (we made this WAN the active default), "demoted" (no longer
    -- the active default — a higher-priority WAN recovered).
    event_type           varchar(20)              NOT NULL,
    detail               jsonb,
    CONSTRAINT chk_wan_event_type CHECK (event_type IN ('up','down','failover','demoted'))
);

CREATE INDEX IF NOT EXISTS idx_wan_health_events_occurred ON wan_health_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_wan_health_events_iface    ON wan_health_events (interface_id, occurred_at DESC);

-- ───────────── fw_apply_history kind 'failover' ─────────────
-- Lets the dashboard's "Recent activity" include failover events alongside
-- other apply operations.
ALTER TABLE fw_apply_history DROP CONSTRAINT IF EXISTS chk_apply_kind;
ALTER TABLE fw_apply_history ADD CONSTRAINT chk_apply_kind
    CHECK (kind IN ('nftables','tc','wireguard','routing','failover'));

