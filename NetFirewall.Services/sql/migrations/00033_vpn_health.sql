-- VPN (WireGuard) health monitoring — the daemon's VpnHealthMonitorService polls
-- `wg show <iface> dump` on a timer, applies hysteresis to the per-peer handshake
-- age, and records up/down transitions here. Mirrors the wan_health_* design
-- (migration 00025): persistent state survives daemon restarts, and a transition
-- log feeds the dashboard + notifications.
--
-- Why a DB table and not just the live `wg show`: the live dump only tells you
-- the *current* handshake age. To say "the tunnel WENT down" (and notify once,
-- not every poll) we need the previous verdict + a consecutive-failure counter,
-- and we want it to outlive a daemon restart.
--
-- Keyed by (server_id, public_key) rather than the wg_peers UUID: `wg show` only
-- gives us the peer's public key, and an imported/desynced peer might not have a
-- catalog row yet. public_key is the stable identity wg itself uses.


-- ───────────── current health state (one row per peer) ─────────────
CREATE TABLE IF NOT EXISTS vpn_health_state (
    server_id             uuid                     NOT NULL REFERENCES wg_servers(id) ON DELETE CASCADE,
    public_key            text                     NOT NULL,
    -- Cooked verdict: true until consecutive_failures crosses the threshold.
    is_up                 boolean                  NOT NULL DEFAULT true,
    consecutive_failures  int                      NOT NULL DEFAULT 0,
    consecutive_successes int                      NOT NULL DEFAULT 0,
    last_check_at         timestamp with time zone NOT NULL DEFAULT now(),
    last_transition_at    timestamp with time zone NOT NULL DEFAULT now(),
    -- Last handshake wg reported (NULL = never). Drives the staleness check.
    last_handshake_at     timestamp with time zone,
    last_endpoint         text,
    PRIMARY KEY (server_id, public_key)
);

-- ───────────── transition log (only state changes, not every probe) ─────────────
CREATE TABLE IF NOT EXISTS vpn_health_events (
    id                    bigserial                PRIMARY KEY,
    occurred_at           timestamp with time zone NOT NULL DEFAULT now(),
    server_id             uuid                     NOT NULL REFERENCES wg_servers(id) ON DELETE CASCADE,
    public_key            text                     NOT NULL,
    -- "down" (handshake went stale past the threshold), "up" (handshake recovered).
    event_type            varchar(20)              NOT NULL,
    detail                jsonb,
    CONSTRAINT chk_vpn_event_type CHECK (event_type IN ('up','down'))
);

CREATE INDEX IF NOT EXISTS idx_vpn_health_events_occurred ON vpn_health_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_vpn_health_events_peer     ON vpn_health_events (server_id, public_key, occurred_at DESC);

-- ───────────── active UI alerts (banner feed) ─────────────
-- A tiny, self-clearing alert store the Web's notification banner reads. The
-- monitor INSERTs an unresolved row on a down transition and stamps resolved_at
-- on recovery. The banner shows any row with resolved_at IS NULL. Generic on
-- purpose (source/severity) so WAN/DHCP can reuse it later — VPN is the first
-- producer.
CREATE TABLE IF NOT EXISTS system_alerts (
    id            bigserial                PRIMARY KEY,
    source        varchar(40)              NOT NULL,            -- e.g. 'vpn'
    severity      varchar(20)              NOT NULL DEFAULT 'danger',  -- danger | warning | info
    -- Stable key so we upsert one row per logical condition instead of piling up
    -- duplicates across polls (e.g. 'vpn:<server_id>:<public_key>').
    dedupe_key    text                     NOT NULL UNIQUE,
    title         text                     NOT NULL,
    body          text,
    raised_at     timestamp with time zone NOT NULL DEFAULT now(),
    resolved_at   timestamp with time zone,
    CONSTRAINT chk_alert_severity CHECK (severity IN ('danger','warning','info'))
);

CREATE INDEX IF NOT EXISTS idx_system_alerts_active ON system_alerts (raised_at DESC) WHERE resolved_at IS NULL;
