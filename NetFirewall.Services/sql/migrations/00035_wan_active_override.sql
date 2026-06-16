-- Persist the currently-active WAN and an optional manual override.
--
-- Two needs the dashboard exposed after the 2026-06-16 incident:
--   1. "Which WAN is active right now?" — previously only tracked in the
--      monitor's in-memory _activeInterfaceId, invisible to the UI and lost on
--      restart.
--   2. "Let me pin a WAN as active and have the monitor respect it" — a STICKY
--      manual override: the operator forces WAN X, and the monitor keeps X as
--      the default route regardless of priority UNTIL X goes unhealthy, at which
--      point the override auto-clears and normal priority failover resumes.
--
-- Single-row table (enforced by a fixed PK). interface_id NULL = no override /
-- auto mode. active_interface_id is the WAN the monitor last made the default
-- route — it's a cache for the UI, the kernel routing table remains the source
-- of truth and the monitor re-primes from it on startup.


CREATE TABLE IF NOT EXISTS wan_failover_control (
    -- Singleton guard: only one row, always id = true.
    id                   boolean                  PRIMARY KEY DEFAULT true,
    CONSTRAINT chk_wan_control_singleton CHECK (id = true),

    -- Manual sticky override. NULL = auto (priority-based). When set, the
    -- monitor keeps this interface active while it stays healthy.
    override_interface_id uuid                    REFERENCES fw_interfaces(id) ON DELETE SET NULL,
    override_set_by       varchar(100),
    override_set_at       timestamp with time zone,

    -- Last interface the monitor made the active default route (UI cache).
    active_interface_id   uuid                    REFERENCES fw_interfaces(id) ON DELETE SET NULL,
    active_since          timestamp with time zone,

    updated_at            timestamp with time zone NOT NULL DEFAULT now()
);

-- Seed the singleton row in auto mode.
INSERT INTO wan_failover_control (id) VALUES (true)
ON CONFLICT (id) DO NOTHING;
