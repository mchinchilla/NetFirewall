-- Auto-seed wan_health_config from the interface catalog.
--
-- ROOT CAUSE of the 2026-06-16 failover incident: wan_health_config was born
-- empty (00025 created the table but seeded nothing). The daemon's
-- WanHealthMonitorService bails on the first line of its tick —
-- `if (configs.Count == 0) return;` — so with no rows it NEVER probes and NEVER
-- fails over. A primary WAN died and the secondary was never promoted because
-- the monitor had no work configured.
--
-- This migration arms failover automatically: one health-config row per WAN
-- interface that has a primary/secondary role, so a fresh deploy (or a host
-- catching up on migrations) gets working failover without any manual SQL.
--
--   priority      1 for primary_wan, 2 for secondary_wan (lower = preferred).
--   monitor_targets  left empty → the monitor pings the interface's gateway.
--   probe_fwmark  best-effort: if the interface routes into exactly one named
--                 table that a policy rule marks (fw_static_routes.table_id →
--                 fw_route_tables → fw_policy_rules.fwmark), use that mark so
--                 probes egress the correct WAN under fwmark policy routing.
--                 Otherwise NULL (falls back to `ping -I`; the operator can set
--                 the right mark later in the WAN UI).
--
-- Idempotent: ON CONFLICT (interface_id) DO NOTHING. Re-running never clobbers
-- an operator's hand-tuned thresholds/targets/fwmark. New WAN interfaces added
-- after this migration are seeded by the application layer (the WAN UI), not
-- here — a forward-only migration only seeds what exists at apply time.


INSERT INTO wan_health_config (interface_id, priority, monitor_targets, probe_fwmark, enabled)
SELECT
    i.id,
    CASE WHEN i.role = 'primary_wan' THEN 1 ELSE 2 END        AS priority,
    '{}'::text[]                                              AS monitor_targets,
    (
        -- The fwmark reaching this interface's named routing table — but ONLY
        -- when the mapping is unambiguous. Aggregating to a single row and
        -- returning min(fwmark) only when there's exactly one DISTINCT mark
        -- means: 0 marks → NULL, >1 marks → NULL, exactly 1 → that mark. We
        -- never silently guess the wrong WAN's mark (which would make probes
        -- egress the wrong interface and defeat failover detection).
        SELECT CASE WHEN count(DISTINCT pr.fwmark) = 1 THEN min(pr.fwmark) END
        FROM fw_static_routes sr
        JOIN fw_route_tables  rt ON rt.id = sr.table_id
        JOIN fw_policy_rules  pr ON pr.table_name = rt.table_name AND pr.enabled = true
        WHERE sr.interface_id = i.id AND sr.table_id IS NOT NULL
    )                                                          AS probe_fwmark,
    true                                                       AS enabled
FROM fw_interfaces i
WHERE i.type = 'WAN'
  AND i.role IN ('primary_wan', 'secondary_wan')
ON CONFLICT (interface_id) DO NOTHING;
