-- WAN health config for tekium: ens192 as primary (priority 1), ens224 as
-- backup (priority 2). Both monitored against 8.8.8.8 + 1.1.1.1. Failover
-- after 3 consecutive failures (~90s @ 30s probe interval). Recovery after
-- 5 consecutive successes (~150s).

BEGIN;

INSERT INTO wan_health_config
    (interface_id, priority, monitor_targets, failover_threshold, recovery_threshold)
SELECT id, 1, ARRAY['8.8.8.8','1.1.1.1'], 3, 5
FROM fw_interfaces WHERE name = 'ens192'
ON CONFLICT (interface_id) DO UPDATE
SET priority           = EXCLUDED.priority,
    monitor_targets    = EXCLUDED.monitor_targets,
    failover_threshold = EXCLUDED.failover_threshold,
    recovery_threshold = EXCLUDED.recovery_threshold;

INSERT INTO wan_health_config
    (interface_id, priority, monitor_targets, failover_threshold, recovery_threshold)
SELECT id, 2, ARRAY['8.8.8.8','1.1.1.1'], 3, 5
FROM fw_interfaces WHERE name = 'ens224'
ON CONFLICT (interface_id) DO UPDATE
SET priority           = EXCLUDED.priority,
    monitor_targets    = EXCLUDED.monitor_targets,
    failover_threshold = EXCLUDED.failover_threshold,
    recovery_threshold = EXCLUDED.recovery_threshold;

COMMIT;
