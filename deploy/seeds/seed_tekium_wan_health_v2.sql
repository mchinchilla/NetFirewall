-- WAN health config v2: ping via fwmark so the probe honors policy routing.
-- Without -m, `ping -I ens224 8.8.8.8` still egresses through ens192 (because
-- the kernel respects the main table's default route). With -m, the kernel
-- matches `ip rule fwmark 0xN lookup wanN` and the probe pins to the right WAN.
--
-- fwmark values must match fw_policy_rules:
--   ens192 → 0x100 = 256
--   ens224 → 0x200 = 512

BEGIN;

UPDATE wan_health_config
   SET probe_fwmark = 256,
       monitor_targets = ARRAY['8.8.8.8','1.1.1.1']
 WHERE interface_id = (SELECT id FROM fw_interfaces WHERE name = 'ens192');

UPDATE wan_health_config
   SET probe_fwmark = 512,
       monitor_targets = ARRAY['8.8.8.8','1.1.1.1']
 WHERE interface_id = (SELECT id FROM fw_interfaces WHERE name = 'ens224');

-- Verify
SELECT i.name, c.priority, c.probe_fwmark, c.monitor_targets
FROM wan_health_config c JOIN fw_interfaces i ON i.id = c.interface_id
ORDER BY c.priority;

COMMIT;
