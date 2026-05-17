-- Tekium-specific policy routing seed. Translates /root/firewall.sh's iproute2
-- statements into DB rows. Idempotent — re-run safely.
--
-- Run AFTER 00023_policy_routing.sql is applied AND seed_tekium.sql so
-- fw_static_routes already exists.

BEGIN;

-- ───────── named route tables ─────────
INSERT INTO fw_route_tables (table_id, table_name, description) VALUES
    (200, 'wan1', 'Primary WAN (ens192) — fwmark 0x100'),
    (201, 'wan2', 'Secondary WAN (ens224) — fwmark 0x200'),
    (202, 'wg0',  'WireGuard tunnel — fwmark 0x500')
ON CONFLICT (table_id) DO UPDATE
SET table_name = EXCLUDED.table_name,
    description = EXCLUDED.description;

-- ───────── ip rule fwmark X lookup Y ─────────
-- firewall.sh adds these 6 rules; we collapse the duplicates and use one
-- canonical priority block. The kernel walks rules in priority order, so we
-- give them sequential priorities for predictability.
INSERT INTO fw_policy_rules (fwmark, table_name, priority, description) VALUES
    (256,  'wan1', 100, 'Traffic marked 0x100 → wan1'),
    (512,  'wan2', 110, 'Traffic marked 0x200 → wan2'),
    (1280, 'wg0',  120, 'Traffic marked 0x500 → wg0 (VPN)')
ON CONFLICT DO NOTHING;

-- ───────── tie existing default static routes to their tables ─────────
-- seed_tekium.sql inserted 3 default routes (via ens192/ens224/wg0). We now
-- bind each to its table so the route ends up in the right rt_tables ID.
UPDATE fw_static_routes
SET table_id = (SELECT id FROM fw_route_tables WHERE table_name = 'wan1')
WHERE description = 'Default via ens192 (table wan1)';

UPDATE fw_static_routes
SET table_id = (SELECT id FROM fw_route_tables WHERE table_name = 'wan2')
WHERE description = 'Default via ens224 (table wan2)';

UPDATE fw_static_routes
SET table_id = (SELECT id FROM fw_route_tables WHERE table_name = 'wg0')
WHERE description = 'Default via wg0 (table 202)';

COMMIT;

-- Verification queries:
--   SELECT * FROM fw_route_tables ORDER BY table_id;
--   SELECT fwmark, table_name, priority, description FROM fw_policy_rules ORDER BY priority;
--   SELECT sr.description, rt.table_name, sr.destination, sr.gateway
--   FROM fw_static_routes sr LEFT JOIN fw_route_tables rt ON rt.id = sr.table_id
--   ORDER BY rt.table_name;
