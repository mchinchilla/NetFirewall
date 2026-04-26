-- Demo / starter data. NOT auto-applied by the migration runner — apply
-- manually with `psql -f seeds/demo_interfaces.sql` if you want a populated
-- starting point for development. Idempotent via ON CONFLICT.

INSERT INTO fw_interfaces (name, type, role, ip_address, subnet_mask, gateway, enabled)
VALUES
    ('ens192', 'WAN', 'primary_wan',      '10.0.0.1',     '255.255.255.0', '10.0.0.254', true),
    ('ens224', 'WAN', 'secondary_wan',    '10.0.1.1',     '255.255.255.0', '10.0.1.254', true),
    ('ens256', 'LAN', 'local_network',    '192.168.99.1', '255.255.255.0', NULL,         true),
    ('wg0',    'VPN', 'wireguard_tunnel', '10.100.0.1',   '255.255.255.0', NULL,         true)
ON CONFLICT (name) DO NOTHING;

INSERT INTO fw_traffic_marks (name, mark_value, description, route_table)
VALUES
    ('WAN1',          256,  'Primary WAN traffic',   'wan1'),    -- 0x100
    ('WAN2',          512,  'Secondary WAN traffic', 'wan2'),    -- 0x200
    ('VPN',           768,  'VPN traffic',           'vpn'),     -- 0x300
    ('HIGH_PRIORITY', 1280, 'High priority QoS',     NULL)       -- 0x500
ON CONFLICT (mark_value) DO NOTHING;
