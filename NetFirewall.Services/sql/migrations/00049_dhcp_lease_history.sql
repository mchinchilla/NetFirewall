-- 00049_dhcp_lease_history.sql
-- "Who had 192.168.1.50 last Tuesday?" dhcp_leases keeps only the CURRENT lease per MAC (rows are
-- overwritten / deleted), so history was lost. One row per (MAC, IP) interval: opened on the first
-- lease, last_seen extended at each renewal, closed when the device moves to another address or
-- releases. Written by the DHCP server's lease write-behind (same transaction); kept 90 days.
CREATE TABLE IF NOT EXISTS dhcp_lease_history (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    mac_address macaddr                  NOT NULL,
    ip_address  inet                     NOT NULL,
    hostname    text,
    first_seen  timestamp with time zone NOT NULL,
    last_seen   timestamp with time zone NOT NULL,
    closed_at   timestamp with time zone
);

-- At most one open interval per device.
CREATE UNIQUE INDEX IF NOT EXISTS ux_dhcp_lease_history_open ON dhcp_lease_history (mac_address) WHERE closed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_dhcp_lease_history_ip   ON dhcp_lease_history (ip_address, first_seen DESC);
CREATE INDEX IF NOT EXISTS idx_dhcp_lease_history_seen ON dhcp_lease_history (last_seen);
