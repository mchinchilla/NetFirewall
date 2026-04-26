-- Legacy single-subnet DHCP tables (kept for backward compat with the early DHCP server).
-- New deployments rely on the multi-subnet model in 00006_dhcp_subnets_pools.

CREATE TABLE IF NOT EXISTS dhcp_config (
    id             uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
    ip_range_start inet NOT NULL,
    ip_range_end   inet NOT NULL,
    subnet_mask    inet NOT NULL,
    lease_time     int  NOT NULL,
    gateway        inet NOT NULL,
    dns_servers    inet[],
    boot_file_name text,
    server_ip      inet,
    server_name    text,
    description    text
);

CREATE TABLE IF NOT EXISTS dhcp_leases (
    id          uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    mac_address macaddr                  NOT NULL,
    ip_address  inet                     NOT NULL,
    start_time  timestamp with time zone NOT NULL,
    end_time    timestamp with time zone NOT NULL,
    hostname    text,
    UNIQUE (mac_address, ip_address)
);

CREATE TABLE IF NOT EXISTS dhcp_mac_reservations (
    id          uuid    DEFAULT uuid_generate_v4() PRIMARY KEY,
    mac_address macaddr NOT NULL UNIQUE,
    reserved_ip inet    NOT NULL UNIQUE,
    description text
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_dhcp_leases_mac_address ON dhcp_leases(mac_address);
CREATE INDEX IF NOT EXISTS idx_dhcp_leases_ip_address         ON dhcp_leases(ip_address);
CREATE INDEX IF NOT EXISTS idx_dhcp_leases_end_time           ON dhcp_leases(end_time);
