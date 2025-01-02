-- Enable the uuid-ossp extension if not already enabled
CREATE
EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create the dhcp_config table for server configuration
drop table if exists dhcp_config cascade;
CREATE TABLE dhcp_config
(
    id             UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ip_range_start INET NOT NULL,
    ip_range_end   INET NOT NULL,
    subnet_mask    INET NOT NULL,
    lease_time     INT  NOT NULL,
    gateway        INET NOT NULL,
    dns_servers    INET[],
    boot_file_name TEXT,
    server_ip      INET,
    server_name    TEXT,
    description    TEXT
);

-- Create the dhcp_leases table for managing IP leases
drop table if exists dhcp_leases cascade;
CREATE TABLE dhcp_leases
(
    id          UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    mac_address MACADDR                  NOT NULL,
    ip_address  INET                     NOT NULL,
    start_time  TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time    TIMESTAMP WITH TIME ZONE NOT NULL,
    hostname    TEXT,
    UNIQUE (mac_address, ip_address)
);

-- Create the mac_reservations table for IP reservations
drop table if exists dhcp_mac_reservations cascade;
CREATE TABLE dhcp_mac_reservations
(
    id          UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    mac_address MACADDR NOT NULL,
    reserved_ip INET    NOT NULL,
    description TEXT,
    UNIQUE (mac_address)
);

-- Add indexes for better performance
CREATE INDEX idx_dhcp_leases_mac_address ON dhcp_leases (mac_address);
CREATE INDEX idx_dhcp_leases_ip_address ON dhcp_leases (ip_address);
CREATE INDEX idx_dhcp_mac_reservations_mac_address ON dhcp_mac_reservations (mac_address);