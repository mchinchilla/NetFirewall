-- enable the uuid-ossp extension if not already enabled
create extension if not exists "uuid-ossp";

-- create the dhcp_config table for server configuration
drop table if exists dhcp_config cascade;
create table dhcp_config
(
    id             uuid default uuid_generate_v4() primary key,
    ip_range_start inet not null,
    ip_range_end   inet not null,
    subnet_mask    inet not null,
    lease_time     int  not null,
    gateway        inet not null,
    dns_servers    inet[],
    boot_file_name text,
    server_ip      inet,
    server_name    text,
    description    text
);

-- create the dhcp_leases table for managing ip leases
drop table if exists dhcp_leases cascade;
create table dhcp_leases
(
    id          uuid default uuid_generate_v4() primary key,
    mac_address macaddr                  not null,
    ip_address  inet                     not null,
    start_time  timestamp with time zone not null,
    end_time    timestamp with time zone not null,
    hostname    text,
    unique (mac_address, ip_address)
);

-- create the mac_reservations table for ip reservations
drop table if exists dhcp_mac_reservations cascade;
create table dhcp_mac_reservations
(
    id          uuid default uuid_generate_v4() primary key,
    mac_address macaddr not null,
    reserved_ip inet    not null,
    description text,
    unique (mac_address)
);

-- add indexes for better performance
create index idx_dhcp_leases_mac_address on dhcp_leases (mac_address);
create index idx_dhcp_leases_ip_address on dhcp_leases (ip_address);
create index idx_dhcp_mac_reservations_mac_address on dhcp_mac_reservations (mac_address);