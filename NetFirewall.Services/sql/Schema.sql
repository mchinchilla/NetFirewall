-- enable the uuid-ossp extension if not already enabled
create extension if not exists "uuid-ossp";

-- ============================================================================
-- DHCP TABLES
-- ============================================================================

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
    unique (mac_address, reserved_ip)
);

-- add indexes for better performance
-- dhcp_leases
create unique index idx_dhcp_leases_mac_address on dhcp_leases (mac_address);
create index idx_dhcp_leases_ip_address on dhcp_leases (ip_address);
create index idx_dhcp_leases_end_time on dhcp_leases (end_time);
-- dhcp_mac_reservations
create index idx_dhcp_mac_reservations_mac_address on dhcp_mac_reservations (mac_address);
create index idx_dhcp_mac_reservations_reserved_ip on dhcp_mac_reservations (reserved_ip);

-- ============================================================================
-- DHCP MULTI-SUBNET TABLES (Advanced Features)
-- ============================================================================

-- DHCP Subnets/Scopes
drop table if exists dhcp_subnets cascade;
create table dhcp_subnets
(
    id                 uuid          default uuid_generate_v4() primary key,
    name               varchar(100)  not null,
    network            cidr          not null,
    subnet_mask        inet          not null,
    router             inet,
    broadcast          inet,
    domain_name        varchar(255),
    dns_servers        inet[],
    ntp_servers        inet[],
    wins_servers       inet[],
    default_lease_time int           default 86400,
    max_lease_time     int           default 604800,
    interface_mtu      int,
    tftp_server        varchar(255),
    boot_filename      varchar(255),
    boot_filename_uefi varchar(255),
    domain_search      text,                          -- Option 119: comma-separated domain list
    static_routes      jsonb,                         -- Option 121: [{"network":"10.0.0.0/8","gateway":"192.168.1.1"}]
    time_offset        int,                           -- Option 2: seconds offset from UTC
    posix_timezone     varchar(100),                  -- Option 100: POSIX TZ string
    interface_name     varchar(50),
    enabled            boolean       default true,
    created_at         timestamp     default now(),
    updated_at         timestamp     default now()
);

-- DHCP Pools within subnets
drop table if exists dhcp_pools cascade;
create table dhcp_pools
(
    id                     uuid        default uuid_generate_v4() primary key,
    subnet_id              uuid        references dhcp_subnets (id) on delete cascade,
    name                   varchar(100),
    range_start            inet        not null,
    range_end              inet        not null,
    allow_unknown_clients  boolean     default true,
    deny_bootp             boolean     default false,
    known_clients_only     boolean     default false,
    priority               int         default 100,
    enabled                boolean     default true,
    created_at             timestamp   default now()
);

-- IP exclusions within subnets
drop table if exists dhcp_exclusions cascade;
create table dhcp_exclusions
(
    id         uuid      default uuid_generate_v4() primary key,
    subnet_id  uuid      references dhcp_subnets (id) on delete cascade,
    ip_start   inet      not null,
    ip_end     inet,
    reason     varchar(255),
    created_at timestamp default now()
);

-- DHCP Client classes for classification
drop table if exists dhcp_classes cascade;
create table dhcp_classes
(
    id               uuid        default uuid_generate_v4() primary key,
    name             varchar(100) not null unique,
    match_type       varchar(50) not null,  -- vendor_class, user_class, mac_prefix, hardware_type
    match_value      varchar(255) not null, -- e.g., 'PXEClient', '00:11:22'
    options          jsonb,                 -- override options for this class
    next_server      inet,                  -- TFTP server override
    boot_filename    varchar(255),          -- boot file override
    priority         int         default 100,
    enabled          boolean     default true,
    created_at       timestamp   default now()
);

-- Pool-class associations (allow/deny classes per pool)
drop table if exists dhcp_pool_classes cascade;
create table dhcp_pool_classes
(
    pool_id  uuid references dhcp_pools (id) on delete cascade,
    class_id uuid references dhcp_classes (id) on delete cascade,
    allow    boolean default true,
    primary key (pool_id, class_id)
);

-- DHCP Options (custom options per subnet/pool/class)
drop table if exists dhcp_custom_options cascade;
create table dhcp_custom_options
(
    id            uuid        default uuid_generate_v4() primary key,
    scope_type    varchar(20) not null,  -- global, subnet, pool, class, host
    scope_id      uuid,                  -- references the scope (null for global)
    option_code   smallint    not null,
    option_name   varchar(100),
    option_value  bytea       not null,  -- raw option data
    option_format varchar(20),           -- ip, ip_list, string, uint8, uint16, uint32, boolean
    created_at    timestamp   default now()
);

-- DHCP relay agents
drop table if exists dhcp_relay_agents cascade;
create table dhcp_relay_agents
(
    id            uuid        default uuid_generate_v4() primary key,
    ip_address    inet        not null unique,
    description   varchar(255),
    trusted       boolean     default true,
    created_at    timestamp   default now()
);

-- DHCP failover peers (for high availability)
drop table if exists dhcp_failover_peers cascade;
create table dhcp_failover_peers
(
    id                  uuid        default uuid_generate_v4() primary key,
    name                varchar(100) not null unique,
    role                varchar(20) not null,  -- primary, secondary
    peer_address        inet        not null,
    peer_port           int         default 647,
    local_address       inet,
    local_port          int         default 647,
    max_response_delay  int         default 60,
    max_unacked_updates int         default 10,
    mclt                int         default 3600,  -- maximum client lead time
    split               int         default 128,   -- 0-255 split ratio
    load_balance_max    int         default 3,
    auto_partner_down   int         default 0,     -- seconds to wait before auto partner-down (0 = disabled)
    shared_secret       text,                      -- optional authentication secret
    enabled             boolean     default false,
    created_at          timestamp   default now()
);

-- DHCP failover runtime state
drop table if exists dhcp_failover_state cascade;
create table dhcp_failover_state
(
    peer_id             uuid        primary key references dhcp_failover_peers(id) on delete cascade,
    state               int         not null default 0,  -- FailoverState enum value
    peer_state          int         default 0,
    last_contact        timestamp,
    state_changed_at    timestamp   default now(),
    updated_at          timestamp   default now()
);

-- Failover binding log for synchronization tracking
drop table if exists dhcp_failover_bindings cascade;
create table dhcp_failover_bindings
(
    id                  uuid        default uuid_generate_v4() primary key,
    ip_address          inet        not null,
    mac_address         macaddr     not null,
    binding_state       int         not null,  -- FailoverBindingState enum
    start_time          timestamp   not null,
    end_time            timestamp   not null,
    cltt                timestamp,              -- Client Last Transaction Time
    stos                bigint,                 -- Start Time of State (epoch)
    pending_ack         boolean     default false,
    synced              boolean     default false,
    created_at          timestamp   default now(),
    unique (ip_address)
);

create index idx_failover_bindings_pending on dhcp_failover_bindings (pending_ack) where pending_ack = true;
create index idx_failover_bindings_synced on dhcp_failover_bindings (synced) where synced = false;

-- DHCP lease events/hooks
drop table if exists dhcp_events cascade;
create table dhcp_events
(
    id           uuid        default uuid_generate_v4() primary key,
    event_type   varchar(20) not null,  -- commit, release, expiry, decline
    script_path  varchar(500),
    script_args  text[],
    enabled      boolean     default true,
    created_at   timestamp   default now()
);

-- DDNS (Dynamic DNS) configuration - RFC 2136
drop table if exists dhcp_ddns_config cascade;
create table dhcp_ddns_config
(
    id                     uuid        default uuid_generate_v4() primary key,
    subnet_id              uuid        references dhcp_subnets (id) on delete cascade,  -- null = global config
    enable_forward         boolean     default true,           -- A record updates
    enable_reverse         boolean     default true,           -- PTR record updates
    forward_zone           varchar(255),                       -- e.g., "example.com"
    reverse_zone           varchar(255),                       -- e.g., "1.168.192.in-addr.arpa" (auto-generated if null)
    dns_server             inet        not null,               -- Primary DNS server for updates
    dns_port               int         default 53,
    tsig_key_name          varchar(255),                       -- TSIG key name for authentication
    tsig_key_secret        text,                               -- TSIG key secret (Base64)
    tsig_algorithm         varchar(50) default 'hmac-sha256',  -- hmac-md5, hmac-sha1, hmac-sha256, hmac-sha512
    ttl                    int         default 300,            -- DNS record TTL
    update_style           varchar(20) default 'standard',     -- standard, interim, none
    override_client_update boolean     default false,          -- Override client's FQDN option
    allow_client_updates   boolean     default false,          -- Let client do its own A record update
    conflict_resolution    varchar(30) default 'check-with-dhcid',  -- check-with-dhcid, no-check, fail-on-conflict
    enabled                boolean     default true,
    created_at             timestamp   default now(),
    updated_at             timestamp   default now()
);

-- DDNS update log for troubleshooting
drop table if exists dhcp_ddns_log cascade;
create table dhcp_ddns_log
(
    id           uuid        default uuid_generate_v4() primary key,
    lease_id     uuid,
    action       varchar(20) not null,  -- add_forward, add_reverse, remove_forward, remove_reverse
    hostname     varchar(255),
    ip_address   inet,
    fqdn         varchar(255),
    success      boolean     not null,
    error_msg    text,
    dns_server   inet,
    created_at   timestamp   default now()
);

-- Indexes for DDNS tables
create index idx_ddns_config_subnet on dhcp_ddns_config (subnet_id);
create index idx_ddns_log_lease on dhcp_ddns_log (lease_id, created_at);
create index idx_ddns_log_created on dhcp_ddns_log (created_at);

-- Indexes for new tables
create index idx_dhcp_subnets_network on dhcp_subnets using gist (network inet_ops);
create index idx_dhcp_subnets_enabled on dhcp_subnets (enabled);
create index idx_dhcp_pools_subnet on dhcp_pools (subnet_id, enabled, priority);
create index idx_dhcp_pools_range on dhcp_pools (range_start, range_end);
create index idx_dhcp_exclusions_subnet on dhcp_exclusions (subnet_id);
create index idx_dhcp_classes_match on dhcp_classes (match_type, match_value);
create index idx_dhcp_custom_options_scope on dhcp_custom_options (scope_type, scope_id);

-- ============================================================================
-- FIREWALL TABLES
-- ============================================================================

-- Network interfaces configuration
drop table if exists fw_interfaces cascade;
create table fw_interfaces
(
    id          uuid        default uuid_generate_v4() primary key,
    name        varchar(50) not null unique,              -- ens192, ens224, ens256, wg0
    type        varchar(20) not null,                     -- WAN, LAN, VPN
    role        varchar(30),                              -- primary_wan, secondary_wan, local_network
    ip_address  inet,
    subnet_mask inet,
    gateway     inet,
    enabled     boolean     default true,
    created_at  timestamp   default now(),
    updated_at  timestamp   default now()
);

-- Traffic marks for QoS/Routing (referenced by other tables)
drop table if exists fw_traffic_marks cascade;
create table fw_traffic_marks
(
    id          uuid        default uuid_generate_v4() primary key,
    name        varchar(50) not null,
    mark_value  int         not null unique,              -- 0x100, 0x200, 0x300, 0x500
    description varchar(255),
    route_table varchar(50),                              -- wan1, wan2, vpn
    created_at  timestamp   default now()
);

-- Port Forwarding rules (DNAT)
drop table if exists fw_port_forwards cascade;
create table fw_port_forwards
(
    id                  uuid        default uuid_generate_v4() primary key,
    description         varchar(255),
    protocol            varchar(10) not null,             -- tcp, udp, tcp/udp
    interface_id        uuid references fw_interfaces (id) on delete set null,
    source_addresses    text[],                           -- IPs/CIDRs permitted (null = any)
    external_port_start int         not null,
    external_port_end   int,                              -- null = single port
    internal_ip         inet        not null,
    internal_port       int         not null,
    enabled             boolean     default true,
    priority            int         default 100,
    created_at          timestamp   default now()
);

-- Filter rules (Input/Forward/Output)
drop table if exists fw_filter_rules cascade;
create table fw_filter_rules
(
    id                    uuid        default uuid_generate_v4() primary key,
    chain                 varchar(20) not null,           -- input, forward, output
    description           varchar(255),
    action                varchar(20) not null,           -- accept, drop, reject, log
    protocol              varchar(10),                    -- tcp, udp, icmp, null = any
    interface_in_id       uuid references fw_interfaces (id) on delete set null,
    interface_out_id      uuid references fw_interfaces (id) on delete set null,
    source_addresses      text[],
    destination_addresses text[],
    destination_ports     text[],                         -- ['22', '80', '443', '8000-9000']
    connection_state      text[],                         -- ['new', 'established', 'related']
    rate_limit            varchar(50),                    -- '60/minute', '10/second'
    log_prefix            varchar(50),
    enabled               boolean     default true,
    priority              int         default 100,
    created_at            timestamp   default now()
);

-- NAT rules (SNAT/Masquerade)
drop table if exists fw_nat_rules cascade;
create table fw_nat_rules
(
    id                  uuid        default uuid_generate_v4() primary key,
    type                varchar(20) not null,             -- masquerade, snat
    description         varchar(255),
    source_network      cidr        not null,
    output_interface_id uuid references fw_interfaces (id) on delete set null,
    snat_address        inet,                             -- only for SNAT
    enabled             boolean     default true,
    priority            int         default 100,
    created_at          timestamp   default now()
);

-- Mangle rules (traffic marking for QoS/Routing)
drop table if exists fw_mangle_rules cascade;
create table fw_mangle_rules
(
    id                    uuid        default uuid_generate_v4() primary key,
    chain                 varchar(20) not null,           -- prerouting, postrouting
    description           varchar(255),
    mark_id               uuid references fw_traffic_marks (id) on delete set null,
    protocol              varchar(10),
    source_addresses      text[],
    destination_addresses text[],
    destination_ports     text[],
    enabled               boolean     default true,
    priority              int         default 100,
    created_at            timestamp   default now()
);

-- QoS configuration per interface
drop table if exists fw_qos_config cascade;
create table fw_qos_config
(
    id                   uuid      default uuid_generate_v4() primary key,
    interface_id         uuid references fw_interfaces (id) on delete cascade,
    enabled              boolean   default true,
    total_bandwidth_mbps int       not null,
    created_at           timestamp default now(),
    unique (interface_id)
);

-- QoS classes (HTB hierarchy)
drop table if exists fw_qos_classes cascade;
create table fw_qos_classes
(
    id              uuid        default uuid_generate_v4() primary key,
    qos_config_id   uuid references fw_qos_config (id) on delete cascade,
    name            varchar(50) not null,                 -- high, normal, low
    mark_id         uuid references fw_traffic_marks (id) on delete set null,
    guaranteed_mbps int         not null,
    ceiling_mbps    int         not null,
    priority        int         not null,                 -- 1=highest
    created_at      timestamp   default now()
);

-- Audit log for tracking all firewall configuration changes
drop table if exists fw_audit_log cascade;
create table fw_audit_log
(
    id         uuid        default uuid_generate_v4() primary key,
    table_name varchar(50) not null,
    record_id  uuid        not null,
    action     varchar(20) not null,                      -- INSERT, UPDATE, DELETE
    old_values jsonb,
    new_values jsonb,
    user_id    varchar(100),
    created_at timestamp   default now()
);

-- ============================================================================
-- FIREWALL INDEXES
-- ============================================================================

-- Filter rules indexes
create index idx_fw_filter_rules_chain on fw_filter_rules (chain, enabled, priority);
create index idx_fw_filter_rules_enabled on fw_filter_rules (enabled);

-- Port forwards indexes
create index idx_fw_port_forwards_enabled on fw_port_forwards (enabled, priority);
create index idx_fw_port_forwards_interface on fw_port_forwards (interface_id);

-- NAT rules indexes
create index idx_fw_nat_rules_enabled on fw_nat_rules (enabled, priority);
create index idx_fw_nat_rules_interface on fw_nat_rules (output_interface_id);

-- Mangle rules indexes
create index idx_fw_mangle_rules_chain on fw_mangle_rules (chain, enabled, priority);
create index idx_fw_mangle_rules_mark on fw_mangle_rules (mark_id);

-- QoS indexes
create index idx_fw_qos_classes_config on fw_qos_classes (qos_config_id);

-- Audit log indexes
create index idx_fw_audit_log_table on fw_audit_log (table_name, created_at);
create index idx_fw_audit_log_record on fw_audit_log (record_id);
create index idx_fw_audit_log_created on fw_audit_log (created_at);

-- ============================================================================
-- SEED DATA
-- ============================================================================

-- Insert default interfaces
insert into fw_interfaces (name, type, role, ip_address, subnet_mask, gateway, enabled)
values ('ens192', 'WAN', 'primary_wan', '10.0.0.1', '255.255.255.0', '10.0.0.254', true),
       ('ens224', 'WAN', 'secondary_wan', '10.0.1.1', '255.255.255.0', '10.0.1.254', true),
       ('ens256', 'LAN', 'local_network', '192.168.99.1', '255.255.255.0', null, true),
       ('wg0', 'VPN', 'wireguard_tunnel', '10.100.0.1', '255.255.255.0', null, true);

-- Insert default traffic marks
insert into fw_traffic_marks (name, mark_value, description, route_table)
values ('WAN1', 256, 'Primary WAN traffic', 'wan1'),    -- 0x100
       ('WAN2', 512, 'Secondary WAN traffic', 'wan2'),  -- 0x200
       ('VPN', 768, 'VPN traffic', 'vpn'),              -- 0x300
       ('HIGH_PRIORITY', 1280, 'High priority QoS', null); -- 0x500

-- Insert default NAT masquerade rules
insert into fw_nat_rules (type, description, source_network, output_interface_id, enabled, priority)
select 'masquerade',
       'Masquerade LAN to ' || fi.name,
       '192.168.99.0/24'::cidr,
       fi.id,
       true,
       100
from fw_interfaces fi
where fi.type = 'WAN';

-- Insert default filter rules (basic stateful firewall)
insert into fw_filter_rules (chain, description, action, protocol, connection_state, enabled, priority)
values ('input', 'Allow established/related connections', 'accept', null, ARRAY ['established', 'related'], true, 10),
       ('forward', 'Allow established/related connections', 'accept', null, ARRAY ['established', 'related'], true, 10),
       ('input', 'Allow ICMP ping', 'accept', 'icmp', null, true, 50),
       ('input', 'Allow SSH', 'accept', 'tcp', ARRAY ['new'], true, 100);

-- Update the SSH rule to include port
update fw_filter_rules
set destination_ports = ARRAY ['22']
where description = 'Allow SSH';

-- Insert default input drop rule (should be last)
insert into fw_filter_rules (chain, description, action, protocol, enabled, priority)
values ('input', 'Drop all other input', 'drop', null, true, 1000);

-- Insert DHCP allow rule for LAN
insert into fw_filter_rules (chain, description, action, protocol, destination_ports, interface_in_id, enabled,
                             priority)
select 'input',
       'Allow DHCP on LAN',
       'accept',
       'udp',
       ARRAY ['67', '68'],
       fi.id,
       true,
       20
from fw_interfaces fi
where fi.role = 'local_network';

-- ============================================================================
-- NETWORK INTERFACE EXTENSIONS
-- ============================================================================

-- Extend fw_interfaces with additional configuration fields
ALTER TABLE fw_interfaces ADD COLUMN IF NOT EXISTS dns_servers inet[];
ALTER TABLE fw_interfaces ADD COLUMN IF NOT EXISTS mtu int;
ALTER TABLE fw_interfaces ADD COLUMN IF NOT EXISTS vlan_id int;
ALTER TABLE fw_interfaces ADD COLUMN IF NOT EXISTS vlan_parent varchar(50);
ALTER TABLE fw_interfaces ADD COLUMN IF NOT EXISTS addressing_mode varchar(20) DEFAULT 'static';
ALTER TABLE fw_interfaces ADD COLUMN IF NOT EXISTS metric int;
ALTER TABLE fw_interfaces ADD COLUMN IF NOT EXISTS mac_address varchar(17);
ALTER TABLE fw_interfaces ADD COLUMN IF NOT EXISTS description text;
ALTER TABLE fw_interfaces ADD COLUMN IF NOT EXISTS auto_start boolean DEFAULT true;

-- Static routes table for interface-specific routing
CREATE TABLE IF NOT EXISTS fw_static_routes (
    id uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
    interface_id uuid REFERENCES fw_interfaces(id) ON DELETE CASCADE,
    destination cidr NOT NULL,
    gateway inet,
    metric int DEFAULT 100,
    description varchar(255),
    enabled boolean DEFAULT true,
    created_at timestamp DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_static_routes_iface ON fw_static_routes(interface_id);
CREATE INDEX IF NOT EXISTS idx_static_routes_enabled ON fw_static_routes(enabled);

-- ============================================================================
-- DHCP SUBNET INTERFACE FK MIGRATION
-- ============================================================================

-- Add interface_id FK to dhcp_subnets (replaces interface_name)
ALTER TABLE dhcp_subnets ADD COLUMN IF NOT EXISTS interface_id uuid REFERENCES fw_interfaces(id) ON DELETE SET NULL;

-- Create index for the FK
CREATE INDEX IF NOT EXISTS idx_dhcp_subnets_interface ON dhcp_subnets(interface_id);

-- Migrate existing interface_name data to interface_id (if any)
UPDATE dhcp_subnets ds
SET interface_id = fi.id
FROM fw_interfaces fi
WHERE ds.interface_name = fi.name
  AND ds.interface_id IS NULL
  AND ds.interface_name IS NOT NULL;

-- ============================================================================
-- SETUP WIZARD
-- ============================================================================

-- Setup wizard state tracking
CREATE TABLE IF NOT EXISTS setup_wizard_state (
    id              uuid        DEFAULT uuid_generate_v4() PRIMARY KEY,
    current_step    int         NOT NULL DEFAULT 1,
    is_completed    boolean     NOT NULL DEFAULT false,

    -- Step 1: Interfaces configuration (JSON snapshot)
    interfaces_config   jsonb,

    -- Step 2: LAN/DHCP configuration (JSON snapshot)
    lan_config          jsonb,

    -- Step 3: Firewall rules configuration (JSON snapshot)
    firewall_config     jsonb,

    -- Step 4: Optional services (JSON snapshot)
    services_config     jsonb,

    started_at      timestamp   DEFAULT now(),
    completed_at    timestamp,
    updated_at      timestamp   DEFAULT now()
);

-- Ensure only one wizard state row exists
CREATE UNIQUE INDEX IF NOT EXISTS idx_setup_wizard_singleton ON setup_wizard_state ((true));
