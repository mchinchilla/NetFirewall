-- Multi-subnet DHCP model: subnets, pools, exclusions, classes, pool↔class mapping.

CREATE TABLE IF NOT EXISTS dhcp_subnets (
    id                 uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    name               varchar(100)             NOT NULL,
    network            cidr                     NOT NULL,
    subnet_mask        inet                     NOT NULL,
    router             inet,
    broadcast          inet,
    domain_name        varchar(255),
    dns_servers        inet[],
    ntp_servers        inet[],
    wins_servers       inet[],
    default_lease_time int                      DEFAULT 86400,
    max_lease_time     int                      DEFAULT 604800,
    interface_mtu      int,
    tftp_server        varchar(255),
    boot_filename      varchar(255),
    boot_filename_uefi varchar(255),
    domain_search      text,                                          -- Option 119
    static_routes      jsonb,                                         -- Option 121
    time_offset        int,                                           -- Option 2
    posix_timezone     varchar(100),                                  -- Option 100
    interface_name     varchar(50),                                   -- legacy textual binding
    interface_id       uuid                     REFERENCES fw_interfaces(id) ON DELETE SET NULL,
    enabled            boolean                  DEFAULT true,
    created_at         timestamp with time zone DEFAULT now(),
    updated_at         timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dhcp_pools (
    id                    uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    subnet_id             uuid                     REFERENCES dhcp_subnets(id) ON DELETE CASCADE,
    name                  varchar(100),
    range_start           inet                     NOT NULL,
    range_end             inet                     NOT NULL,
    allow_unknown_clients boolean                  DEFAULT true,
    deny_bootp            boolean                  DEFAULT false,
    known_clients_only    boolean                  DEFAULT false,
    priority              int                      DEFAULT 100,
    enabled               boolean                  DEFAULT true,
    created_at            timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dhcp_exclusions (
    id         uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    subnet_id  uuid                     REFERENCES dhcp_subnets(id) ON DELETE CASCADE,
    ip_start   inet                     NOT NULL,
    ip_end     inet,
    reason     varchar(255),
    created_at timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dhcp_classes (
    id            uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    name          varchar(100)             NOT NULL UNIQUE,
    match_type    varchar(50)              NOT NULL,                  -- vendor_class, user_class, mac_prefix, hardware_type
    match_value   varchar(255)             NOT NULL,                  -- e.g. 'PXEClient', '00:11:22'
    options       jsonb,                                              -- override options for this class
    next_server   inet,                                               -- TFTP server override
    boot_filename varchar(255),                                       -- boot file override
    priority      int                      DEFAULT 100,
    enabled       boolean                  DEFAULT true,
    created_at    timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dhcp_pool_classes (
    pool_id  uuid    REFERENCES dhcp_pools(id)   ON DELETE CASCADE,
    class_id uuid    REFERENCES dhcp_classes(id) ON DELETE CASCADE,
    allow    boolean DEFAULT true,
    PRIMARY KEY (pool_id, class_id)
);

CREATE INDEX IF NOT EXISTS idx_dhcp_subnets_network    ON dhcp_subnets USING gist (network inet_ops);
CREATE INDEX IF NOT EXISTS idx_dhcp_subnets_enabled    ON dhcp_subnets(enabled);
CREATE INDEX IF NOT EXISTS idx_dhcp_subnets_interface  ON dhcp_subnets(interface_id);
CREATE INDEX IF NOT EXISTS idx_dhcp_pools_subnet       ON dhcp_pools(subnet_id, enabled, priority);
CREATE INDEX IF NOT EXISTS idx_dhcp_pools_range        ON dhcp_pools(range_start, range_end);
CREATE INDEX IF NOT EXISTS idx_dhcp_exclusions_subnet  ON dhcp_exclusions(subnet_id);
CREATE INDEX IF NOT EXISTS idx_dhcp_classes_match      ON dhcp_classes(match_type, match_value);
