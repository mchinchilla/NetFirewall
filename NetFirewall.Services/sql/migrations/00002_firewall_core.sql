-- Firewall core tables: interfaces, traffic marks, static routes.
-- These are referenced by FK from later migrations, so they MUST come first.

CREATE TABLE IF NOT EXISTS fw_interfaces (
    id              uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    name            varchar(50)              NOT NULL UNIQUE,         -- ens192, ens224, eth0, wg0
    type            varchar(20)              NOT NULL,                -- WAN, LAN, VPN
    role            varchar(30),                                       -- primary_wan, secondary_wan, local_network
    ip_address      inet,
    subnet_mask     inet,
    gateway         inet,
    dns_servers     inet[],
    mtu             int,
    vlan_id         int,
    vlan_parent     varchar(50),
    addressing_mode varchar(20)              DEFAULT 'static',        -- static, dhcp, disabled
    metric          int,
    mac_address     varchar(17),
    description     text,
    auto_start      boolean                  DEFAULT true,
    enabled         boolean                  DEFAULT true,
    created_at      timestamp with time zone DEFAULT now(),
    updated_at      timestamp with time zone DEFAULT now()
);

-- Traffic marks for QoS / policy routing (mangle rules + qos classes reference these).
CREATE TABLE IF NOT EXISTS fw_traffic_marks (
    id          uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    name        varchar(50)              NOT NULL,
    mark_value  int                      NOT NULL UNIQUE,             -- 0x100, 0x200, 0x300, 0x500
    description varchar(255),
    route_table varchar(50),                                          -- wan1, wan2, vpn
    created_at  timestamp with time zone DEFAULT now()
);

-- Static routes bound to an interface.
CREATE TABLE IF NOT EXISTS fw_static_routes (
    id           uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    interface_id uuid                     REFERENCES fw_interfaces(id) ON DELETE CASCADE,
    destination  cidr                     NOT NULL,
    gateway      inet,
    metric       int                      DEFAULT 100,
    description  varchar(255),
    enabled      boolean                  DEFAULT true,
    created_at   timestamp with time zone DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_static_routes_iface   ON fw_static_routes(interface_id);
CREATE INDEX IF NOT EXISTS idx_static_routes_enabled ON fw_static_routes(enabled);
