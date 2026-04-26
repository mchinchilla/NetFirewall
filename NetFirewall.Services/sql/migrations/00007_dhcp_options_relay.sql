-- Custom DHCP options (per scope) and relay agent registry.

CREATE TABLE IF NOT EXISTS dhcp_custom_options (
    id            uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    scope_type    varchar(20)              NOT NULL,                  -- global, subnet, pool, class, host
    scope_id      uuid,                                               -- references the scope (null for global)
    option_code   smallint                 NOT NULL,
    option_name   varchar(100),
    option_value  bytea                    NOT NULL,                  -- raw option data
    option_format varchar(20),                                        -- ip, ip_list, string, uint8, uint16, uint32, boolean
    created_at    timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dhcp_relay_agents (
    id          uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    ip_address  inet                     NOT NULL UNIQUE,
    description varchar(255),
    trusted     boolean                  DEFAULT true,
    created_at  timestamp with time zone DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_dhcp_custom_options_scope ON dhcp_custom_options(scope_type, scope_id);
