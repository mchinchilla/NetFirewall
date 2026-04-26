-- DHCP lease event hooks and DDNS (RFC 2136) configuration + log.

CREATE TABLE IF NOT EXISTS dhcp_events (
    id          uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    event_type  varchar(20)              NOT NULL,                    -- commit, release, expiry, decline
    script_path varchar(500),
    script_args text[],
    enabled     boolean                  DEFAULT true,
    created_at  timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dhcp_ddns_config (
    id                     uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    subnet_id              uuid                     REFERENCES dhcp_subnets(id) ON DELETE CASCADE,  -- null = global config
    enable_forward         boolean                  DEFAULT true,            -- A record updates
    enable_reverse         boolean                  DEFAULT true,            -- PTR record updates
    forward_zone           varchar(255),                                     -- e.g. "example.com"
    reverse_zone           varchar(255),                                     -- e.g. "1.168.192.in-addr.arpa"
    dns_server             inet                     NOT NULL,                -- Primary DNS server for updates
    dns_port               int                      DEFAULT 53,
    tsig_key_name          varchar(255),                                     -- TSIG key name for authentication
    tsig_key_secret        text,                                             -- TSIG key secret (Base64)
    tsig_algorithm         varchar(50)              DEFAULT 'hmac-sha256',
    ttl                    int                      DEFAULT 300,
    update_style           varchar(20)              DEFAULT 'standard',
    override_client_update boolean                  DEFAULT false,
    allow_client_updates   boolean                  DEFAULT false,
    conflict_resolution    varchar(30)              DEFAULT 'check-with-dhcid',
    enabled                boolean                  DEFAULT true,
    created_at             timestamp with time zone DEFAULT now(),
    updated_at             timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dhcp_ddns_log (
    id         uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    lease_id   uuid,
    action     varchar(20)              NOT NULL,                     -- add_forward, add_reverse, remove_*
    hostname   varchar(255),
    ip_address inet,
    fqdn       varchar(255),
    success    boolean                  NOT NULL,
    error_msg  text,
    dns_server inet,
    created_at timestamp with time zone DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ddns_config_subnet ON dhcp_ddns_config(subnet_id);
CREATE INDEX IF NOT EXISTS idx_ddns_log_lease     ON dhcp_ddns_log(lease_id, created_at);
CREATE INDEX IF NOT EXISTS idx_ddns_log_created   ON dhcp_ddns_log(created_at);
