-- DHCP failover (active/passive HA) — peer registry, runtime state, binding sync log.

CREATE TABLE IF NOT EXISTS dhcp_failover_peers (
    id                  uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    name                varchar(100)             NOT NULL UNIQUE,
    role                varchar(20)              NOT NULL,            -- primary, secondary
    peer_address        inet                     NOT NULL,
    peer_port           int                      DEFAULT 647,
    local_address       inet,
    local_port          int                      DEFAULT 647,
    max_response_delay  int                      DEFAULT 60,
    max_unacked_updates int                      DEFAULT 10,
    mclt                int                      DEFAULT 3600,        -- maximum client lead time
    split               int                      DEFAULT 128,         -- 0-255 split ratio
    load_balance_max    int                      DEFAULT 3,
    auto_partner_down   int                      DEFAULT 0,           -- seconds (0 = disabled)
    shared_secret       text,                                         -- optional auth secret
    enabled             boolean                  DEFAULT false,
    created_at          timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dhcp_failover_state (
    peer_id          uuid                     PRIMARY KEY REFERENCES dhcp_failover_peers(id) ON DELETE CASCADE,
    state            int                      NOT NULL DEFAULT 0,    -- FailoverState enum
    peer_state       int                      DEFAULT 0,
    last_contact     timestamp with time zone,
    state_changed_at timestamp with time zone DEFAULT now(),
    updated_at       timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dhcp_failover_bindings (
    id            uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    ip_address    inet                     NOT NULL UNIQUE,
    mac_address   macaddr                  NOT NULL,
    binding_state int                      NOT NULL,                  -- FailoverBindingState enum
    start_time    timestamp with time zone NOT NULL,
    end_time      timestamp with time zone NOT NULL,
    cltt          timestamp with time zone,                           -- Client Last Transaction Time
    stos          bigint,                                             -- Start Time of State (epoch)
    pending_ack   boolean                  DEFAULT false,
    synced        boolean                  DEFAULT false,
    created_at    timestamp with time zone DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_failover_bindings_pending ON dhcp_failover_bindings(pending_ack) WHERE pending_ack = true;
CREATE INDEX IF NOT EXISTS idx_failover_bindings_synced  ON dhcp_failover_bindings(synced)      WHERE synced = false;
