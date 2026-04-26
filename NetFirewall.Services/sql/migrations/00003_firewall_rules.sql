-- Firewall rule tables: port forwards (DNAT), filter rules, NAT rules, mangle rules.

CREATE TABLE IF NOT EXISTS fw_port_forwards (
    id                  uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    description         varchar(255),
    protocol            varchar(10)              NOT NULL,            -- tcp, udp, tcp/udp
    interface_id        uuid                     REFERENCES fw_interfaces(id) ON DELETE SET NULL,
    source_addresses    text[],                                       -- IPs/CIDRs permitted (null = any)
    external_port_start int                      NOT NULL,
    external_port_end   int,                                          -- null = single port
    internal_ip         inet                     NOT NULL,
    internal_port       int                      NOT NULL,
    enabled             boolean                  DEFAULT true,
    priority            int                      DEFAULT 100,
    created_at          timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fw_filter_rules (
    id                    uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    chain                 varchar(20)              NOT NULL,          -- input, forward, output
    description           varchar(255),
    action                varchar(20)              NOT NULL,          -- accept, drop, reject, log
    protocol              varchar(10),                                -- tcp, udp, icmp, null = any
    interface_in_id       uuid                     REFERENCES fw_interfaces(id) ON DELETE SET NULL,
    interface_out_id      uuid                     REFERENCES fw_interfaces(id) ON DELETE SET NULL,
    source_addresses      text[],
    destination_addresses text[],
    destination_ports     text[],                                     -- ['22','80','443','8000-9000']
    connection_state      text[],                                     -- ['new','established','related']
    rate_limit            varchar(50),                                -- '60/minute', '10/second'
    log_prefix            varchar(50),
    enabled               boolean                  DEFAULT true,
    priority              int                      DEFAULT 100,
    created_at            timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fw_nat_rules (
    id                  uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    type                varchar(20)              NOT NULL,            -- masquerade, snat
    description         varchar(255),
    source_network      cidr                     NOT NULL,
    output_interface_id uuid                     REFERENCES fw_interfaces(id) ON DELETE SET NULL,
    snat_address        inet,                                         -- only for SNAT
    enabled             boolean                  DEFAULT true,
    priority            int                      DEFAULT 100,
    created_at          timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fw_mangle_rules (
    id                    uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    chain                 varchar(20)              NOT NULL,          -- prerouting, postrouting
    description           varchar(255),
    mark_id               uuid                     REFERENCES fw_traffic_marks(id) ON DELETE SET NULL,
    protocol              varchar(10),
    source_addresses      text[],
    destination_addresses text[],
    destination_ports     text[],
    enabled               boolean                  DEFAULT true,
    priority              int                      DEFAULT 100,
    created_at            timestamp with time zone DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_fw_port_forwards_enabled  ON fw_port_forwards(enabled, priority);
CREATE INDEX IF NOT EXISTS idx_fw_port_forwards_interface ON fw_port_forwards(interface_id);
CREATE INDEX IF NOT EXISTS idx_fw_filter_rules_chain     ON fw_filter_rules(chain, enabled, priority);
CREATE INDEX IF NOT EXISTS idx_fw_filter_rules_enabled   ON fw_filter_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_fw_nat_rules_enabled      ON fw_nat_rules(enabled, priority);
CREATE INDEX IF NOT EXISTS idx_fw_nat_rules_interface    ON fw_nat_rules(output_interface_id);
CREATE INDEX IF NOT EXISTS idx_fw_mangle_rules_chain     ON fw_mangle_rules(chain, enabled, priority);
CREATE INDEX IF NOT EXISTS idx_fw_mangle_rules_mark      ON fw_mangle_rules(mark_id);
