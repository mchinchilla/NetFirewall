-- QoS configuration and audit log.

CREATE TABLE IF NOT EXISTS fw_qos_config (
    id                   uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    interface_id         uuid                     REFERENCES fw_interfaces(id) ON DELETE CASCADE,
    enabled              boolean                  DEFAULT true,
    total_bandwidth_mbps int                      NOT NULL,
    created_at           timestamp with time zone DEFAULT now(),
    UNIQUE (interface_id)
);

CREATE TABLE IF NOT EXISTS fw_qos_classes (
    id              uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    qos_config_id   uuid                     REFERENCES fw_qos_config(id) ON DELETE CASCADE,
    name            varchar(50)              NOT NULL,                -- high, normal, low
    mark_id         uuid                     REFERENCES fw_traffic_marks(id) ON DELETE SET NULL,
    guaranteed_mbps int                      NOT NULL,
    ceiling_mbps    int                      NOT NULL,
    priority        int                      NOT NULL,                -- 1 = highest
    created_at      timestamp with time zone DEFAULT now()
);

-- Audit log for tracking all firewall configuration changes.
CREATE TABLE IF NOT EXISTS fw_audit_log (
    id         uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name varchar(50)              NOT NULL,
    record_id  uuid                     NOT NULL,
    action     varchar(20)              NOT NULL,                     -- INSERT, UPDATE, DELETE
    old_values jsonb,
    new_values jsonb,
    user_id    varchar(100),
    created_at timestamp with time zone DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_fw_qos_classes_config ON fw_qos_classes(qos_config_id);
CREATE INDEX IF NOT EXISTS idx_fw_audit_log_table    ON fw_audit_log(table_name, created_at);
CREATE INDEX IF NOT EXISTS idx_fw_audit_log_record   ON fw_audit_log(record_id);
CREATE INDEX IF NOT EXISTS idx_fw_audit_log_created  ON fw_audit_log(created_at);
