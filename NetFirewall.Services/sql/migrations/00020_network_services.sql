-- 00020_network_services.sql
-- Named, reusable port/protocol catalog. Mirror of network_objects but for
-- L4 rather than L3. Filter / mangle / port-forward rules can reference
-- services by name in the destination_ports field; the resolver expands at
-- apply time. Single port → "22"; range → "10000-20000"; group → fan-out.
--
-- Seeded with the IANA / common-ops well-known catalog so users can hit the
-- ground running without manually re-typing "22 = SSH". is_builtin flags
-- those rows so the UI can de-emphasize "delete" on them.

CREATE TABLE IF NOT EXISTS network_services (
    id          uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    name        varchar(80)  UNIQUE NOT NULL,
    protocol    varchar(10)  NOT NULL CHECK (protocol IN ('tcp', 'udp', 'tcp+udp', 'icmp')),
    port_start  int          NOT NULL,
    port_end    int,                                      -- nullable; set for ranges
    description text,
    category    varchar(40),                              -- "Web", "Mail", "VoIP", ...
    is_builtin  boolean      NOT NULL DEFAULT false,
    created_at  timestamptz  NOT NULL DEFAULT NOW(),
    updated_at  timestamptz  NOT NULL DEFAULT NOW(),
    CHECK (port_start BETWEEN 0 AND 65535),
    CHECK (port_end IS NULL OR (port_end BETWEEN 0 AND 65535 AND port_end >= port_start))
);

CREATE TABLE IF NOT EXISTS network_service_groups (
    parent_id uuid NOT NULL REFERENCES network_services(id) ON DELETE CASCADE,
    child_id  uuid NOT NULL REFERENCES network_services(id) ON DELETE CASCADE,
    PRIMARY KEY (parent_id, child_id),
    CHECK (parent_id <> child_id)
);

CREATE INDEX IF NOT EXISTS idx_network_services_category ON network_services(category);
CREATE INDEX IF NOT EXISTS idx_network_service_groups_child ON network_service_groups(child_id);

-- ---------- Search index trigger ----------
CREATE OR REPLACE FUNCTION search_sync_network_service() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = 'network_service' AND entity_id = OLD.id;
        RETURN OLD;
    END IF;

    INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
    VALUES (
        'network_service',
        NEW.id,
        NEW.name,
        NEW.protocol || ' · ' || NEW.port_start::text || COALESCE('-' || NEW.port_end::text, '') ||
            COALESCE(' · ' || NEW.category, ''),
        '/Network/Services',
        search_make_tsv(NEW.name::text, NEW.protocol::text,
            (NEW.port_start::text || COALESCE('-' || NEW.port_end::text, ''))::text,
            (COALESCE(NEW.description, '') || ' ' || COALESCE(NEW.category, ''))::text),
        NOW()
    )
    ON CONFLICT (entity_type, entity_id) DO UPDATE SET
        title = EXCLUDED.title, subtitle = EXCLUDED.subtitle, url = EXCLUDED.url,
        tsv = EXCLUDED.tsv, updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_search_network_service ON network_services;
CREATE TRIGGER trg_search_network_service
    AFTER INSERT OR UPDATE OR DELETE ON network_services
    FOR EACH ROW EXECUTE FUNCTION search_sync_network_service();

-- =====================================================================
--  SEED — well-known services (IANA + common-ops curated)
-- =====================================================================
-- ON CONFLICT (name) DO NOTHING so re-running this migration is safe and
-- never clobbers an operator's edits to a builtin (e.g. they renamed HTTP).

INSERT INTO network_services (name, protocol, port_start, port_end, description, category, is_builtin) VALUES
  -- Web
  ('HTTP',         'tcp',     80,    NULL, 'Hypertext Transfer Protocol',                'Web',      true),
  ('HTTPS',        'tcp',    443,    NULL, 'HTTP over TLS',                              'Web',      true),
  ('HTTP_ALT',     'tcp',   8080,    NULL, 'Common alternate HTTP port',                 'Web',      true),
  ('HTTPS_ALT',    'tcp',   8443,    NULL, 'Common alternate HTTPS port',                'Web',      true),
  ('QUIC',         'udp',    443,    NULL, 'HTTP/3 QUIC over UDP',                       'Web',      true),

  -- Remote access
  ('SSH',          'tcp',     22,    NULL, 'Secure Shell',                               'Remote',   true),
  ('TELNET',       'tcp',     23,    NULL, 'Telnet (legacy, plaintext)',                 'Remote',   true),
  ('RDP',          'tcp',   3389,    NULL, 'Microsoft Remote Desktop',                   'Remote',   true),
  ('VNC',          'tcp',   5900,    NULL, 'Virtual Network Computing',                  'Remote',   true),
  ('MOSH',         'udp',  60000,  61000, 'Mobile Shell UDP range',                      'Remote',   true),

  -- File transfer
  ('FTP',          'tcp',     21,    NULL, 'File Transfer Protocol (control)',           'Files',    true),
  ('FTP_DATA',     'tcp',     20,    NULL, 'FTP data channel (active mode)',             'Files',    true),
  ('SFTP',         'tcp',     22,    NULL, 'SFTP rides on SSH',                          'Files',    true),
  ('TFTP',         'udp',     69,    NULL, 'Trivial File Transfer Protocol',             'Files',    true),
  ('SMB',          'tcp',    445,    NULL, 'Microsoft SMB / CIFS',                       'Files',    true),
  ('NFS',          'tcp',   2049,    NULL, 'Network File System',                        'Files',    true),
  ('AFP',          'tcp',    548,    NULL, 'Apple Filing Protocol',                      'Files',    true),
  ('RSYNC',        'tcp',    873,    NULL, 'rsync daemon',                               'Files',    true),

  -- Mail
  ('SMTP',         'tcp',     25,    NULL, 'Simple Mail Transfer Protocol',              'Mail',     true),
  ('SMTPS',        'tcp',    465,    NULL, 'SMTP over TLS (implicit)',                   'Mail',     true),
  ('SUBMISSION',   'tcp',    587,    NULL, 'Mail submission (STARTTLS)',                 'Mail',     true),
  ('IMAP',         'tcp',    143,    NULL, 'Internet Message Access Protocol',           'Mail',     true),
  ('IMAPS',        'tcp',    993,    NULL, 'IMAP over TLS',                              'Mail',     true),
  ('POP3',         'tcp',    110,    NULL, 'Post Office Protocol v3',                    'Mail',     true),
  ('POP3S',        'tcp',    995,    NULL, 'POP3 over TLS',                              'Mail',     true),

  -- DNS / directory / time
  ('DNS_UDP',      'udp',     53,    NULL, 'Domain Name System (UDP)',                   'Infra',    true),
  ('DNS_TCP',      'tcp',     53,    NULL, 'DNS over TCP (zone transfers, large)',       'Infra',    true),
  ('DNS_OVER_TLS', 'tcp',    853,    NULL, 'DoT — DNS over TLS',                         'Infra',    true),
  ('DOH',          'tcp',    443,    NULL, 'DoH typically rides standard HTTPS',         'Infra',    true),
  ('NTP',          'udp',    123,    NULL, 'Network Time Protocol',                      'Infra',    true),
  ('LDAP',         'tcp',    389,    NULL, 'Lightweight Directory Access Protocol',      'Infra',    true),
  ('LDAPS',        'tcp',    636,    NULL, 'LDAP over TLS',                              'Infra',    true),
  ('KERBEROS',     'tcp',     88,    NULL, 'Kerberos authentication',                    'Infra',    true),
  ('SNMP',         'udp',    161,    NULL, 'Simple Network Management Protocol',         'Infra',    true),
  ('SNMP_TRAP',    'udp',    162,    NULL, 'SNMP traps',                                 'Infra',    true),
  ('SYSLOG',       'udp',    514,    NULL, 'Syslog (legacy)',                            'Infra',    true),

  -- Networking infra
  ('DHCP_SERVER',  'udp',     67,    NULL, 'DHCP server-side',                           'Infra',    true),
  ('DHCP_CLIENT',  'udp',     68,    NULL, 'DHCP client-side',                           'Infra',    true),
  ('BGP',          'tcp',    179,    NULL, 'Border Gateway Protocol',                    'Routing',  true),
  ('OSPF',         'icmp',    89,    NULL, 'OSPF (IP proto 89; rule typically uses ip protocol)', 'Routing', true),
  ('GRE',          'icmp',    47,    NULL, 'GRE tunneling (IP proto 47)',                'Tunnels',  true),
  ('IKE',          'udp',    500,    NULL, 'IPsec IKE',                                  'Tunnels',  true),
  ('IPSEC_NATT',   'udp',   4500,    NULL, 'IPsec NAT-traversal',                        'Tunnels',  true),
  ('WIREGUARD',    'udp',  51820,    NULL, 'WireGuard default',                          'Tunnels',  true),
  ('OPENVPN',      'udp',   1194,    NULL, 'OpenVPN default',                            'Tunnels',  true),

  -- VoIP / RTC
  ('SIP',          'udp',   5060,    NULL, 'SIP signalling (UDP)',                       'VoIP',     true),
  ('SIP_TCP',      'tcp',   5060,    NULL, 'SIP signalling (TCP)',                       'VoIP',     true),
  ('SIPS',         'tcp',   5061,    NULL, 'SIP over TLS',                               'VoIP',     true),
  ('RTP',          'udp',  10000,  20000, 'RTP media stream range (typical)',            'VoIP',     true),
  ('STUN',         'udp',   3478,    NULL, 'STUN (TURN over UDP)',                       'VoIP',     true),
  ('TURN_TCP',     'tcp',   3478,    NULL, 'TURN over TCP',                              'VoIP',     true),
  ('TURNS',        'tcp',   5349,    NULL, 'TURN over TLS',                              'VoIP',     true),

  -- Databases
  ('POSTGRES',     'tcp',   5432,    NULL, 'PostgreSQL',                                 'Database', true),
  ('MYSQL',        'tcp',   3306,    NULL, 'MySQL / MariaDB',                            'Database', true),
  ('REDIS',        'tcp',   6379,    NULL, 'Redis',                                      'Database', true),
  ('MONGODB',      'tcp',  27017,    NULL, 'MongoDB',                                    'Database', true),
  ('MSSQL',        'tcp',   1433,    NULL, 'SQL Server',                                 'Database', true),
  ('ORACLE',       'tcp',   1521,    NULL, 'Oracle Database',                            'Database', true),
  ('CASSANDRA',    'tcp',   9042,    NULL, 'Cassandra CQL',                              'Database', true),

  -- Messaging / queues
  ('AMQP',         'tcp',   5672,    NULL, 'AMQP (RabbitMQ default)',                    'Messaging',true),
  ('AMQPS',        'tcp',   5671,    NULL, 'AMQP over TLS',                              'Messaging',true),
  ('MQTT',         'tcp',   1883,    NULL, 'MQTT broker',                                'Messaging',true),
  ('MQTTS',        'tcp',   8883,    NULL, 'MQTT over TLS',                              'Messaging',true),
  ('KAFKA',        'tcp',   9092,    NULL, 'Apache Kafka broker',                        'Messaging',true),

  -- Container / k8s
  ('DOCKER_API',   'tcp',   2375,    NULL, 'Docker remote API (plaintext)',              'Container',true),
  ('DOCKER_TLS',   'tcp',   2376,    NULL, 'Docker remote API (TLS)',                    'Container',true),
  ('K8S_API',      'tcp',   6443,    NULL, 'Kubernetes API server',                      'Container',true),
  ('ETCD',         'tcp',   2379,    NULL, 'etcd client',                                'Container',true),

  -- Monitoring / observability
  ('PROMETHEUS',   'tcp',   9090,    NULL, 'Prometheus server',                          'Observ',   true),
  ('GRAFANA',      'tcp',   3000,    NULL, 'Grafana',                                    'Observ',   true),
  ('STATSD',       'udp',   8125,    NULL, 'StatsD',                                     'Observ',   true),

  -- ICMP
  ('PING',         'icmp',     8,    NULL, 'ICMP echo request (type 8)',                 'ICMP',     true)
ON CONFLICT (name) DO NOTHING;

-- Backfill the search index for the seed.
INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
SELECT 'network_service', id, name,
       protocol || ' · ' || port_start::text || COALESCE('-' || port_end::text, '') ||
           COALESCE(' · ' || category, ''),
       '/Network/Services',
       search_make_tsv(name::text, protocol::text,
           (port_start::text || COALESCE('-' || port_end::text, ''))::text,
           (COALESCE(description, '') || ' ' || COALESCE(category, ''))::text),
       NOW()
FROM network_services
ON CONFLICT (entity_type, entity_id) DO NOTHING;
