-- 00018_search_index.sql
-- Centralized full-text search index. One row per searchable entity across
-- the firewall (filter rules, NAT, port forwards, mangle, network objects,
-- DHCP subnets, WireGuard peers).
--
-- Design choice: centralized over per-table tsvector columns. Trade-off is
-- a few more triggers up front, but the search query stays a single GIN
-- index hit instead of N UNION ALL branches — much faster on large data
-- sets and trivial to add new entity types later.
--
-- IMPORTANT: every value passed to search_make_tsv is cast to text with
-- ::text. Postgres won't auto-cast cidr/inet/uuid/etc. to text, and column
-- types vary across our schema (e.g. dhcp_subnets.network may be cidr in
-- some installs). The casts make the call site bulletproof regardless of
-- upstream column-type drift.

CREATE TABLE IF NOT EXISTS search_index (
    entity_type varchar(40)  NOT NULL,
    entity_id   uuid         NOT NULL,
    title       text         NOT NULL,
    subtitle    text,
    url         text         NOT NULL,
    tsv         tsvector     NOT NULL,
    updated_at  timestamptz  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (entity_type, entity_id)
);

CREATE INDEX IF NOT EXISTS idx_search_index_tsv ON search_index USING GIN (tsv);
CREATE INDEX IF NOT EXISTS idx_search_index_kind ON search_index (entity_type);

-- Helper: assemble a tsvector from up to four nullable text inputs, weighted
-- A (title) > B (subtitle/value) > C (description) > D (anything else). All
-- inputs are coerced to '' so NULLs don't blow up to_tsvector.
CREATE OR REPLACE FUNCTION search_make_tsv(a text, b text, c text, d text)
RETURNS tsvector AS $$
    SELECT setweight(to_tsvector('simple', COALESCE(a, '')), 'A') ||
           setweight(to_tsvector('simple', COALESCE(b, '')), 'B') ||
           setweight(to_tsvector('simple', COALESCE(c, '')), 'C') ||
           setweight(to_tsvector('simple', COALESCE(d, '')), 'D');
$$ LANGUAGE SQL IMMUTABLE;

-- =====================================================================
--  TRIGGER FACTORIES — one per source table
-- =====================================================================

-- ---------- fw_filter_rules ----------
CREATE OR REPLACE FUNCTION search_sync_filter_rule() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = 'filter_rule' AND entity_id = OLD.id;
        RETURN OLD;
    END IF;

    INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
    VALUES (
        'filter_rule',
        NEW.id,
        COALESCE(NEW.description, NEW.chain || ' ' || NEW.action),
        NEW.chain || ' · ' || NEW.action || COALESCE(' · ' || NEW.protocol, ''),
        '/Firewall/FilterRules',
        search_make_tsv(
            NEW.description::text,
            (NEW.chain || ' ' || NEW.action || ' ' || COALESCE(NEW.protocol, ''))::text,
            (COALESCE(array_to_string(NEW.source_addresses, ' '), '') || ' ' ||
                COALESCE(array_to_string(NEW.destination_addresses, ' '), ''))::text,
            COALESCE(array_to_string(NEW.destination_ports, ' '), '')::text
        ),
        NOW()
    )
    ON CONFLICT (entity_type, entity_id) DO UPDATE SET
        title = EXCLUDED.title,
        subtitle = EXCLUDED.subtitle,
        url = EXCLUDED.url,
        tsv = EXCLUDED.tsv,
        updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_search_filter_rule ON fw_filter_rules;
CREATE TRIGGER trg_search_filter_rule
    AFTER INSERT OR UPDATE OR DELETE ON fw_filter_rules
    FOR EACH ROW EXECUTE FUNCTION search_sync_filter_rule();

-- ---------- fw_nat_rules ----------
CREATE OR REPLACE FUNCTION search_sync_nat_rule() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = 'nat_rule' AND entity_id = OLD.id;
        RETURN OLD;
    END IF;

    INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
    VALUES (
        'nat_rule',
        NEW.id,
        COALESCE(NEW.description, NEW.type || ' ' || NEW.source_network),
        'NAT ' || NEW.type || ' · ' || NEW.source_network,
        '/Firewall/NatRules',
        search_make_tsv(NEW.description::text, NEW.type::text, NEW.source_network::text, NEW.snat_address::text),
        NOW()
    )
    ON CONFLICT (entity_type, entity_id) DO UPDATE SET
        title = EXCLUDED.title, subtitle = EXCLUDED.subtitle, url = EXCLUDED.url,
        tsv = EXCLUDED.tsv, updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_search_nat_rule ON fw_nat_rules;
CREATE TRIGGER trg_search_nat_rule
    AFTER INSERT OR UPDATE OR DELETE ON fw_nat_rules
    FOR EACH ROW EXECUTE FUNCTION search_sync_nat_rule();

-- ---------- fw_port_forwards ----------
CREATE OR REPLACE FUNCTION search_sync_port_forward() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = 'port_forward' AND entity_id = OLD.id;
        RETURN OLD;
    END IF;

    INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
    VALUES (
        'port_forward',
        NEW.id,
        COALESCE(NEW.description, NEW.protocol || ' ' || NEW.external_port_start::text || ' → ' || NEW.internal_ip::text),
        NEW.protocol || ' ' || NEW.external_port_start::text ||
            COALESCE('-' || NEW.external_port_end::text, '') || ' → ' || NEW.internal_ip::text || ':' || NEW.internal_port::text,
        '/Firewall/PortForwards',
        search_make_tsv(
            NEW.description::text,
            (NEW.protocol || ' ' || NEW.internal_ip::text)::text,
            (NEW.external_port_start::text || ' ' || NEW.internal_port::text)::text,
            COALESCE(array_to_string(NEW.source_addresses, ' '), '')::text
        ),
        NOW()
    )
    ON CONFLICT (entity_type, entity_id) DO UPDATE SET
        title = EXCLUDED.title, subtitle = EXCLUDED.subtitle, url = EXCLUDED.url,
        tsv = EXCLUDED.tsv, updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_search_port_forward ON fw_port_forwards;
CREATE TRIGGER trg_search_port_forward
    AFTER INSERT OR UPDATE OR DELETE ON fw_port_forwards
    FOR EACH ROW EXECUTE FUNCTION search_sync_port_forward();

-- ---------- fw_mangle_rules ----------
CREATE OR REPLACE FUNCTION search_sync_mangle_rule() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = 'mangle_rule' AND entity_id = OLD.id;
        RETURN OLD;
    END IF;

    INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
    VALUES (
        'mangle_rule',
        NEW.id,
        COALESCE(NEW.description, 'Mangle ' || NEW.chain),
        NEW.chain || COALESCE(' · ' || NEW.protocol, ''),
        '/Firewall/MangleRules',
        search_make_tsv(NEW.description::text, NEW.chain::text, NEW.protocol::text,
            COALESCE(array_to_string(NEW.source_addresses, ' '), '')::text),
        NOW()
    )
    ON CONFLICT (entity_type, entity_id) DO UPDATE SET
        title = EXCLUDED.title, subtitle = EXCLUDED.subtitle, url = EXCLUDED.url,
        tsv = EXCLUDED.tsv, updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_search_mangle_rule ON fw_mangle_rules;
CREATE TRIGGER trg_search_mangle_rule
    AFTER INSERT OR UPDATE OR DELETE ON fw_mangle_rules
    FOR EACH ROW EXECUTE FUNCTION search_sync_mangle_rule();

-- ---------- network_objects ----------
CREATE OR REPLACE FUNCTION search_sync_network_object() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = 'network_object' AND entity_id = OLD.id;
        RETURN OLD;
    END IF;

    INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
    VALUES (
        'network_object',
        NEW.id,
        NEW.name,
        NEW.type || COALESCE(' · ' || NEW.value, ''),
        '/Network/Objects',
        search_make_tsv(NEW.name::text, NEW.value::text, NEW.description::text, NEW.type::text),
        NOW()
    )
    ON CONFLICT (entity_type, entity_id) DO UPDATE SET
        title = EXCLUDED.title, subtitle = EXCLUDED.subtitle, url = EXCLUDED.url,
        tsv = EXCLUDED.tsv, updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_search_network_object ON network_objects;
CREATE TRIGGER trg_search_network_object
    AFTER INSERT OR UPDATE OR DELETE ON network_objects
    FOR EACH ROW EXECUTE FUNCTION search_sync_network_object();

-- ---------- dhcp_subnets ----------
-- network may be cidr/inet rather than text depending on prior migrations —
-- the ::text casts below normalize either way.
CREATE OR REPLACE FUNCTION search_sync_dhcp_subnet() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = 'dhcp_subnet' AND entity_id = OLD.id;
        RETURN OLD;
    END IF;

    INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
    VALUES (
        'dhcp_subnet',
        NEW.id,
        NEW.name,
        'Subnet · ' || NEW.network::text,
        '/Dhcp/Subnets',
        search_make_tsv(NEW.name::text, NEW.network::text, NEW.domain_name::text, NEW.router::text),
        NOW()
    )
    ON CONFLICT (entity_type, entity_id) DO UPDATE SET
        title = EXCLUDED.title, subtitle = EXCLUDED.subtitle, url = EXCLUDED.url,
        tsv = EXCLUDED.tsv, updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_search_dhcp_subnet ON dhcp_subnets;
CREATE TRIGGER trg_search_dhcp_subnet
    AFTER INSERT OR UPDATE OR DELETE ON dhcp_subnets
    FOR EACH ROW EXECUTE FUNCTION search_sync_dhcp_subnet();

-- ---------- wg_peers ----------
CREATE OR REPLACE FUNCTION search_sync_wg_peer() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = 'wg_peer' AND entity_id = OLD.id;
        RETURN OLD;
    END IF;

    INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
    VALUES (
        'wg_peer',
        NEW.id,
        NEW.name,
        'WireGuard peer · ' || COALESCE(array_to_string(NEW.allowed_ips, ', '), '(any)'),
        '/Vpn/WireGuard',
        search_make_tsv(NEW.name::text,
            COALESCE(array_to_string(NEW.allowed_ips, ' '), '')::text,
            NEW.description::text,
            ''::text),
        NOW()
    )
    ON CONFLICT (entity_type, entity_id) DO UPDATE SET
        title = EXCLUDED.title, subtitle = EXCLUDED.subtitle, url = EXCLUDED.url,
        tsv = EXCLUDED.tsv, updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_search_wg_peer ON wg_peers;
CREATE TRIGGER trg_search_wg_peer
    AFTER INSERT OR UPDATE OR DELETE ON wg_peers
    FOR EACH ROW EXECUTE FUNCTION search_sync_wg_peer();

-- =====================================================================
--  BACKFILL — populate existing rows once at migration time
-- =====================================================================

INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
SELECT 'filter_rule', id,
       COALESCE(description, chain || ' ' || action),
       chain || ' · ' || action || COALESCE(' · ' || protocol, ''),
       '/Firewall/FilterRules',
       search_make_tsv(description::text,
           (chain || ' ' || action || ' ' || COALESCE(protocol, ''))::text,
           (COALESCE(array_to_string(source_addresses, ' '), '') || ' ' ||
               COALESCE(array_to_string(destination_addresses, ' '), ''))::text,
           COALESCE(array_to_string(destination_ports, ' '), '')::text),
       NOW()
FROM fw_filter_rules
ON CONFLICT (entity_type, entity_id) DO NOTHING;

INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
SELECT 'nat_rule', id,
       COALESCE(description, type || ' ' || source_network),
       'NAT ' || type || ' · ' || source_network,
       '/Firewall/NatRules',
       search_make_tsv(description::text, type::text, source_network::text, snat_address::text),
       NOW()
FROM fw_nat_rules
ON CONFLICT (entity_type, entity_id) DO NOTHING;

INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
SELECT 'port_forward', id,
       COALESCE(description, protocol || ' ' || external_port_start::text || ' → ' || internal_ip::text),
       protocol || ' ' || external_port_start::text || COALESCE('-' || external_port_end::text, '') ||
           ' → ' || internal_ip::text || ':' || internal_port::text,
       '/Firewall/PortForwards',
       search_make_tsv(description::text,
           (protocol || ' ' || internal_ip::text)::text,
           (external_port_start::text || ' ' || internal_port::text)::text,
           COALESCE(array_to_string(source_addresses, ' '), '')::text),
       NOW()
FROM fw_port_forwards
ON CONFLICT (entity_type, entity_id) DO NOTHING;

INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
SELECT 'mangle_rule', id,
       COALESCE(description, 'Mangle ' || chain),
       chain || COALESCE(' · ' || protocol, ''),
       '/Firewall/MangleRules',
       search_make_tsv(description::text, chain::text, protocol::text,
           COALESCE(array_to_string(source_addresses, ' '), '')::text),
       NOW()
FROM fw_mangle_rules
ON CONFLICT (entity_type, entity_id) DO NOTHING;

INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
SELECT 'network_object', id, name,
       type || COALESCE(' · ' || value, ''), '/Network/Objects',
       search_make_tsv(name::text, value::text, description::text, type::text), NOW()
FROM network_objects
ON CONFLICT (entity_type, entity_id) DO NOTHING;

INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
SELECT 'dhcp_subnet', id, name, 'Subnet · ' || network::text, '/Dhcp/Subnets',
       search_make_tsv(name::text, network::text, domain_name::text, router::text), NOW()
FROM dhcp_subnets
ON CONFLICT (entity_type, entity_id) DO NOTHING;

INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
SELECT 'wg_peer', id, name,
       'WireGuard peer · ' || COALESCE(array_to_string(allowed_ips, ', '), '(any)'),
       '/Vpn/WireGuard',
       search_make_tsv(name::text,
           COALESCE(array_to_string(allowed_ips, ' '), '')::text,
           description::text,
           ''::text),
       NOW()
FROM wg_peers
ON CONFLICT (entity_type, entity_id) DO NOTHING;
