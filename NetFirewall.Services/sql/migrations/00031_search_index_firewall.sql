-- 00031_search_index_firewall.sql
-- Extend the global search index (see 00018_search_index.sql) to the remaining
-- firewall config entities that have a navigable Web UI page:
--   traffic marks, QoS config, QoS classes, static routes, interfaces, schedules.
--
-- Deliberately NOT indexed:
--   * fw_policy_rules / fw_route_tables — no Web UI page yet, so a hit would be
--     a dead link. Add triggers here once those pages exist.
--   * fw_audit_log / fw_apply_history — append-only logs, not config entities;
--     high churn would pollute results and they aren't navigable to a row.
--
-- Same conventions as 00018: every value cast ::text (Postgres won't auto-cast
-- inet/cidr/uuid/int), title weight A > B > C > D, UPSERT on (type,id), DELETE
-- removes the row. host() strips the inet prefix so addresses tokenize cleanly.

-- ---------- fw_traffic_marks ----------
CREATE OR REPLACE FUNCTION search_sync_traffic_mark() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = 'traffic_mark' AND entity_id = OLD.id;
        RETURN OLD;
    END IF;

    INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
    VALUES (
        'traffic_mark',
        NEW.id,
        COALESCE(NEW.name, 'Mark ' || NEW.mark_value::text),
        'Mark ' || NEW.mark_value::text || COALESCE(' · ' || NEW.route_table, ''),
        '/Firewall/TrafficMarks',
        search_make_tsv(NEW.name::text, NEW.mark_value::text, NEW.description::text, NEW.route_table::text),
        NOW()
    )
    ON CONFLICT (entity_type, entity_id) DO UPDATE SET
        title = EXCLUDED.title, subtitle = EXCLUDED.subtitle, url = EXCLUDED.url,
        tsv = EXCLUDED.tsv, updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_search_traffic_mark ON fw_traffic_marks;
CREATE TRIGGER trg_search_traffic_mark
    AFTER INSERT OR UPDATE OR DELETE ON fw_traffic_marks
    FOR EACH ROW EXECUTE FUNCTION search_sync_traffic_mark();

-- ---------- fw_qos_config (no name column — synthesize from interface) ----------
CREATE OR REPLACE FUNCTION search_sync_qos_config() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = 'qos_config' AND entity_id = OLD.id;
        RETURN OLD;
    END IF;

    INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
    VALUES (
        'qos_config',
        NEW.id,
        'QoS — ' || COALESCE((SELECT name FROM fw_interfaces WHERE id = NEW.interface_id), 'interface'),
        COALESCE(NEW.total_bandwidth_mbps::text || ' Mbps total', 'QoS configuration'),
        '/Firewall/Qos',
        search_make_tsv(
            'qos quality of service traffic shaping',
            (SELECT name FROM fw_interfaces WHERE id = NEW.interface_id)::text,
            NEW.total_bandwidth_mbps::text,
            ''::text),
        NOW()
    )
    ON CONFLICT (entity_type, entity_id) DO UPDATE SET
        title = EXCLUDED.title, subtitle = EXCLUDED.subtitle, url = EXCLUDED.url,
        tsv = EXCLUDED.tsv, updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_search_qos_config ON fw_qos_config;
CREATE TRIGGER trg_search_qos_config
    AFTER INSERT OR UPDATE OR DELETE ON fw_qos_config
    FOR EACH ROW EXECUTE FUNCTION search_sync_qos_config();

-- ---------- fw_qos_classes (deep-link to parent config's classes page) ----------
CREATE OR REPLACE FUNCTION search_sync_qos_class() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = 'qos_class' AND entity_id = OLD.id;
        RETURN OLD;
    END IF;

    INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
    VALUES (
        'qos_class',
        NEW.id,
        COALESCE(NEW.name, 'QoS class'),
        'QoS class' || COALESCE(' · ' || NEW.guaranteed_mbps::text || '–' || NEW.ceiling_mbps::text || ' Mbps', ''),
        '/Firewall/Qos/' || NEW.qos_config_id::text || '/Classes',
        search_make_tsv(
            NEW.name::text,
            'qos class quality of service',
            (COALESCE(NEW.guaranteed_mbps::text, '') || ' ' || COALESCE(NEW.ceiling_mbps::text, ''))::text,
            ''::text),
        NOW()
    )
    ON CONFLICT (entity_type, entity_id) DO UPDATE SET
        title = EXCLUDED.title, subtitle = EXCLUDED.subtitle, url = EXCLUDED.url,
        tsv = EXCLUDED.tsv, updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_search_qos_class ON fw_qos_classes;
CREATE TRIGGER trg_search_qos_class
    AFTER INSERT OR UPDATE OR DELETE ON fw_qos_classes
    FOR EACH ROW EXECUTE FUNCTION search_sync_qos_class();

-- ---------- fw_static_routes ----------
CREATE OR REPLACE FUNCTION search_sync_static_route() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = 'static_route' AND entity_id = OLD.id;
        RETURN OLD;
    END IF;

    INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
    VALUES (
        'static_route',
        NEW.id,
        COALESCE(NEW.description, NEW.destination::text),
        NEW.destination::text || ' → ' || host(NEW.gateway),
        '/Network/Routes',
        search_make_tsv(NEW.description::text, NEW.destination::text, host(NEW.gateway)::text, NEW.metric::text),
        NOW()
    )
    ON CONFLICT (entity_type, entity_id) DO UPDATE SET
        title = EXCLUDED.title, subtitle = EXCLUDED.subtitle, url = EXCLUDED.url,
        tsv = EXCLUDED.tsv, updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_search_static_route ON fw_static_routes;
CREATE TRIGGER trg_search_static_route
    AFTER INSERT OR UPDATE OR DELETE ON fw_static_routes
    FOR EACH ROW EXECUTE FUNCTION search_sync_static_route();

-- ---------- fw_interfaces ----------
CREATE OR REPLACE FUNCTION search_sync_fw_interface() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = 'fw_interface' AND entity_id = OLD.id;
        RETURN OLD;
    END IF;

    INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
    VALUES (
        'fw_interface',
        NEW.id,
        NEW.name,
        COALESCE(NEW.role, NEW.type, 'interface') || COALESCE(' · ' || host(NEW.ip_address), ''),
        '/Network/Interfaces',
        search_make_tsv(
            NEW.name::text,
            host(NEW.ip_address)::text,
            (COALESCE(NEW.description, '') || ' ' || COALESCE(NEW.role, '') || ' ' || COALESCE(NEW.type, ''))::text,
            (COALESCE(NEW.mac_address, '') || ' ' || COALESCE(NEW.vlan_parent, ''))::text),
        NOW()
    )
    ON CONFLICT (entity_type, entity_id) DO UPDATE SET
        title = EXCLUDED.title, subtitle = EXCLUDED.subtitle, url = EXCLUDED.url,
        tsv = EXCLUDED.tsv, updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_search_fw_interface ON fw_interfaces;
CREATE TRIGGER trg_search_fw_interface
    AFTER INSERT OR UPDATE OR DELETE ON fw_interfaces
    FOR EACH ROW EXECUTE FUNCTION search_sync_fw_interface();

-- ---------- fw_schedules ----------
CREATE OR REPLACE FUNCTION search_sync_fw_schedule() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = 'fw_schedule' AND entity_id = OLD.id;
        RETURN OLD;
    END IF;

    INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
    VALUES (
        'fw_schedule',
        NEW.id,
        COALESCE(NEW.name, 'Schedule'),
        'Schedule' || COALESCE(' · ' || array_to_string(NEW.days_of_week, ', '), ''),
        '/Firewall/Schedules',
        search_make_tsv(
            NEW.name::text,
            NEW.description::text,
            COALESCE(array_to_string(NEW.days_of_week, ' '), '')::text,
            NEW.timezone::text),
        NOW()
    )
    ON CONFLICT (entity_type, entity_id) DO UPDATE SET
        title = EXCLUDED.title, subtitle = EXCLUDED.subtitle, url = EXCLUDED.url,
        tsv = EXCLUDED.tsv, updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_search_fw_schedule ON fw_schedules;
CREATE TRIGGER trg_search_fw_schedule
    AFTER INSERT OR UPDATE OR DELETE ON fw_schedules
    FOR EACH ROW EXECUTE FUNCTION search_sync_fw_schedule();

-- =====================================================================
--  BACKFILL — populate existing rows once at migration time
-- =====================================================================

INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
SELECT 'traffic_mark', id,
       COALESCE(name, 'Mark ' || mark_value::text),
       'Mark ' || mark_value::text || COALESCE(' · ' || route_table, ''),
       '/Firewall/TrafficMarks',
       search_make_tsv(name::text, mark_value::text, description::text, route_table::text), NOW()
FROM fw_traffic_marks
ON CONFLICT (entity_type, entity_id) DO NOTHING;

INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
SELECT 'qos_config', q.id,
       'QoS — ' || COALESCE(i.name, 'interface'),
       COALESCE(q.total_bandwidth_mbps::text || ' Mbps total', 'QoS configuration'),
       '/Firewall/Qos',
       search_make_tsv('qos quality of service traffic shaping', i.name::text, q.total_bandwidth_mbps::text, ''::text), NOW()
FROM fw_qos_config q
LEFT JOIN fw_interfaces i ON i.id = q.interface_id
ON CONFLICT (entity_type, entity_id) DO NOTHING;

INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
SELECT 'qos_class', id,
       COALESCE(name, 'QoS class'),
       'QoS class' || COALESCE(' · ' || guaranteed_mbps::text || '–' || ceiling_mbps::text || ' Mbps', ''),
       '/Firewall/Qos/' || qos_config_id::text || '/Classes',
       search_make_tsv(name::text, 'qos class quality of service',
           (COALESCE(guaranteed_mbps::text, '') || ' ' || COALESCE(ceiling_mbps::text, ''))::text, ''::text), NOW()
FROM fw_qos_classes
ON CONFLICT (entity_type, entity_id) DO NOTHING;

INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
SELECT 'static_route', id,
       COALESCE(description, destination::text),
       destination::text || ' → ' || host(gateway),
       '/Network/Routes',
       search_make_tsv(description::text, destination::text, host(gateway)::text, metric::text), NOW()
FROM fw_static_routes
ON CONFLICT (entity_type, entity_id) DO NOTHING;

INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
SELECT 'fw_interface', id,
       name,
       COALESCE(role, type, 'interface') || COALESCE(' · ' || host(ip_address), ''),
       '/Network/Interfaces',
       search_make_tsv(name::text, host(ip_address)::text,
           (COALESCE(description, '') || ' ' || COALESCE(role, '') || ' ' || COALESCE(type, ''))::text,
           (COALESCE(mac_address, '') || ' ' || COALESCE(vlan_parent, ''))::text), NOW()
FROM fw_interfaces
ON CONFLICT (entity_type, entity_id) DO NOTHING;

INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
SELECT 'fw_schedule', id,
       COALESCE(name, 'Schedule'),
       'Schedule' || COALESCE(' · ' || array_to_string(days_of_week, ', '), ''),
       '/Firewall/Schedules',
       search_make_tsv(name::text, description::text,
           COALESCE(array_to_string(days_of_week, ' '), '')::text, timezone::text), NOW()
FROM fw_schedules
ON CONFLICT (entity_type, entity_id) DO NOTHING;
