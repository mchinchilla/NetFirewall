-- 00030_search_index_dhcp.sql
-- Extend the centralized full-text search index (see 00018_search_index.sql)
-- to cover DHCP MAC reservations and active leases, so the global search box
-- finds devices by hostname, IP, or MAC.
--
-- MAC matching: the UI renders MACs with no separators and uppercase
-- (PhysicalAddress.ToString() => "B08BA8286D69"), but macaddr::text is the
-- colon form ("b0:8b:a8:28:6d:69"). We feed BOTH forms into the tsvector so a
-- search for either "b0:8b:a8" or "b08ba8286d69" resolves. host() strips the
-- inet prefix so addresses tokenize cleanly.
--
-- PERFORMANCE NOTE: the dhcp_leases trigger fires on every lease insert/renew.
-- On a busy DHCP server this adds one GIN upsert per lease write. It is kept
-- in its OWN migration precisely so it can be dropped independently if lease
-- write latency ever becomes a concern (see docs/PerformanceAnalysis.md):
--     DROP TRIGGER trg_search_dhcp_lease ON dhcp_leases;
-- Reservations change rarely, so their trigger is essentially free.

-- ---------- dhcp_mac_reservations ----------
CREATE OR REPLACE FUNCTION search_sync_dhcp_reservation() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = 'dhcp_reservation' AND entity_id = OLD.id;
        RETURN OLD;
    END IF;

    INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
    VALUES (
        'dhcp_reservation',
        NEW.id,
        COALESCE(NEW.description, NEW.mac_address::text),
        NEW.mac_address::text || ' → ' || host(NEW.reserved_ip),
        '/Dhcp/Reservations',
        search_make_tsv(
            NEW.description::text,
            (NEW.mac_address::text || ' ' || replace(NEW.mac_address::text, ':', ''))::text,
            host(NEW.reserved_ip)::text,
            ''::text
        ),
        NOW()
    )
    ON CONFLICT (entity_type, entity_id) DO UPDATE SET
        title = EXCLUDED.title, subtitle = EXCLUDED.subtitle, url = EXCLUDED.url,
        tsv = EXCLUDED.tsv, updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_search_dhcp_reservation ON dhcp_mac_reservations;
CREATE TRIGGER trg_search_dhcp_reservation
    AFTER INSERT OR UPDATE OR DELETE ON dhcp_mac_reservations
    FOR EACH ROW EXECUTE FUNCTION search_sync_dhcp_reservation();

-- ---------- dhcp_leases ----------
CREATE OR REPLACE FUNCTION search_sync_dhcp_lease() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = 'dhcp_lease' AND entity_id = OLD.id;
        RETURN OLD;
    END IF;

    INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
    VALUES (
        'dhcp_lease',
        NEW.id,
        COALESCE(NEW.hostname, host(NEW.ip_address)),
        NEW.mac_address::text || ' · ' || host(NEW.ip_address),
        '/Dhcp/Leases',
        search_make_tsv(
            NEW.hostname::text,
            (NEW.mac_address::text || ' ' || replace(NEW.mac_address::text, ':', ''))::text,
            host(NEW.ip_address)::text,
            ''::text
        ),
        NOW()
    )
    ON CONFLICT (entity_type, entity_id) DO UPDATE SET
        title = EXCLUDED.title, subtitle = EXCLUDED.subtitle, url = EXCLUDED.url,
        tsv = EXCLUDED.tsv, updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_search_dhcp_lease ON dhcp_leases;
CREATE TRIGGER trg_search_dhcp_lease
    AFTER INSERT OR UPDATE OR DELETE ON dhcp_leases
    FOR EACH ROW EXECUTE FUNCTION search_sync_dhcp_lease();

-- =====================================================================
--  BACKFILL — populate existing rows once at migration time
-- =====================================================================

INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
SELECT 'dhcp_reservation', id,
       COALESCE(description, mac_address::text),
       mac_address::text || ' → ' || host(reserved_ip),
       '/Dhcp/Reservations',
       search_make_tsv(description::text,
           (mac_address::text || ' ' || replace(mac_address::text, ':', ''))::text,
           host(reserved_ip)::text, ''::text),
       NOW()
FROM dhcp_mac_reservations
ON CONFLICT (entity_type, entity_id) DO NOTHING;

INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
SELECT 'dhcp_lease', id,
       COALESCE(hostname, host(ip_address)),
       mac_address::text || ' · ' || host(ip_address),
       '/Dhcp/Leases',
       search_make_tsv(hostname::text,
           (mac_address::text || ' ' || replace(mac_address::text, ':', ''))::text,
           host(ip_address)::text, ''::text),
       NOW()
FROM dhcp_leases
ON CONFLICT (entity_type, entity_id) DO NOTHING;
