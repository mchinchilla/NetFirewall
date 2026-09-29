-- 00042_wol_devices.sql
-- Wake-on-LAN: machines the operator wakes from the firewall. The magic packet
-- itself is sent by the daemon (it binds the socket to the LAN interface, which
-- the zero-capability Web cannot be trusted to pick); this table only remembers
-- WHAT to wake and WHERE it is plugged in.
--
-- mac_address is macaddr so it joins straight against dhcp_mac_reservations /
-- dhcp_leases (the device list shows the reserved or last-leased IP). One row
-- per NIC: a second row for the same MAC would only be a second button that
-- sends the same packet.

CREATE TABLE IF NOT EXISTS wol_devices (
    id             uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    name           varchar(64)  NOT NULL,
    mac_address    macaddr      NOT NULL UNIQUE,
    interface      varchar(15)  NOT NULL,
    port           int          NOT NULL DEFAULT 9 CHECK (port BETWEEN 1 AND 65535),
    description    varchar(255),
    last_woken_at  timestamptz,
    last_woken_by  varchar(100),
    created_at     timestamptz  NOT NULL DEFAULT now(),
    updated_at     timestamptz  NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_wol_devices_name ON wol_devices (lower(name));

-- ---------- global search (see 00018_search_index.sql) ----------
-- Both MAC spellings go into the vector, as for DHCP (00030): "b0:8b:a8" and
-- "b08ba8286d69" must both find the device.
CREATE OR REPLACE FUNCTION search_sync_wol_device() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM search_index WHERE entity_type = 'wol_device' AND entity_id = OLD.id;
        RETURN OLD;
    END IF;

    INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
    VALUES (
        'wol_device',
        NEW.id,
        NEW.name,
        upper(NEW.mac_address::text) || ' · ' || NEW.interface,
        '/Network/WakeOnLan',
        search_make_tsv(
            NEW.name::text,
            (NEW.mac_address::text || ' ' || replace(NEW.mac_address::text, ':', ''))::text,
            NEW.description::text,
            NEW.interface::text
        ),
        NOW()
    )
    ON CONFLICT (entity_type, entity_id) DO UPDATE SET
        title = EXCLUDED.title, subtitle = EXCLUDED.subtitle, url = EXCLUDED.url,
        tsv = EXCLUDED.tsv, updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Waking a device only stamps last_woken_*; don't re-index for that.
DROP TRIGGER IF EXISTS trg_search_wol_device ON wol_devices;
CREATE TRIGGER trg_search_wol_device
    AFTER INSERT OR DELETE OR UPDATE OF name, mac_address, interface, description ON wol_devices
    FOR EACH ROW EXECUTE FUNCTION search_sync_wol_device();
