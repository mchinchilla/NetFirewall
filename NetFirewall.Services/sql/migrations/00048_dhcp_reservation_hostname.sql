-- 00048_dhcp_reservation_hostname.sql
-- A reserved device gets a name: published into the firewall's DNS resolver (Unbound local-data)
-- together with lease hostnames, so `ping nas.home.lan` works. One DNS label (RFC 1123), lower-case.
ALTER TABLE dhcp_mac_reservations ADD COLUMN IF NOT EXISTS hostname varchar(63);

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_dhcp_reservation_hostname') THEN
        ALTER TABLE dhcp_mac_reservations ADD CONSTRAINT chk_dhcp_reservation_hostname
            CHECK (hostname IS NULL OR hostname ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$');
    END IF;
END $$;

-- Two devices with the same name would make the DNS answer ambiguous.
CREATE UNIQUE INDEX IF NOT EXISTS ux_dhcp_reservations_hostname
    ON dhcp_mac_reservations (hostname) WHERE hostname IS NOT NULL;
