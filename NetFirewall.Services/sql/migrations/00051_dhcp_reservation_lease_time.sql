-- 00051_dhcp_reservation_lease_time.sql
-- Per-host lease time. A reservation may carry its own lease length (seconds) — a printer that
-- should hold its address for a week, a guest laptop that should not. NULL = the subnet's
-- default_lease_time, which is what every existing reservation keeps.
-- The DHCP server reads it from DhcpReservationCache (dropped by the reservation.changed NOTIFY,
-- migration 00044), so no new trigger is needed.
ALTER TABLE dhcp_mac_reservations ADD COLUMN IF NOT EXISTS lease_time integer;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_dhcp_reservation_lease_time') THEN
        ALTER TABLE dhcp_mac_reservations ADD CONSTRAINT chk_dhcp_reservation_lease_time
            CHECK (lease_time IS NULL OR lease_time BETWEEN 60 AND 31536000);
    END IF;
END $$;
