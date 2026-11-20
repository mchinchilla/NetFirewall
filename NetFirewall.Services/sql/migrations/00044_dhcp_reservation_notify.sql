-- Tell the DHCP server when MAC reservations change.
--
-- The DHCP server now answers "which IP is reserved for this MAC?" and "who owns
-- this reserved IP?" from an in-memory DhcpReservationCache instead of 1–2 queries
-- per DISCOVER/REQUEST. Any write to dhcp_mac_reservations — the Web UI, a seed,
-- psql — must drop that cache, or a re-pointed reservation keeps handing out the
-- old binding. Statement-level: one notify per write statement, not per row.
-- Channel/payload must match IDhcpCacheNotifier.SubnetChannel and the
-- "reservation." prefix handled by DhcpCacheRefreshListener.

CREATE OR REPLACE FUNCTION notify_dhcp_reservation_change() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('dhcp_cache_invalidate', 'reservation.changed');
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_dhcp_reservation_notify ON dhcp_mac_reservations;
CREATE TRIGGER trg_dhcp_reservation_notify
    AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON dhcp_mac_reservations
    FOR EACH STATEMENT
    EXECUTE FUNCTION notify_dhcp_reservation_change();
