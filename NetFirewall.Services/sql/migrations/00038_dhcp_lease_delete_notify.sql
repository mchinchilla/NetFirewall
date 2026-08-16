-- Propagate EVERY dhcp_leases delete to the DHCP server's in-memory
-- LeaseCache.
--
-- Incident (2026-08-16): a MAC reservation was re-pointed at a new device
-- (same IP, new MAC). The stale lease for the old MAC kept the reserved IP
-- "in use" in the LeaseCache, so the reserved device was NAKed. Deleting the
-- lease row BY HAND in psql changed nothing — the cache is the runtime source
-- of truth and never saw the delete — until the service was restarted.
--
-- The application paths (UI lease release, reservation save purge) already
-- emit pg_notify('dhcp_cache_invalidate', 'lease.release:<ip>') themselves.
-- This trigger makes the invalidation unconditional: any delete — app,
-- migration, psql at 2am — reaches DhcpCacheRefreshListener, which drops the
-- entry via LeaseCache.ReleaseLeaseByIpAsync. The listener's removal is
-- conditional (only enqueues a write-through delete when an in-memory entry
-- was actually removed), so echoes of the cache's own write-through deletes
-- are harmless no-ops, not a notify loop.

CREATE OR REPLACE FUNCTION notify_dhcp_lease_delete() RETURNS trigger AS $$
BEGIN
    -- host() strips the /32 suffix inet renders with; the listener parses the
    -- payload with IPAddress.TryParse. Channel/prefix must match
    -- IDhcpCacheNotifier.SubnetChannel and DhcpCacheRefreshListener.
    PERFORM pg_notify('dhcp_cache_invalidate', 'lease.release:' || host(OLD.ip_address));
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_dhcp_lease_delete_notify ON dhcp_leases;
CREATE TRIGGER trg_dhcp_lease_delete_notify
    AFTER DELETE ON dhcp_leases
    FOR EACH ROW
    EXECUTE FUNCTION notify_dhcp_lease_delete();
