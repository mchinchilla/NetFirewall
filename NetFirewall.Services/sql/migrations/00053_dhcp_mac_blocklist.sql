-- 00053_dhcp_mac_blocklist.sql
-- MAC block list: devices the DHCP server never answers (DHCP → Access control). Before this,
-- blocking a device meant a class + a pool deny rule. Adding a MAC also purges its lease
-- (DhcpAccessControlService), so it doesn't stay online until the lease runs out.
CREATE TABLE IF NOT EXISTS dhcp_mac_blocklist (
    id          uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    mac_address macaddr                  NOT NULL UNIQUE,
    reason      varchar(255),
    created_at  timestamp with time zone DEFAULT now()
);

-- Tell the DHCP server (DhcpBlocklistCache) on any write — Web, psql, seed.
-- Channel/payload must match IDhcpCacheNotifier.SubnetChannel and the "blocklist." prefix
-- handled by DhcpCacheRefreshListener.
CREATE OR REPLACE FUNCTION notify_dhcp_blocklist_change() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('dhcp_cache_invalidate', 'blocklist.changed');
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_dhcp_blocklist_notify ON dhcp_mac_blocklist;
CREATE TRIGGER trg_dhcp_blocklist_notify
    AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON dhcp_mac_blocklist
    FOR EACH STATEMENT
    EXECUTE FUNCTION notify_dhcp_blocklist_change();
