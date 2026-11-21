-- 00054_dhcp_relay_agents_notify.sql
-- Trusted DHCP relays. dhcp_relay_agents existed since 00007 but nothing read it. The DHCP
-- server now builds its relay policy from it (DhcpRelayTrustCache): once at least one relay is
-- trusted, relayed packets from any other giaddr are dropped, and option 82 on direct packets
-- no longer picks a class or pool. A row with trusted = false is always refused.
-- NULL trusted is read as true (the column default), so make it explicit.
UPDATE dhcp_relay_agents SET trusted = true WHERE trusted IS NULL;
ALTER TABLE dhcp_relay_agents ALTER COLUMN trusted SET NOT NULL;

CREATE OR REPLACE FUNCTION notify_dhcp_relay_change() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('dhcp_cache_invalidate', 'relay.changed');
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_dhcp_relay_notify ON dhcp_relay_agents;
CREATE TRIGGER trg_dhcp_relay_notify
    AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON dhcp_relay_agents
    FOR EACH STATEMENT
    EXECUTE FUNCTION notify_dhcp_relay_change();
