-- Per-peer routing intent for WireGuard peers (server mode).
--
-- route_mode drives BOTH the exported client config's AllowedIPs AND the
-- auto-generated NAT/FORWARD rules (VpnRoutingService.EnsurePeerForwardingAsync):
--   full       — LAN + internet (client AllowedIPs 0.0.0.0/0; masquerade out WAN)
--   split      — LAN subnets only (client routes only the LAN; no internet via tunnel)
--   restricted — only the subnets/hosts in allowed_subnets
--   site       — site-to-site; allowed_subnets is the remote LAN
--
-- allowed_subnets are the LAN targets for split/restricted/site.

ALTER TABLE wg_peers
    ADD COLUMN IF NOT EXISTS route_mode      varchar(16) NOT NULL DEFAULT 'full',
    ADD COLUMN IF NOT EXISTS allowed_subnets text[]      NOT NULL DEFAULT '{}';

ALTER TABLE wg_peers
    DROP CONSTRAINT IF EXISTS chk_wg_peer_route_mode;
ALTER TABLE wg_peers
    ADD CONSTRAINT chk_wg_peer_route_mode
    CHECK (route_mode IN ('full','split','restricted','site'));
