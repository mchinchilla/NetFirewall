-- Explicit per-peer role for WireGuard peers. Replaces the confusing
-- server-level mode ('client'|'server') as the thing that decides behavior:
-- one interface can dial an upstream AND accept inbound clients at once
-- (tekium's wg0 does exactly that), so the role has to live on the peer.
--
--   upstream — a remote wg server this firewall dials out to (endpoint
--              required; health-monitored; no NAT/forward generated for it).
--   client   — inbound road-warrior (laptop/phone). Allowed to be offline —
--              never health-monitored. Keys are generated on-device.
--   site     — site-to-site link (allowed_subnets = the remote LAN).
--              Expected up regardless of which side dials; health-monitored.
--
-- Backfill mirrors WireGuardImporter's inference: route_mode 'site' wins;
-- a peer we dial (endpoint set) that routes everything (0.0.0.0/0) is the
-- upstream; everything else is an inbound client. A road-warrior with a
-- mis-filled endpoint stays 'client' (its allowed_ips is just its /32).

ALTER TABLE wg_peers
    ADD COLUMN IF NOT EXISTS role varchar(16) NOT NULL DEFAULT 'client';

UPDATE wg_peers SET role = CASE
    WHEN route_mode = 'site' THEN 'site'
    WHEN COALESCE(endpoint, '') <> ''
         AND ('0.0.0.0/0' = ANY(allowed_ips) OR '::/0' = ANY(allowed_ips))
        THEN 'upstream'
    ELSE 'client'
END;

ALTER TABLE wg_peers
    DROP CONSTRAINT IF EXISTS chk_wg_peer_role;
ALTER TABLE wg_peers
    ADD CONSTRAINT chk_wg_peer_role
    CHECK (role IN ('upstream','client','site'));
