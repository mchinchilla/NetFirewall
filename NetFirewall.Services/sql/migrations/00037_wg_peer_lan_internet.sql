-- Split client access into two independent axes. route_mode conflated LAN and
-- internet ('full' = LAN+internet, 'split' = LAN only, 'restricted' = subnets
-- only) which made "specific hosts + internet" and "internet only" impossible
-- to express.
--
--   route_mode (LAN axis, clients):  split = whole LAN | restricted = only
--     allowed_subnets | none = no LAN access. ('full' stays legal as a legacy
--     synonym of split; 'site' belongs to site-to-site tunnels.)
--   allow_internet (internet axis):  masquerade + forward to WAN scoped to the
--     peer's tunnel IP; the exported client config routes 0.0.0.0/0 and the
--     firewall does the LAN fine-cut.
--
-- Backfill preserves semantics: old 'full' clients were LAN+internet, so they
-- become split + allow_internet.

ALTER TABLE wg_peers
    ADD COLUMN IF NOT EXISTS allow_internet boolean NOT NULL DEFAULT false;

UPDATE wg_peers
SET allow_internet = true
WHERE role = 'client' AND route_mode = 'full';

UPDATE wg_peers
SET route_mode = 'split'
WHERE role = 'client' AND route_mode = 'full';

ALTER TABLE wg_peers
    DROP CONSTRAINT IF EXISTS chk_wg_peer_route_mode;
ALTER TABLE wg_peers
    ADD CONSTRAINT chk_wg_peer_route_mode
    CHECK (route_mode IN ('full','split','restricted','site','none'));
