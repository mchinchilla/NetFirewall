-- WireGuard: support both server (hub) and client (spoke) modes.
--
-- Until now wg_servers only modeled a wg interface that ACCEPTS inbound peers.
-- This migration lets the same table also describe an interface that
-- INITIATES a tunnel to a remote wg server. The discriminator is `mode`.
--
--   mode='server' : firewall accepts peers. [Interface] has ListenPort. N peers, each potentially with PersistentKeepalive.
--   mode='client' : firewall connects out. [Interface] has NO ListenPort. Exactly one peer (the remote server), with Endpoint=host:port.
--
-- New columns are nullable / defaulted so existing rows stay valid and keep
-- behaving exactly as before. Forward-only migration — to undo, write a new one.


-- wg_servers: add mode + client-only knobs (DNS, MTU, Table=off for wg-quick).
ALTER TABLE wg_servers
    ADD COLUMN IF NOT EXISTS mode       varchar(10) NOT NULL DEFAULT 'server',
    ADD COLUMN IF NOT EXISTS dns        text,        -- comma-sep, e.g. "1.1.1.1,8.8.8.8"
    ADD COLUMN IF NOT EXISTS mtu        int,         -- null = wg-quick default (1420)
    ADD COLUMN IF NOT EXISTS table_off  boolean NOT NULL DEFAULT false;  -- emit `Table = off` (don't manage routes)

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_wg_mode'
    ) THEN
        ALTER TABLE wg_servers
            ADD CONSTRAINT chk_wg_mode CHECK (mode IN ('server','client'));
    END IF;
END $$;

-- wg_peers: endpoint = "host:port" of the remote side. Required when the
-- parent server is in 'client' mode (then the single peer IS the remote
-- server). Optional in 'server' mode — some site-to-site configs include
-- it on inbound peers too, for symmetric keepalive.
ALTER TABLE wg_peers
    ADD COLUMN IF NOT EXISTS endpoint text;

