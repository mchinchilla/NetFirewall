-- 00045_wg_interface_per_role.sql
-- One wg_servers row per WireGuard INTERFACE, and every interface has one role:
--   mode='server' : the remote-access server (listens; road-warrior clients, inbound sites)
--   mode='client' : one outbound connection (dials a VPN provider or a remote site)
-- Until now the stack read "the first row" and ignored the rest, so a duplicate
-- name was harmless-by-accident. Now names select rows (daemon ?name=, wg-quick,
-- /etc/wireguard/<name>.conf, the policy-routing table) — they must be unique and
-- safe as a Linux link name (1-15 chars, no shell/path characters).
--
-- No data is rewritten: an existing dual-role wg0 (server with upstream peers) keeps
-- working as-is; splitting it is an explicit operator action in the UI.

DO $$
DECLARE dup text;
BEGIN
    SELECT name INTO dup FROM wg_servers GROUP BY name HAVING count(*) > 1 LIMIT 1;
    IF dup IS NOT NULL THEN
        RAISE EXCEPTION 'wg_servers has more than one row named %. Delete or rename the extra row(s), then re-run migrations.', dup;
    END IF;

    SELECT name INTO dup FROM wg_servers WHERE name !~ '^[A-Za-z0-9_.-]{1,15}$' LIMIT 1;
    IF dup IS NOT NULL THEN
        RAISE EXCEPTION 'wg_servers.name % is not a valid interface name (1-15 of A-Z a-z 0-9 _ . -).', dup;
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS ux_wg_servers_name ON wg_servers (name);

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_wg_server_name') THEN
        ALTER TABLE wg_servers
            ADD CONSTRAINT chk_wg_server_name CHECK (name ~ '^[A-Za-z0-9_.-]{1,15}$');
    END IF;
END $$;
