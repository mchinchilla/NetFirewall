-- Policy routing: replace the ad-hoc /root/firewall.sh ip-rule / ip-route
-- bookkeeping with DB-driven config that the daemon applies via iproute2.
--
-- Conceptually:
--   fw_route_tables  = named rt_tables (wan1=200, wan2=201, wg0=202).
--                      The daemon syncs these to /etc/iproute2/rt_tables.
--   fw_policy_rules  = 'ip rule add fwmark X lookup Y priority Z'.
--   fw_static_routes.table_id = which named table the route lives in
--                              (NULL = main table).
--
-- A NetFirewall apply-policy-routing diffs DB → kernel and reconciles.


CREATE TABLE IF NOT EXISTS fw_route_tables (
    id          uuid                     PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Numeric rt_tables ID (200..252 is the "user" range; 0,253,254,255 reserved).
    table_id    int                      NOT NULL UNIQUE,
    -- Symbolic name written to /etc/iproute2/rt_tables ("wan1", "wg0", …).
    table_name  varchar(50)              NOT NULL UNIQUE,
    description varchar(255),
    enabled     boolean                  NOT NULL DEFAULT true,
    created_at  timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT chk_table_id_range CHECK (table_id BETWEEN 1 AND 252)
);

CREATE TABLE IF NOT EXISTS fw_policy_rules (
    id           uuid                     PRIMARY KEY DEFAULT gen_random_uuid(),
    fwmark       bigint                   NOT NULL,                            -- e.g. 256 (0x100)
    -- The named table this rule looks up. Soft FK so a rule survives table renaming via UI.
    table_name   varchar(50)              NOT NULL,
    -- Kernel priority (lower = matched first). NULL = let kernel assign.
    priority     int,
    description  varchar(255),
    enabled      boolean                  NOT NULL DEFAULT true,
    created_at   timestamp with time zone NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_fw_policy_rules_fwmark
    ON fw_policy_rules (fwmark);

-- Tie static routes to a named table. Existing rows stay NULL → main table.
ALTER TABLE fw_static_routes
    ADD COLUMN IF NOT EXISTS table_id uuid REFERENCES fw_route_tables(id) ON DELETE SET NULL;

-- Allow apply_history to record the new kind.
ALTER TABLE fw_apply_history
    DROP CONSTRAINT IF EXISTS chk_apply_kind;
ALTER TABLE fw_apply_history
    ADD CONSTRAINT chk_apply_kind CHECK (kind IN ('nftables','tc','wireguard','routing'));

