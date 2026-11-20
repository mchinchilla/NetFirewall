-- 00050_vpn_split_journal.sql
-- Splitting a dual-role wg0 (server + outbound tunnel) into two interfaces is reversible: the
-- executor records the state it changed here, and the split must be CONFIRMED within a deadline
-- or the watchdog reverts it (the operator may be connected through the very tunnel being split).
CREATE TABLE IF NOT EXISTS vpn_split_journal (
    id           uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_name  varchar(15)              NOT NULL,   -- the dual-role interface (stays: outbound)
    server_name  varchar(15)              NOT NULL,   -- the new server interface
    snapshot     jsonb                    NOT NULL,   -- what to restore on revert
    state        varchar(20)              NOT NULL,   -- pending | confirmed | reverted | revert_failed
    deadline     timestamp with time zone NOT NULL,
    created_by   text,
    created_at   timestamp with time zone NOT NULL DEFAULT now(),
    finished_at  timestamp with time zone,
    CONSTRAINT chk_vpn_split_state CHECK (state IN ('pending', 'confirmed', 'reverted', 'revert_failed'))
);
-- One split in flight at a time.
CREATE UNIQUE INDEX IF NOT EXISTS ux_vpn_split_pending ON vpn_split_journal ((true)) WHERE state = 'pending';
