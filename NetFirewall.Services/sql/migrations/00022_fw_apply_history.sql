-- Track every Apply (nftables / tc / wireguard) so the dashboard can tell
-- the operator "you have N changes in the DB that haven't been pushed to the
-- kernel yet". Compared against MAX(fw_audit_log.created_at WHERE table_name
-- LIKE 'fw_%') to detect drift.
--
-- We don't store the rendered config — that already lives in
-- /var/lib/netfirewall/backups (the daemon's pre-apply snapshot).


CREATE TABLE IF NOT EXISTS fw_apply_history (
    id          uuid                     PRIMARY KEY DEFAULT gen_random_uuid(),
    kind        varchar(20)              NOT NULL,                            -- nftables | tc | wireguard
    success     boolean                  NOT NULL,
    applied_at  timestamp with time zone NOT NULL DEFAULT now(),
    applied_by  varchar(100),                                                  -- username from session (nullable for unauth daemon ops)
    exit_code   int,
    message     text,                                                          -- short, human-readable summary
    CONSTRAINT chk_apply_kind CHECK (kind IN ('nftables','tc','wireguard'))
);

CREATE INDEX IF NOT EXISTS idx_fw_apply_history_kind_applied
    ON fw_apply_history (kind, applied_at DESC);

