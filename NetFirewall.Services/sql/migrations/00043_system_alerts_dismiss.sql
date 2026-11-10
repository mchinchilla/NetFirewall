-- Manual dismissal of UI alerts (the banner's "x" button).
--
-- Dismissed is deliberately NOT the same as resolved: level-triggered alerts
-- ("WAN ens224 is down", "VPN peer down") are re-raised by their monitor on every
-- probe while the condition lasts, which would un-resolve a manually resolved row
-- and put it straight back on the banner. A dismissed row stays hidden for as
-- long as that same occurrence is active; when the condition resolves and later
-- fires again, the upsert clears dismissed_at and the banner shows it anew.

ALTER TABLE system_alerts
    ADD COLUMN IF NOT EXISTS dismissed_at timestamp with time zone,
    ADD COLUMN IF NOT EXISTS dismissed_by text;

-- The banner query is now "unresolved AND not dismissed".
DROP INDEX IF EXISTS idx_system_alerts_active;
CREATE INDEX IF NOT EXISTS idx_system_alerts_active
    ON system_alerts (raised_at DESC)
    WHERE resolved_at IS NULL AND dismissed_at IS NULL;
