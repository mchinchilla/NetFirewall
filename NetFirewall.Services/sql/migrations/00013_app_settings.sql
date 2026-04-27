-- 00013_app_settings.sql
-- Minimal key/value store for runtime-tunable settings. The descriptor catalog
-- (label, type, default, allowed values, category) lives in code so adding a
-- new setting is one line in AppSettingDescriptors — not a migration.
-- Rows here only exist for settings the operator has changed from their default.

CREATE TABLE IF NOT EXISTS app_settings (
    key        VARCHAR(100) PRIMARY KEY,
    value      TEXT         NOT NULL,
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_by VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_app_settings_updated_at
    ON app_settings (updated_at DESC);
