-- Setup wizard state singleton.

CREATE TABLE IF NOT EXISTS setup_wizard_state (
    id                uuid                     DEFAULT uuid_generate_v4() PRIMARY KEY,
    current_step      int                      NOT NULL DEFAULT 1,
    is_completed      boolean                  NOT NULL DEFAULT false,
    interfaces_config jsonb,                                          -- Step 1
    lan_config        jsonb,                                          -- Step 2
    firewall_config   jsonb,                                          -- Step 3
    services_config   jsonb,                                          -- Step 4
    started_at        timestamp with time zone DEFAULT now(),
    completed_at      timestamp with time zone,
    updated_at        timestamp with time zone DEFAULT now()
);

-- Singleton: at most one row in the table.
CREATE UNIQUE INDEX IF NOT EXISTS idx_setup_wizard_singleton ON setup_wizard_state ((true));
