-- 00047_dhcp_custom_options_unique.sql
-- dhcp_custom_options becomes live (server emits them, Web manages them). One value per option
-- code per scope: a second row for the same (scope, code) would make the reply ambiguous.
-- Global rows have scope_id NULL, hence the COALESCE.
DELETE FROM dhcp_custom_options a
USING dhcp_custom_options b
WHERE a.scope_type = b.scope_type
  AND COALESCE(a.scope_id, '00000000-0000-0000-0000-000000000000'::uuid) = COALESCE(b.scope_id, '00000000-0000-0000-0000-000000000000'::uuid)
  AND a.option_code = b.option_code
  AND a.created_at < b.created_at;   -- keep the newest duplicate (the table had no writer, so normally a no-op)

CREATE UNIQUE INDEX IF NOT EXISTS ux_dhcp_custom_options_scope_code
    ON dhcp_custom_options (scope_type, COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid), option_code);
