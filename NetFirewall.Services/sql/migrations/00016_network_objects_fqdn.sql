-- 00016_network_objects_fqdn.sql
-- Extend network_objects.type to allow 'fqdn' (DNS-resolved at apply time).
-- We have to drop+recreate the CHECK because Postgres doesn't support
-- "ALTER CHECK". The data move is null — the new constraint is a superset
-- of the old one.

ALTER TABLE network_objects DROP CONSTRAINT IF EXISTS network_objects_type_check;
ALTER TABLE network_objects ADD CONSTRAINT network_objects_type_check
    CHECK (type IN ('host', 'network', 'range', 'group', 'fqdn'));
