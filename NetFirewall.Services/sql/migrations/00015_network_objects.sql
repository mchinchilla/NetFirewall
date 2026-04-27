-- 00015_network_objects.sql
-- Named, reusable address objects (the "alias" pattern from pfSense/OPNsense
-- and "address objects" from commercial firewalls). Filter / NAT / mangle
-- rules reference these by name — when the value changes, every rule that
-- references the object picks up the new value at the next apply.
--
-- Types:
--   host    — single IP, value stores "10.0.0.5" (or "10.0.0.5/32")
--   network — CIDR,      value stores "10.0.0.0/24"
--   range   — start-end, value stores "10.0.0.10-10.0.0.50"
--   group   — composition of other objects; value is empty, members live
--             in network_object_members. Cycle prevention is enforced in
--             the resolver, not the schema.
--
-- Names are unique and used as the in-rule reference. Convention: UPPER_SNAKE
-- to make them visually distinct from literal CIDRs.

CREATE TABLE IF NOT EXISTS network_objects (
    id          uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    name        varchar(80)  UNIQUE NOT NULL,
    type        varchar(20)  NOT NULL CHECK (type IN ('host', 'network', 'range', 'group')),
    value       text         NOT NULL DEFAULT '',
    description text,
    created_at  timestamptz  NOT NULL DEFAULT NOW(),
    updated_at  timestamptz  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS network_object_members (
    parent_id uuid NOT NULL REFERENCES network_objects(id) ON DELETE CASCADE,
    child_id  uuid NOT NULL REFERENCES network_objects(id) ON DELETE CASCADE,
    PRIMARY KEY (parent_id, child_id),
    CHECK (parent_id <> child_id)
);

CREATE INDEX IF NOT EXISTS idx_network_objects_type ON network_objects(type);
CREATE INDEX IF NOT EXISTS idx_network_object_members_child ON network_object_members(child_id);
