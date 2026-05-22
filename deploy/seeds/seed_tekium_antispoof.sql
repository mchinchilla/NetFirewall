-- Anti-spoofing on the WAN edge. A packet arriving on a WAN interface whose
-- SOURCE address is private/loopback/link-local cannot be legitimate — it's
-- spoofed (or misconfigured). Drop it before any accept rule sees it.
--
-- This complements the kernel rp_filter sysctl: rp_filter checks routability,
-- these rules are an explicit, logged, auditable belt-and-suspenders drop that
-- shows up in the firewall UI and the FORWARD/INPUT counters.
--
-- Priority 5 = evaluated before the established/related accept (10) and all the
-- service accepts (30+), so spoofed packets die first. Idempotent: re-running
-- updates the existing rows (matched by description) instead of duplicating.
--
-- Bogon source ranges dropped (RFC1918 + loopback + link-local + CGNAT + this-host):
--   10.0.0.0/8 · 172.16.0.0/12 · 192.168.0.0/16 · 127.0.0.0/8
--   169.254.0.0/16 · 100.64.0.0/10 · 0.0.0.0/8
--
-- Destination is restricted to `!= 224.0.0.0/4` (everything EXCEPT multicast).
-- Reason: ISPs legitimately send IGMP/multicast (DST=224.0.0.1, PROTO=2, TTL=1)
-- from their private 10.x access network. That's normal link-local network
-- management, not spoofing — matching it here would just log noise every ~2 min.
-- Excluding multicast lets that traffic fall through to the chain's default drop
-- silently, while still catching/logging bogon-sourced packets to real dsts.
-- (The generator renders a single-element destination_addresses without braces,
--  so '!= 224.0.0.0/4' emits the valid nft form `ip daddr != 224.0.0.0/4`.)

BEGIN;

-- Clean any previous copies so re-seeding is idempotent.
DELETE FROM fw_filter_rules WHERE description LIKE 'Anti-spoof: drop bogon src via %';

INSERT INTO fw_filter_rules
    (chain, action, protocol, interface_in_id,
     source_addresses, destination_addresses, log_prefix, enabled, priority, description)
SELECT
    'input', 'drop', NULL, i.id,
    ARRAY['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8',
          '169.254.0.0/16','100.64.0.0/10','0.0.0.0/8'],
    ARRAY['!= 224.0.0.0/4'],
    'SPOOFED_SRC: ', true, 5,
    'Anti-spoof: drop bogon src via ' || i.name
FROM fw_interfaces i
WHERE upper(i.type) = 'WAN';

-- Same on the forward chain — spoofed packets must not be routed into the LAN.
INSERT INTO fw_filter_rules
    (chain, action, protocol, interface_in_id,
     source_addresses, destination_addresses, log_prefix, enabled, priority, description)
SELECT
    'forward', 'drop', NULL, i.id,
    ARRAY['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8',
          '169.254.0.0/16','100.64.0.0/10','0.0.0.0/8'],
    ARRAY['!= 224.0.0.0/4'],
    'SPOOFED_SRC_FWD: ', true, 5,
    'Anti-spoof: drop bogon src via ' || i.name || ' (forward)'
FROM fw_interfaces i
WHERE upper(i.type) = 'WAN';

-- Verify what got inserted.
SELECT f.chain, f.priority, i.name AS wan_iface, f.action,
       array_to_string(f.source_addresses, ',') AS bogons, f.log_prefix
FROM fw_filter_rules f
JOIN fw_interfaces i ON i.id = f.interface_in_id
WHERE f.description LIKE 'Anti-spoof: drop bogon src via %'
ORDER BY f.chain, i.name;

COMMIT;
