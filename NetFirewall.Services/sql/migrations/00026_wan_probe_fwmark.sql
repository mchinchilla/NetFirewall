-- WAN probe via fwmark.
--
-- 'ping -I ens224 8.8.8.8' doesn't actually force egress through ens224
-- when the source IP doesn't have a matching `ip rule from` and the main
-- table points to the other WAN. Result: the probe goes out the wrong
-- interface, gets a reply, but the WAN we're testing is invisible. Solved
-- by marking the ping packet (`ping -m <fwmark>`) so the existing
-- `ip rule fwmark X lookup wanN` policy route kicks in.
--
-- probe_fwmark is the fwmark value to put on probe packets for this WAN.
-- Typically matches the policy rule for the WAN (256/0x100 for wan1,
-- 512/0x200 for wan2, etc.). NULL = fall back to -I (legacy behavior;
-- works fine when the probe target is L2-adjacent like the gateway).


ALTER TABLE wan_health_config
    ADD COLUMN IF NOT EXISTS probe_fwmark bigint;

