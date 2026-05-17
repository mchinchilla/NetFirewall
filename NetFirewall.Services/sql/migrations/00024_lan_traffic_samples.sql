-- Top-talkers feed. The daemon's ConntrackSampler runs `conntrack -L` every
-- 30s, attributes the bytes-since-flow-start to the LAN-side source IP and
-- bucketizes by (src_ip, proto, dport). One row per sample window — we keep
-- a 7-day retention window so the dashboard can show "top hosts in the last
-- 24h" without scanning forever.
--
-- Schema-level decisions:
--   - dst_port is normalized to the SERVER side (lower of the two ports).
--     conntrack reports both ports of a flow; the server one is what we want
--     for grouping ("https" vs "ephemeral").
--   - bytes_in/out are deltas WITHIN the sample window (not flow-total),
--     so we can SUM() across windows without double counting.

BEGIN;

CREATE TABLE IF NOT EXISTS lan_traffic_samples (
    id          bigserial                PRIMARY KEY,
    sampled_at  timestamp with time zone NOT NULL DEFAULT now(),
    src_ip      inet                     NOT NULL,
    -- May be NULL for unidentified flows (e.g., ICMP). NULL means "no service
    -- attribution" — top-by-host still works, top-by-service skips them.
    proto       varchar(10),                       -- tcp | udp | icmp | other
    dst_port    int,                               -- server-side port
    bytes_in    bigint                   NOT NULL, -- bytes from src toward outside
    bytes_out   bigint                   NOT NULL, -- bytes coming back to src
    flow_count  int                      NOT NULL  -- distinct flows in this window
);

CREATE INDEX IF NOT EXISTS idx_lan_traffic_sampled_at  ON lan_traffic_samples (sampled_at DESC);
CREATE INDEX IF NOT EXISTS idx_lan_traffic_src         ON lan_traffic_samples (src_ip, sampled_at DESC);
CREATE INDEX IF NOT EXISTS idx_lan_traffic_service     ON lan_traffic_samples (proto, dst_port, sampled_at DESC);

COMMIT;
