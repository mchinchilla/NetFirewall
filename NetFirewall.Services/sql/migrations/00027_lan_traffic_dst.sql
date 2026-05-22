-- Per-destination accounting for the top-talkers feed. Until now the conntrack
-- sampler bucketed by (src_ip, proto, dst_port) and DISCARDED the destination,
-- so the panel could say how much a host sent but not WHERE. We now record the
-- real (forward-tuple) destination IP so the dashboard can drill into "which
-- hosts is device X talking to".
--
-- dst_ip is NULLABLE on purpose:
--   - existing rows predate the column and keep working,
--   - the per-host Top-N rollup stores the long tail as ONE row with
--     dst_ip IS NULL ("others"), so a chatty IoT/browser host doesn't explode
--     the table into thousands of rows per sample window.

BEGIN;

ALTER TABLE lan_traffic_samples
    ADD COLUMN IF NOT EXISTS dst_ip inet;

-- Per-host-per-destination drill-down queries.
CREATE INDEX IF NOT EXISTS idx_lan_traffic_src_dst
    ON lan_traffic_samples (src_ip, dst_ip, sampled_at DESC);

COMMIT;
