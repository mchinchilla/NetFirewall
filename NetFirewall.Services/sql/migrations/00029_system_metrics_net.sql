-- Per-interface network metrics. The old system_metrics(.network_rx/tx) stored
-- the SUM across ALL interfaces, which double-counts every routed packet (it's
-- RX on the LAN NIC and TX on the WAN NIC) and makes in≈out — wrong for a router.
--
-- These tables keep RX/TX PER INTERFACE so the chart can sum only the WAN side
-- (real Internet download/upload) and we can later graph per-NIC. Mirrors the
-- system_metrics / system_metrics_hourly raw+rollup shape.
--
-- rx_bytes/tx_bytes are the kernel's cumulative counters (from /proc/net/dev);
-- the hourly rollup takes MAX-MIN to get the delta for the hour, same as the
-- existing aggregation. rx_rate/tx_rate are the instantaneous bytes/sec.

BEGIN;

CREATE TABLE IF NOT EXISTS system_metrics_net (
    id             bigserial                PRIMARY KEY,
    timestamp      timestamp with time zone NOT NULL,
    hostname       varchar(255)             NOT NULL,
    interface_name varchar(64)              NOT NULL,
    rx_bytes       bigint                   NOT NULL,   -- cumulative counter
    tx_bytes       bigint                   NOT NULL,
    rx_rate        double precision         NOT NULL,   -- bytes/sec, instantaneous
    tx_rate        double precision         NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sysmetrics_net_ts    ON system_metrics_net (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_sysmetrics_net_iface ON system_metrics_net (interface_name, timestamp DESC);

CREATE TABLE IF NOT EXISTS system_metrics_net_hourly (
    hour_bucket    timestamp with time zone NOT NULL,
    hostname       varchar(255)             NOT NULL,
    interface_name varchar(64)              NOT NULL,
    rx_total       bigint                   NOT NULL,   -- bytes in the hour (MAX-MIN)
    tx_total       bigint                   NOT NULL,
    rx_rate_avg    double precision         NOT NULL,
    tx_rate_avg    double precision         NOT NULL,
    sample_count   int                      NOT NULL,
    PRIMARY KEY (hour_bucket, hostname, interface_name)
);

CREATE INDEX IF NOT EXISTS idx_sysmetrics_net_hourly_bucket
    ON system_metrics_net_hourly (hour_bucket DESC);

COMMIT;
