-- 00012_system_metrics.sql
-- Time-series tables for the host-monitoring collector.
-- Raw 5-second samples roll up into hourly aggregates (30 days) and then
-- daily aggregates (1 year). The collector itself prunes raw beyond 48h.

CREATE TABLE IF NOT EXISTS system_metrics (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hostname VARCHAR(255) NOT NULL,

    -- CPU
    cpu_usage_percent  DOUBLE PRECISION NOT NULL,
    cpu_user_percent   DOUBLE PRECISION NOT NULL,
    cpu_system_percent DOUBLE PRECISION NOT NULL,
    cpu_iowait_percent DOUBLE PRECISION NOT NULL,
    cpu_idle_percent   DOUBLE PRECISION NOT NULL,

    -- Memory
    memory_total_bytes     BIGINT NOT NULL,
    memory_used_bytes      BIGINT NOT NULL,
    memory_available_bytes BIGINT NOT NULL,
    memory_cached_bytes    BIGINT NOT NULL,
    swap_total_bytes       BIGINT NOT NULL,
    swap_used_bytes        BIGINT NOT NULL,

    -- Load
    load_avg_1m  DOUBLE PRECISION NOT NULL,
    load_avg_5m  DOUBLE PRECISION NOT NULL,
    load_avg_15m DOUBLE PRECISION NOT NULL,

    -- Network (totals + per-second rate at sample time)
    network_rx_bytes BIGINT NOT NULL,
    network_tx_bytes BIGINT NOT NULL,
    network_rx_rate  DOUBLE PRECISION NOT NULL,
    network_tx_rate  DOUBLE PRECISION NOT NULL,

    -- Disk usage snapshot — JSONB so we don't need a per-mount table
    disk_usage_json JSONB
);

CREATE TABLE IF NOT EXISTS system_metrics_hourly (
    hour_bucket TIMESTAMPTZ NOT NULL,
    hostname    VARCHAR(255) NOT NULL,

    cpu_usage_avg DOUBLE PRECISION NOT NULL,
    cpu_usage_max DOUBLE PRECISION NOT NULL,
    cpu_usage_min DOUBLE PRECISION NOT NULL,

    memory_used_avg DOUBLE PRECISION NOT NULL,
    memory_used_max BIGINT           NOT NULL,

    load_avg_1m_avg DOUBLE PRECISION NOT NULL,
    load_avg_1m_max DOUBLE PRECISION NOT NULL,

    network_rx_total BIGINT NOT NULL,
    network_tx_total BIGINT NOT NULL,

    sample_count INT NOT NULL,

    PRIMARY KEY (hour_bucket, hostname)
);

CREATE TABLE IF NOT EXISTS system_metrics_daily (
    day_bucket DATE         NOT NULL,
    hostname   VARCHAR(255) NOT NULL,

    cpu_usage_avg DOUBLE PRECISION NOT NULL,
    cpu_usage_max DOUBLE PRECISION NOT NULL,
    cpu_usage_min DOUBLE PRECISION NOT NULL,

    memory_used_avg DOUBLE PRECISION NOT NULL,
    memory_used_max BIGINT           NOT NULL,

    load_avg_1m_avg DOUBLE PRECISION NOT NULL,
    load_avg_1m_max DOUBLE PRECISION NOT NULL,

    network_rx_total BIGINT NOT NULL,
    network_tx_total BIGINT NOT NULL,

    sample_count INT NOT NULL,

    PRIMARY KEY (day_bucket, hostname)
);

CREATE INDEX IF NOT EXISTS idx_system_metrics_timestamp
    ON system_metrics (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_system_metrics_hostname_timestamp
    ON system_metrics (hostname, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_system_metrics_hourly_bucket
    ON system_metrics_hourly (hour_bucket DESC);
CREATE INDEX IF NOT EXISTS idx_system_metrics_daily_bucket
    ON system_metrics_daily (day_bucket DESC);
