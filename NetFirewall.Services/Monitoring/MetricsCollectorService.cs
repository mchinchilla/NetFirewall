using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;

namespace NetFirewall.Services.Monitoring;

/// <summary>
/// Configuration for the metrics collector background service.
/// </summary>
public class MetricsCollectorOptions
{
    /// <summary>
    /// Interval between metric samples (default: 5 seconds for raw data).
    /// </summary>
    public TimeSpan SampleInterval { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// How long to keep raw metric data (default: 48 hours).
    /// </summary>
    public TimeSpan RawDataRetention { get; set; } = TimeSpan.FromHours(48);

    /// <summary>
    /// Interval for hourly aggregation job (default: every hour at :05).
    /// </summary>
    public TimeSpan HourlyAggregationInterval { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// How long to keep hourly aggregates (default: 30 days).
    /// </summary>
    public TimeSpan HourlyDataRetention { get; set; } = TimeSpan.FromDays(30);

    /// <summary>
    /// How long to keep daily aggregates (default: 365 days).
    /// </summary>
    public TimeSpan DailyDataRetention { get; set; } = TimeSpan.FromDays(365);

    /// <summary>
    /// Enable/disable metrics collection.
    /// </summary>
    public bool Enabled { get; set; } = true;
}

/// <summary>
/// Background service that collects system metrics at regular intervals
/// and stores them in PostgreSQL with automatic aggregation and cleanup.
/// </summary>
public sealed class MetricsCollectorService : BackgroundService
{
    private readonly ISystemMonitorService _monitor;
    private readonly NpgsqlDataSource _dataSource;
    private readonly ILogger<MetricsCollectorService> _logger;
    private readonly MetricsCollectorOptions _options;

    private DateTime _lastHourlyAggregation = DateTime.MinValue;
    private DateTime _lastDailyAggregation = DateTime.MinValue;
    private DateTime _lastCleanup = DateTime.MinValue;

    public MetricsCollectorService(
        ISystemMonitorService monitor,
        NpgsqlDataSource dataSource,
        IOptions<MetricsCollectorOptions> options,
        ILogger<MetricsCollectorService> logger)
    {
        _monitor = monitor;
        _dataSource = dataSource;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
        {
            _logger.LogInformation("Metrics collector is disabled");
            return;
        }

        _logger.LogInformation("Metrics collector started with {Interval}s sample interval",
            _options.SampleInterval.TotalSeconds);

        // Wait for database to be ready with retries
        var schemaInitialized = await InitializeWithRetryAsync(stoppingToken);
        if (!schemaInitialized)
        {
            _logger.LogWarning("Metrics collector could not initialize database schema, running in degraded mode");
        }

        using var timer = new PeriodicTimer(_options.SampleInterval);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (schemaInitialized || await TryEnsureSchemaAsync(stoppingToken))
                {
                    schemaInitialized = true;
                    await CollectAndStoreMetricsAsync(stoppingToken);
                    await RunMaintenanceTasksAsync(stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error collecting metrics, will retry");
            }

            await timer.WaitForNextTickAsync(stoppingToken);
        }

        _logger.LogInformation("Metrics collector stopped");
    }

    private async Task<bool> InitializeWithRetryAsync(CancellationToken ct)
    {
        var retryDelays = new[] { 1, 2, 5, 10, 30 }; // seconds

        foreach (var delay in retryDelays)
        {
            if (ct.IsCancellationRequested) return false;

            if (await TryEnsureSchemaAsync(ct))
                return true;

            _logger.LogWarning("Database not ready, retrying in {Delay}s...", delay);
            await Task.Delay(TimeSpan.FromSeconds(delay), ct);
        }

        return false;
    }

    private async Task<bool> TryEnsureSchemaAsync(CancellationToken ct)
    {
        try
        {
            await EnsureSchemaAsync(ct);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Schema initialization failed");
            return false;
        }
    }

    private async Task CollectAndStoreMetricsAsync(CancellationToken ct)
    {
        var snapshot = await _monitor.GetSnapshotAsync(ct);

        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        // Store raw metrics
        const string sql = @"
            INSERT INTO system_metrics (
                timestamp, hostname,
                cpu_usage_percent, cpu_user_percent, cpu_system_percent, cpu_iowait_percent, cpu_idle_percent,
                memory_total_bytes, memory_used_bytes, memory_available_bytes, memory_cached_bytes,
                swap_total_bytes, swap_used_bytes,
                load_avg_1m, load_avg_5m, load_avg_15m,
                network_rx_bytes, network_tx_bytes, network_rx_rate, network_tx_rate,
                disk_usage_json
            ) VALUES (
                @ts, @host,
                @cpuUsage, @cpuUser, @cpuSystem, @cpuIowait, @cpuIdle,
                @memTotal, @memUsed, @memAvail, @memCached,
                @swapTotal, @swapUsed,
                @load1, @load5, @load15,
                @netRx, @netTx, @netRxRate, @netTxRate,
                @diskJson::jsonb
            )";

        await using var cmd = new NpgsqlCommand(sql, conn);

        // Aggregate network stats
        var totalRxBytes = snapshot.Network.Sum(n => n.BytesReceived);
        var totalTxBytes = snapshot.Network.Sum(n => n.BytesSent);
        var totalRxRate = snapshot.Network.Sum(n => n.BytesReceivedPerSecond);
        var totalTxRate = snapshot.Network.Sum(n => n.BytesSentPerSecond);

        // Serialize disk info
        var diskJson = JsonSerializer.Serialize(snapshot.Disks.Select(d => new
        {
            mount = d.MountPoint,
            total = d.TotalBytes,
            used = d.UsedBytes,
            percent = d.UsagePercent
        }));

        cmd.Parameters.AddWithValue("ts", snapshot.Timestamp);
        cmd.Parameters.AddWithValue("host", snapshot.System.Hostname);
        cmd.Parameters.AddWithValue("cpuUsage", snapshot.Cpu.UsagePercent);
        cmd.Parameters.AddWithValue("cpuUser", snapshot.Cpu.UserPercent);
        cmd.Parameters.AddWithValue("cpuSystem", snapshot.Cpu.SystemPercent);
        cmd.Parameters.AddWithValue("cpuIowait", snapshot.Cpu.IoWaitPercent);
        cmd.Parameters.AddWithValue("cpuIdle", snapshot.Cpu.IdlePercent);
        cmd.Parameters.AddWithValue("memTotal", snapshot.Memory.TotalBytes);
        cmd.Parameters.AddWithValue("memUsed", snapshot.Memory.UsedBytes);
        cmd.Parameters.AddWithValue("memAvail", snapshot.Memory.AvailableBytes);
        cmd.Parameters.AddWithValue("memCached", snapshot.Memory.CachedBytes);
        cmd.Parameters.AddWithValue("swapTotal", snapshot.Memory.SwapTotalBytes);
        cmd.Parameters.AddWithValue("swapUsed", snapshot.Memory.SwapUsedBytes);
        cmd.Parameters.AddWithValue("load1", snapshot.System.LoadAverage1Min);
        cmd.Parameters.AddWithValue("load5", snapshot.System.LoadAverage5Min);
        cmd.Parameters.AddWithValue("load15", snapshot.System.LoadAverage15Min);
        cmd.Parameters.AddWithValue("netRx", totalRxBytes);
        cmd.Parameters.AddWithValue("netTx", totalTxBytes);
        cmd.Parameters.AddWithValue("netRxRate", totalRxRate);
        cmd.Parameters.AddWithValue("netTxRate", totalTxRate);
        cmd.Parameters.AddWithValue("diskJson", diskJson);

        await cmd.ExecuteNonQueryAsync(ct);
    }

    private async Task RunMaintenanceTasksAsync(CancellationToken ct)
    {
        var now = DateTime.UtcNow;

        // Run hourly aggregation
        if (now - _lastHourlyAggregation > TimeSpan.FromHours(1))
        {
            await RunHourlyAggregationAsync(ct);
            _lastHourlyAggregation = now;
        }

        // Run daily aggregation at midnight
        if (now.Date != _lastDailyAggregation.Date && now.Hour >= 1)
        {
            await RunDailyAggregationAsync(ct);
            _lastDailyAggregation = now;
        }

        // Run cleanup every 6 hours
        if (now - _lastCleanup > TimeSpan.FromHours(6))
        {
            await RunCleanupAsync(ct);
            _lastCleanup = now;
        }
    }

    private async Task RunHourlyAggregationAsync(CancellationToken ct)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        // Aggregate last hour's data
        const string sql = @"
            INSERT INTO system_metrics_hourly (
                hour_bucket, hostname,
                cpu_usage_avg, cpu_usage_max, cpu_usage_min,
                memory_used_avg, memory_used_max,
                load_avg_1m_avg, load_avg_1m_max,
                network_rx_total, network_tx_total,
                sample_count
            )
            SELECT
                date_trunc('hour', timestamp) as hour_bucket,
                hostname,
                AVG(cpu_usage_percent), MAX(cpu_usage_percent), MIN(cpu_usage_percent),
                AVG(memory_used_bytes), MAX(memory_used_bytes),
                AVG(load_avg_1m), MAX(load_avg_1m),
                MAX(network_rx_bytes) - MIN(network_rx_bytes),
                MAX(network_tx_bytes) - MIN(network_tx_bytes),
                COUNT(*)
            FROM system_metrics
            WHERE timestamp >= date_trunc('hour', NOW() - INTERVAL '1 hour')
              AND timestamp < date_trunc('hour', NOW())
            GROUP BY date_trunc('hour', timestamp), hostname
            ON CONFLICT (hour_bucket, hostname) DO UPDATE SET
                cpu_usage_avg = EXCLUDED.cpu_usage_avg,
                cpu_usage_max = EXCLUDED.cpu_usage_max,
                cpu_usage_min = EXCLUDED.cpu_usage_min,
                memory_used_avg = EXCLUDED.memory_used_avg,
                memory_used_max = EXCLUDED.memory_used_max,
                load_avg_1m_avg = EXCLUDED.load_avg_1m_avg,
                load_avg_1m_max = EXCLUDED.load_avg_1m_max,
                network_rx_total = EXCLUDED.network_rx_total,
                network_tx_total = EXCLUDED.network_tx_total,
                sample_count = EXCLUDED.sample_count";

        await using var cmd = new NpgsqlCommand(sql, conn);
        var rows = await cmd.ExecuteNonQueryAsync(ct);

        if (rows > 0)
            _logger.LogDebug("Hourly aggregation: {Rows} rows", rows);
    }

    private async Task RunDailyAggregationAsync(CancellationToken ct)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        const string sql = @"
            INSERT INTO system_metrics_daily (
                day_bucket, hostname,
                cpu_usage_avg, cpu_usage_max, cpu_usage_min,
                memory_used_avg, memory_used_max,
                load_avg_1m_avg, load_avg_1m_max,
                network_rx_total, network_tx_total,
                sample_count
            )
            SELECT
                hour_bucket::date as day_bucket,
                hostname,
                AVG(cpu_usage_avg), MAX(cpu_usage_max), MIN(cpu_usage_min),
                AVG(memory_used_avg), MAX(memory_used_max),
                AVG(load_avg_1m_avg), MAX(load_avg_1m_max),
                SUM(network_rx_total), SUM(network_tx_total),
                SUM(sample_count)
            FROM system_metrics_hourly
            WHERE hour_bucket >= (CURRENT_DATE - INTERVAL '1 day')
              AND hour_bucket < CURRENT_DATE
            GROUP BY hour_bucket::date, hostname
            ON CONFLICT (day_bucket, hostname) DO UPDATE SET
                cpu_usage_avg = EXCLUDED.cpu_usage_avg,
                cpu_usage_max = EXCLUDED.cpu_usage_max,
                cpu_usage_min = EXCLUDED.cpu_usage_min,
                memory_used_avg = EXCLUDED.memory_used_avg,
                memory_used_max = EXCLUDED.memory_used_max,
                load_avg_1m_avg = EXCLUDED.load_avg_1m_avg,
                load_avg_1m_max = EXCLUDED.load_avg_1m_max,
                network_rx_total = EXCLUDED.network_rx_total,
                network_tx_total = EXCLUDED.network_tx_total,
                sample_count = EXCLUDED.sample_count";

        await using var cmd = new NpgsqlCommand(sql, conn);
        var rows = await cmd.ExecuteNonQueryAsync(ct);

        if (rows > 0)
            _logger.LogInformation("Daily aggregation: {Rows} rows", rows);
    }

    private async Task RunCleanupAsync(CancellationToken ct)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        // Delete old raw data
        var rawCutoff = DateTime.UtcNow - _options.RawDataRetention;
        await using (var cmd = new NpgsqlCommand(
            "DELETE FROM system_metrics WHERE timestamp < @cutoff", conn))
        {
            cmd.Parameters.AddWithValue("cutoff", rawCutoff);
            var deleted = await cmd.ExecuteNonQueryAsync(ct);
            if (deleted > 0)
                _logger.LogInformation("Cleaned up {Count} raw metrics older than {Cutoff}",
                    deleted, rawCutoff);
        }

        // Delete old hourly data
        var hourlyCutoff = DateTime.UtcNow - _options.HourlyDataRetention;
        await using (var cmd = new NpgsqlCommand(
            "DELETE FROM system_metrics_hourly WHERE hour_bucket < @cutoff", conn))
        {
            cmd.Parameters.AddWithValue("cutoff", hourlyCutoff);
            var deleted = await cmd.ExecuteNonQueryAsync(ct);
            if (deleted > 0)
                _logger.LogInformation("Cleaned up {Count} hourly metrics", deleted);
        }

        // Delete old daily data
        var dailyCutoff = DateTime.UtcNow - _options.DailyDataRetention;
        await using (var cmd = new NpgsqlCommand(
            "DELETE FROM system_metrics_daily WHERE day_bucket < @cutoff", conn))
        {
            cmd.Parameters.AddWithValue("cutoff", dailyCutoff);
            var deleted = await cmd.ExecuteNonQueryAsync(ct);
            if (deleted > 0)
                _logger.LogInformation("Cleaned up {Count} daily metrics", deleted);
        }
    }

    private async Task EnsureSchemaAsync(CancellationToken ct)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        const string sql = @"
            -- Raw metrics (5-second samples, 48h retention)
            CREATE TABLE IF NOT EXISTS system_metrics (
                id BIGSERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                hostname VARCHAR(255) NOT NULL,

                -- CPU
                cpu_usage_percent DOUBLE PRECISION NOT NULL,
                cpu_user_percent DOUBLE PRECISION NOT NULL,
                cpu_system_percent DOUBLE PRECISION NOT NULL,
                cpu_iowait_percent DOUBLE PRECISION NOT NULL,
                cpu_idle_percent DOUBLE PRECISION NOT NULL,

                -- Memory
                memory_total_bytes BIGINT NOT NULL,
                memory_used_bytes BIGINT NOT NULL,
                memory_available_bytes BIGINT NOT NULL,
                memory_cached_bytes BIGINT NOT NULL,
                swap_total_bytes BIGINT NOT NULL,
                swap_used_bytes BIGINT NOT NULL,

                -- Load
                load_avg_1m DOUBLE PRECISION NOT NULL,
                load_avg_5m DOUBLE PRECISION NOT NULL,
                load_avg_15m DOUBLE PRECISION NOT NULL,

                -- Network (totals)
                network_rx_bytes BIGINT NOT NULL,
                network_tx_bytes BIGINT NOT NULL,
                network_rx_rate DOUBLE PRECISION NOT NULL,
                network_tx_rate DOUBLE PRECISION NOT NULL,

                -- Disk (JSONB for flexibility)
                disk_usage_json JSONB
            );

            -- Hourly aggregates (30 day retention)
            CREATE TABLE IF NOT EXISTS system_metrics_hourly (
                hour_bucket TIMESTAMPTZ NOT NULL,
                hostname VARCHAR(255) NOT NULL,

                cpu_usage_avg DOUBLE PRECISION NOT NULL,
                cpu_usage_max DOUBLE PRECISION NOT NULL,
                cpu_usage_min DOUBLE PRECISION NOT NULL,

                memory_used_avg DOUBLE PRECISION NOT NULL,
                memory_used_max BIGINT NOT NULL,

                load_avg_1m_avg DOUBLE PRECISION NOT NULL,
                load_avg_1m_max DOUBLE PRECISION NOT NULL,

                network_rx_total BIGINT NOT NULL,
                network_tx_total BIGINT NOT NULL,

                sample_count INT NOT NULL,

                PRIMARY KEY (hour_bucket, hostname)
            );

            -- Daily aggregates (365 day retention)
            CREATE TABLE IF NOT EXISTS system_metrics_daily (
                day_bucket DATE NOT NULL,
                hostname VARCHAR(255) NOT NULL,

                cpu_usage_avg DOUBLE PRECISION NOT NULL,
                cpu_usage_max DOUBLE PRECISION NOT NULL,
                cpu_usage_min DOUBLE PRECISION NOT NULL,

                memory_used_avg DOUBLE PRECISION NOT NULL,
                memory_used_max BIGINT NOT NULL,

                load_avg_1m_avg DOUBLE PRECISION NOT NULL,
                load_avg_1m_max DOUBLE PRECISION NOT NULL,

                network_rx_total BIGINT NOT NULL,
                network_tx_total BIGINT NOT NULL,

                sample_count INT NOT NULL,

                PRIMARY KEY (day_bucket, hostname)
            );

            -- Indexes for efficient queries
            CREATE INDEX IF NOT EXISTS idx_system_metrics_timestamp
                ON system_metrics (timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_system_metrics_hostname_timestamp
                ON system_metrics (hostname, timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_system_metrics_hourly_bucket
                ON system_metrics_hourly (hour_bucket DESC);
            CREATE INDEX IF NOT EXISTS idx_system_metrics_daily_bucket
                ON system_metrics_daily (day_bucket DESC);
        ";

        await using var cmd = new NpgsqlCommand(sql, conn);
        await cmd.ExecuteNonQueryAsync(ct);

        _logger.LogInformation("Metrics schema initialized");
    }
}
