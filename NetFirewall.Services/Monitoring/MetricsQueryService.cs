using System.Text.Json;
using Npgsql;

namespace NetFirewall.Services.Monitoring;

/// <summary>
/// Service for querying historical system metrics.
/// </summary>
public interface IMetricsQueryService
{
    /// <summary>
    /// Get raw metrics for a time range (max 24 hours recommended).
    /// </summary>
    Task<IReadOnlyList<MetricPoint>> GetRawMetricsAsync(
        DateTime from, DateTime to,
        string? hostname = null,
        CancellationToken ct = default);

    /// <summary>
    /// Get hourly aggregated metrics.
    /// </summary>
    Task<IReadOnlyList<MetricAggregate>> GetHourlyMetricsAsync(
        DateTime from, DateTime to,
        string? hostname = null,
        CancellationToken ct = default);

    /// <summary>
    /// Get daily aggregated metrics.
    /// </summary>
    Task<IReadOnlyList<MetricAggregate>> GetDailyMetricsAsync(
        DateTime from, DateTime to,
        string? hostname = null,
        CancellationToken ct = default);

    /// <summary>
    /// Get metrics summary for dashboard display.
    /// </summary>
    Task<MetricsSummary> GetSummaryAsync(
        string? hostname = null,
        CancellationToken ct = default);
}

/// <summary>
/// Single metric data point.
/// </summary>
public record MetricPoint
{
    public DateTime Timestamp { get; init; }
    public string Hostname { get; init; } = "";
    public double CpuUsage { get; init; }
    public double MemoryUsagePercent { get; init; }
    public long MemoryUsedBytes { get; init; }
    public double LoadAvg1m { get; init; }
    public double NetworkRxRate { get; init; }
    public double NetworkTxRate { get; init; }
}

/// <summary>
/// Aggregated metric data.
/// </summary>
public record MetricAggregate
{
    public DateTime Bucket { get; init; }
    public string Hostname { get; init; } = "";
    public double CpuAvg { get; init; }
    public double CpuMax { get; init; }
    public double CpuMin { get; init; }
    public double MemoryUsedAvg { get; init; }
    public long MemoryUsedMax { get; init; }
    public double LoadAvg { get; init; }
    public double LoadMax { get; init; }
    public long NetworkRxTotal { get; init; }
    public long NetworkTxTotal { get; init; }
    public int SampleCount { get; init; }
}

/// <summary>
/// Dashboard metrics summary.
/// </summary>
public record MetricsSummary
{
    public double CurrentCpuUsage { get; init; }
    public double AvgCpuUsage24h { get; init; }
    public double MaxCpuUsage24h { get; init; }

    public double CurrentMemoryUsagePercent { get; init; }
    public double AvgMemoryUsagePercent24h { get; init; }

    public double CurrentLoadAvg { get; init; }
    public double MaxLoadAvg24h { get; init; }

    public long NetworkRxBytes24h { get; init; }
    public long NetworkTxBytes24h { get; init; }

    public IReadOnlyList<DiskUsageSummary> DiskUsage { get; init; } = [];

    public DateTime LastUpdate { get; init; }
    public TimeSpan Uptime { get; init; }
}

public record DiskUsageSummary
{
    public string MountPoint { get; init; } = "";
    public long TotalBytes { get; init; }
    public long UsedBytes { get; init; }
    public double UsagePercent { get; init; }
}

public sealed class MetricsQueryService : IMetricsQueryService
{
    private readonly NpgsqlDataSource _dataSource;

    public MetricsQueryService(NpgsqlDataSource dataSource)
    {
        _dataSource = dataSource;
    }

    public async Task<IReadOnlyList<MetricPoint>> GetRawMetricsAsync(
        DateTime from, DateTime to,
        string? hostname = null,
        CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        var sql = @"
            SELECT timestamp, hostname,
                   cpu_usage_percent, memory_used_bytes,
                   memory_used_bytes * 100.0 / NULLIF(memory_total_bytes, 0) as mem_pct,
                   load_avg_1m, network_rx_rate, network_tx_rate
            FROM system_metrics
            WHERE timestamp >= @from AND timestamp <= @to";

        if (hostname != null)
            sql += " AND hostname = @host";

        sql += " ORDER BY timestamp ASC";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("from", from);
        cmd.Parameters.AddWithValue("to", to);
        if (hostname != null)
            cmd.Parameters.AddWithValue("host", hostname);

        var results = new List<MetricPoint>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        while (await reader.ReadAsync(ct))
        {
            results.Add(new MetricPoint
            {
                Timestamp = reader.GetDateTime(0),
                Hostname = reader.GetString(1),
                CpuUsage = reader.GetDouble(2),
                MemoryUsedBytes = reader.GetInt64(3),
                MemoryUsagePercent = reader.IsDBNull(4) ? 0 : reader.GetDouble(4),
                LoadAvg1m = reader.GetDouble(5),
                NetworkRxRate = reader.GetDouble(6),
                NetworkTxRate = reader.GetDouble(7)
            });
        }

        return results;
    }

    public async Task<IReadOnlyList<MetricAggregate>> GetHourlyMetricsAsync(
        DateTime from, DateTime to,
        string? hostname = null,
        CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        var sql = @"
            SELECT hour_bucket, hostname,
                   cpu_usage_avg, cpu_usage_max, cpu_usage_min,
                   memory_used_avg, memory_used_max,
                   load_avg_1m_avg, load_avg_1m_max,
                   network_rx_total, network_tx_total,
                   sample_count
            FROM system_metrics_hourly
            WHERE hour_bucket >= @from AND hour_bucket <= @to";

        if (hostname != null)
            sql += " AND hostname = @host";

        sql += " ORDER BY hour_bucket ASC";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("from", from);
        cmd.Parameters.AddWithValue("to", to);
        if (hostname != null)
            cmd.Parameters.AddWithValue("host", hostname);

        return await ReadAggregatesAsync(cmd, ct);
    }

    public async Task<IReadOnlyList<MetricAggregate>> GetDailyMetricsAsync(
        DateTime from, DateTime to,
        string? hostname = null,
        CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        var sql = @"
            SELECT day_bucket, hostname,
                   cpu_usage_avg, cpu_usage_max, cpu_usage_min,
                   memory_used_avg, memory_used_max,
                   load_avg_1m_avg, load_avg_1m_max,
                   network_rx_total, network_tx_total,
                   sample_count
            FROM system_metrics_daily
            WHERE day_bucket >= @from AND day_bucket <= @to";

        if (hostname != null)
            sql += " AND hostname = @host";

        sql += " ORDER BY day_bucket ASC";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("from", from.Date);
        cmd.Parameters.AddWithValue("to", to.Date);
        if (hostname != null)
            cmd.Parameters.AddWithValue("host", hostname);

        return await ReadAggregatesAsync(cmd, ct);
    }

    public async Task<MetricsSummary> GetSummaryAsync(
        string? hostname = null,
        CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        // Get latest metrics
        var latestSql = @"
            SELECT timestamp, hostname,
                   cpu_usage_percent, memory_used_bytes, memory_total_bytes,
                   load_avg_1m, disk_usage_json
            FROM system_metrics
            WHERE timestamp > NOW() - INTERVAL '1 minute'";

        if (hostname != null)
            latestSql += " AND hostname = @host";

        latestSql += " ORDER BY timestamp DESC LIMIT 1";

        await using var latestCmd = new NpgsqlCommand(latestSql, conn);
        if (hostname != null)
            latestCmd.Parameters.AddWithValue("host", hostname);

        double currentCpu = 0, currentMemPct = 0, currentLoad = 0;
        var diskUsage = new List<DiskUsageSummary>();
        DateTime lastUpdate = DateTime.MinValue;

        await using (var reader = await latestCmd.ExecuteReaderAsync(ct))
        {
            if (await reader.ReadAsync(ct))
            {
                lastUpdate = reader.GetDateTime(0);
                currentCpu = reader.GetDouble(2);
                var memUsed = reader.GetInt64(3);
                var memTotal = reader.GetInt64(4);
                currentMemPct = memTotal > 0 ? (double)memUsed / memTotal * 100 : 0;
                currentLoad = reader.GetDouble(5);

                if (!reader.IsDBNull(6))
                {
                    var diskJson = reader.GetString(6);
                    var disks = JsonSerializer.Deserialize<List<DiskJsonEntry>>(diskJson);
                    if (disks != null)
                    {
                        diskUsage = disks.Select(d => new DiskUsageSummary
                        {
                            MountPoint = d.mount ?? "",
                            TotalBytes = d.total,
                            UsedBytes = d.used,
                            UsagePercent = d.percent
                        }).ToList();
                    }
                }
            }
        }

        // Get 24h aggregates
        var aggSql = @"
            SELECT AVG(cpu_usage_avg) as cpu_avg,
                   MAX(cpu_usage_max) as cpu_max,
                   AVG(memory_used_avg) / NULLIF(MAX(memory_used_max), 0) * 100 as mem_avg_pct,
                   MAX(load_avg_1m_max) as load_max,
                   SUM(network_rx_total) as rx_total,
                   SUM(network_tx_total) as tx_total
            FROM system_metrics_hourly
            WHERE hour_bucket > NOW() - INTERVAL '24 hours'";

        if (hostname != null)
            aggSql += " AND hostname = @host";

        await using var aggCmd = new NpgsqlCommand(aggSql, conn);
        if (hostname != null)
            aggCmd.Parameters.AddWithValue("host", hostname);

        double avgCpu24h = 0, maxCpu24h = 0, avgMem24h = 0, maxLoad24h = 0;
        long rxBytes24h = 0, txBytes24h = 0;

        await using (var reader = await aggCmd.ExecuteReaderAsync(ct))
        {
            if (await reader.ReadAsync(ct))
            {
                avgCpu24h = reader.IsDBNull(0) ? 0 : reader.GetDouble(0);
                maxCpu24h = reader.IsDBNull(1) ? 0 : reader.GetDouble(1);
                avgMem24h = reader.IsDBNull(2) ? 0 : reader.GetDouble(2);
                maxLoad24h = reader.IsDBNull(3) ? 0 : reader.GetDouble(3);
                rxBytes24h = reader.IsDBNull(4) ? 0 : reader.GetInt64(4);
                txBytes24h = reader.IsDBNull(5) ? 0 : reader.GetInt64(5);
            }
        }

        return new MetricsSummary
        {
            CurrentCpuUsage = currentCpu,
            AvgCpuUsage24h = avgCpu24h,
            MaxCpuUsage24h = maxCpu24h,
            CurrentMemoryUsagePercent = currentMemPct,
            AvgMemoryUsagePercent24h = avgMem24h,
            CurrentLoadAvg = currentLoad,
            MaxLoadAvg24h = maxLoad24h,
            NetworkRxBytes24h = rxBytes24h,
            NetworkTxBytes24h = txBytes24h,
            DiskUsage = diskUsage,
            LastUpdate = lastUpdate
        };
    }

    private static async Task<IReadOnlyList<MetricAggregate>> ReadAggregatesAsync(
        NpgsqlCommand cmd, CancellationToken ct)
    {
        var results = new List<MetricAggregate>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        while (await reader.ReadAsync(ct))
        {
            results.Add(new MetricAggregate
            {
                Bucket = reader.GetDateTime(0),
                Hostname = reader.GetString(1),
                CpuAvg = reader.GetDouble(2),
                CpuMax = reader.GetDouble(3),
                CpuMin = reader.GetDouble(4),
                MemoryUsedAvg = reader.GetDouble(5),
                MemoryUsedMax = reader.GetInt64(6),
                LoadAvg = reader.GetDouble(7),
                LoadMax = reader.GetDouble(8),
                NetworkRxTotal = reader.GetInt64(9),
                NetworkTxTotal = reader.GetInt64(10),
                SampleCount = reader.GetInt32(11)
            });
        }

        return results;
    }

    private record DiskJsonEntry
    {
        public string? mount { get; init; }
        public long total { get; init; }
        public long used { get; init; }
        public double percent { get; init; }
    }
}
