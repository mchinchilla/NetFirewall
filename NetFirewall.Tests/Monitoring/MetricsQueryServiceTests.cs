using NetFirewall.Services.Monitoring;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Monitoring;

/// <summary>
/// Real-Postgres coverage for <see cref="MetricsQueryService"/>. Verifies the
/// time-window filters, hostname filter, and that hourly/daily rollups read
/// from their respective aggregate tables.
/// </summary>
[Collection("Postgres")]
public sealed class MetricsQueryServiceTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private MetricsQueryService _svc = null!;

    public MetricsQueryServiceTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _svc = new MetricsQueryService(_pg.DataSource);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private async Task InsertRawAsync(DateTime ts, string host = "host1",
        double cpu = 10, long memUsed = 1000, long memTotal = 4000,
        double load = 0.5, double rxRate = 100, double txRate = 50)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(@"
            INSERT INTO system_metrics
                (timestamp, hostname,
                 cpu_usage_percent, cpu_user_percent, cpu_system_percent, cpu_iowait_percent, cpu_idle_percent,
                 memory_total_bytes, memory_used_bytes, memory_available_bytes, memory_cached_bytes,
                 swap_total_bytes, swap_used_bytes,
                 load_avg_1m, load_avg_5m, load_avg_15m,
                 network_rx_bytes, network_tx_bytes, network_rx_rate, network_tx_rate)
            VALUES (@ts, @h,
                    @cpu, 5, 5, 0, @idle,
                    @memT, @memU, @memT - @memU, 0,
                    0, 0,
                    @load, @load, @load,
                    0, 0, @rx, @tx)", conn);
        cmd.Parameters.AddWithValue("ts", ts);
        cmd.Parameters.AddWithValue("h", host);
        cmd.Parameters.AddWithValue("cpu", cpu);
        cmd.Parameters.AddWithValue("idle", 100 - cpu);
        cmd.Parameters.AddWithValue("memT", memTotal);
        cmd.Parameters.AddWithValue("memU", memUsed);
        cmd.Parameters.AddWithValue("load", load);
        cmd.Parameters.AddWithValue("rx", rxRate);
        cmd.Parameters.AddWithValue("tx", txRate);
        await cmd.ExecuteNonQueryAsync();
    }

    private async Task InsertHourlyAsync(DateTime hourBucket, string host = "host1",
        double cpuAvg = 50, int samples = 720)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(@"
            INSERT INTO system_metrics_hourly
                (hour_bucket, hostname,
                 cpu_usage_avg, cpu_usage_max, cpu_usage_min,
                 memory_used_avg, memory_used_max,
                 load_avg_1m_avg, load_avg_1m_max,
                 network_rx_total, network_tx_total,
                 sample_count)
            VALUES (@hb, @h, @cpu, @cpu + 10, @cpu - 10, 1000, 2000, 0.5, 1.0, 1000, 500, @s)", conn);
        cmd.Parameters.AddWithValue("hb", hourBucket);
        cmd.Parameters.AddWithValue("h", host);
        cmd.Parameters.AddWithValue("cpu", cpuAvg);
        cmd.Parameters.AddWithValue("s", samples);
        await cmd.ExecuteNonQueryAsync();
    }

    // ── Raw metrics ────────────────────────────────────────────────────

    [Fact]
    public async Task GetRawMetricsAsync_OnlyReturnsRowsInsideTimeRange()
    {
        var now = DateTime.UtcNow;
        await InsertRawAsync(now.AddHours(-3));            // outside (before)
        await InsertRawAsync(now.AddMinutes(-30), cpu: 25);// inside
        await InsertRawAsync(now.AddMinutes(-15), cpu: 35);// inside
        await InsertRawAsync(now.AddMinutes(5));           // outside (after)

        var rows = await _svc.GetRawMetricsAsync(
            from: now.AddHours(-1),
            to: now);

        Assert.Equal(2, rows.Count);
        Assert.Equal(25, rows[0].CpuUsage);
        Assert.Equal(35, rows[1].CpuUsage);
    }

    [Fact]
    public async Task GetRawMetricsAsync_OrdersAscByTimestamp()
    {
        var now = DateTime.UtcNow;
        await InsertRawAsync(now.AddMinutes(-10), cpu: 20);
        await InsertRawAsync(now.AddMinutes(-30), cpu: 10);
        await InsertRawAsync(now.AddMinutes(-5),  cpu: 30);

        var rows = await _svc.GetRawMetricsAsync(now.AddHours(-1), now);

        Assert.Equal(3, rows.Count);
        Assert.Equal(new double[] { 10, 20, 30 }, rows.Select(r => r.CpuUsage));
    }

    [Fact]
    public async Task GetRawMetricsAsync_HostnameFilter_OnlyReturnsMatchingHost()
    {
        var now = DateTime.UtcNow;
        await InsertRawAsync(now.AddMinutes(-10), host: "alpha");
        await InsertRawAsync(now.AddMinutes(-10), host: "beta");
        await InsertRawAsync(now.AddMinutes(-5),  host: "alpha");

        var rows = await _svc.GetRawMetricsAsync(now.AddHours(-1), now, hostname: "alpha");

        Assert.Equal(2, rows.Count);
        Assert.All(rows, r => Assert.Equal("alpha", r.Hostname));
    }

    [Fact]
    public async Task GetRawMetricsAsync_ComputesMemoryPercentageFromTotalAndUsed()
    {
        var now = DateTime.UtcNow;
        await InsertRawAsync(now.AddMinutes(-5), memTotal: 4000, memUsed: 1000); // 25%

        var rows = await _svc.GetRawMetricsAsync(now.AddHours(-1), now);
        var hit = Assert.Single(rows);
        Assert.Equal(25.0, hit.MemoryUsagePercent);
    }

    [Fact]
    public async Task GetRawMetricsAsync_MemoryTotalZero_PercentageIsZero_NoDivByZeroCrash()
    {
        var now = DateTime.UtcNow;
        await InsertRawAsync(now.AddMinutes(-5), memTotal: 0, memUsed: 0);

        var rows = await _svc.GetRawMetricsAsync(now.AddHours(-1), now);
        Assert.Equal(0, rows[0].MemoryUsagePercent);
    }

    [Fact]
    public async Task GetRawMetricsAsync_EmptyRange_ReturnsEmpty()
    {
        var rows = await _svc.GetRawMetricsAsync(DateTime.UtcNow.AddDays(-1), DateTime.UtcNow);
        Assert.Empty(rows);
    }

    // ── Hourly rollups ─────────────────────────────────────────────────

    [Fact]
    public async Task GetHourlyMetricsAsync_FiltersByBucketRange_AndOrdersAsc()
    {
        var now = DateTime.UtcNow;
        await InsertHourlyAsync(now.AddHours(-5), cpuAvg: 10);
        await InsertHourlyAsync(now.AddHours(-2), cpuAvg: 20);
        await InsertHourlyAsync(now.AddHours(-1), cpuAvg: 30);
        await InsertHourlyAsync(now.AddHours(2),  cpuAvg: 40); // outside

        var rows = await _svc.GetHourlyMetricsAsync(now.AddHours(-3), now);

        Assert.Equal(2, rows.Count);
        Assert.Equal(20, rows[0].CpuAvg);
        Assert.Equal(30, rows[1].CpuAvg);
    }

    [Fact]
    public async Task GetHourlyMetricsAsync_PopulatesAggregateFields()
    {
        var now = DateTime.UtcNow;
        await InsertHourlyAsync(now.AddHours(-1), cpuAvg: 50, samples: 720);

        var rows = await _svc.GetHourlyMetricsAsync(now.AddHours(-2), now);
        var row = Assert.Single(rows);
        Assert.Equal(50, row.CpuAvg);
        Assert.Equal(60, row.CpuMax); // cpuAvg + 10
        Assert.Equal(40, row.CpuMin); // cpuAvg - 10
        Assert.Equal(720, row.SampleCount);
    }

    [Fact]
    public async Task GetHourlyMetricsAsync_HostFilterWorks()
    {
        var now = DateTime.UtcNow;
        await InsertHourlyAsync(now.AddHours(-1), host: "alpha");
        await InsertHourlyAsync(now.AddHours(-1), host: "beta");

        var alphaOnly = await _svc.GetHourlyMetricsAsync(now.AddHours(-2), now, hostname: "alpha");
        Assert.Single(alphaOnly);
        Assert.Equal("alpha", alphaOnly[0].Hostname);
    }

    // ── per-WAN live series ────────────────────────────────────────────

    [Fact]
    public async Task GetWanRatePerInterfaceAsync_OnlyReturnsWan_AndGroupsByName()
    {
        var now = DateTime.UtcNow;
        await InsertIfaceAsync("ens192", "WAN");
        await InsertIfaceAsync("ens160", "LAN");
        await InsertNetAsync(now.AddMinutes(-2), "ens192", rx: 100, tx: 10);
        await InsertNetAsync(now.AddMinutes(-1), "ens192", rx: 200, tx: 20);
        await InsertNetAsync(now.AddMinutes(-1), "ens160", rx: 999, tx: 999);

        var series = await _svc.GetWanRatePerInterfaceAsync(15);
        var wan = Assert.Single(series);
        Assert.Equal("ens192", wan.InterfaceName);
        Assert.Equal(2, wan.Points.Count);
        Assert.Equal(100, wan.Points[0].RxBytesPerSec);
        Assert.Equal(200, wan.Points[1].RxBytesPerSec);
    }

    [Fact]
    public async Task GetWanRatePerInterfaceAsync_IgnoresSamplesOutsideWindow()
    {
        await InsertIfaceAsync("ens192", "WAN");
        await InsertNetAsync(DateTime.UtcNow.AddHours(-3), "ens192", rx: 50, tx: 5);

        var series = await _svc.GetWanRatePerInterfaceAsync(15);
        Assert.Empty(series);
    }

    private async Task InsertIfaceAsync(string name, string type)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(@"
            INSERT INTO fw_interfaces (id, name, type, addressing_mode, auto_start, enabled, created_at, updated_at)
            VALUES (@id, @n, @t, 'static', true, true, now(), now())", conn);
        cmd.Parameters.AddWithValue("id", Guid.NewGuid());
        cmd.Parameters.AddWithValue("n", name);
        cmd.Parameters.AddWithValue("t", type);
        await cmd.ExecuteNonQueryAsync();
    }

    private async Task InsertNetAsync(DateTime ts, string iface, double rx, double tx)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(@"
            INSERT INTO system_metrics_net
                (timestamp, hostname, interface_name, rx_bytes, tx_bytes, rx_rate, tx_rate)
            VALUES (@ts, 'host1', @iface, 0, 0, @rx, @tx)", conn);
        cmd.Parameters.AddWithValue("ts", ts);
        cmd.Parameters.AddWithValue("iface", iface);
        cmd.Parameters.AddWithValue("rx", rx);
        cmd.Parameters.AddWithValue("tx", tx);
        await cmd.ExecuteNonQueryAsync();
    }
}
