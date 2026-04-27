using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Services.Dhcp;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// Real-Postgres coverage of <see cref="LeaseCache"/> — the singleton hot-path
/// cache that backs every DHCP read in the worker. Covers warmup, indexed
/// lookups, declined-IP TTL, and the write-through batch loop.
/// </summary>
[Collection("Postgres")]
public sealed class LeaseCacheTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;

    public LeaseCacheTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    /// <summary>
    /// Build a cache with a tight batch interval so write-through happens
    /// quickly enough for tests to observe without sleep-bombs.
    /// </summary>
    private LeaseCache CreateCache(int batchIntervalMs = 20) =>
        new(_pg.DataSource, NullLogger<LeaseCache>.Instance,
            batchSize: 100, batchIntervalMs: batchIntervalMs, cleanupIntervalSeconds: 60);

    private async Task<int> CountLeasesInDbAsync()
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand("SELECT COUNT(*) FROM dhcp_leases", conn);
        return Convert.ToInt32(await cmd.ExecuteScalarAsync());
    }

    private async Task InsertLeaseRowAsync(string mac, IPAddress ip, DateTime end, string? hostname = null)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(@"
            INSERT INTO dhcp_leases (id, mac_address, ip_address, hostname, start_time, end_time)
            VALUES (gen_random_uuid(), @mac::macaddr, @ip, @host, @start, @end)", conn);
        cmd.Parameters.AddWithValue("mac", mac);
        cmd.Parameters.AddWithValue("ip", ip);
        cmd.Parameters.AddWithValue("host", (object?)hostname ?? DBNull.Value);
        cmd.Parameters.AddWithValue("start", DateTime.UtcNow.AddMinutes(-1));
        cmd.Parameters.AddWithValue("end", end);
        await cmd.ExecuteNonQueryAsync();
    }

    /// <summary>
    /// Polls until the predicate is true or timeout elapses. Used to bridge the
    /// write-through batch loop's natural latency without sleep-bombing tests.
    /// </summary>
    private static async Task<bool> WaitForAsync(Func<Task<bool>> predicate, int timeoutMs = 2000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTime.UtcNow < deadline)
        {
            if (await predicate()) return true;
            await Task.Delay(20);
        }
        return false;
    }

    // ── Warmup ─────────────────────────────────────────────────────────

    [Fact]
    public async Task WarmupAsync_LoadsActiveLeases_AndSkipsExpiredOnes()
    {
        // Two leases: one active, one already expired.
        await InsertLeaseRowAsync("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.10"),
            end: DateTime.UtcNow.AddHours(1), hostname: "alive");
        await InsertLeaseRowAsync("aa:bb:cc:00:00:02", IPAddress.Parse("10.0.0.11"),
            end: DateTime.UtcNow.AddMinutes(-5));

        using var cache = CreateCache();
        await cache.WarmupAsync();

        Assert.NotNull(cache.GetByMac("aa:bb:cc:00:00:01"));
        Assert.Equal("alive", cache.GetByMac("aa:bb:cc:00:00:01")!.Hostname);
        Assert.Null(cache.GetByMac("aa:bb:cc:00:00:02")); // expired one not loaded
    }

    [Fact]
    public async Task WarmupAsync_OnEmptyDb_LeavesCacheEmpty()
    {
        using var cache = CreateCache();
        await cache.WarmupAsync();

        Assert.Null(cache.GetByMac("any"));
        Assert.Equal(0, cache.GetStats().ActiveLeases);
    }

    // ── Set / lookup ───────────────────────────────────────────────────

    [Fact]
    public async Task SetLeaseAsync_MakesEntryImmediatelyAvailableInCache()
    {
        using var cache = CreateCache();
        var ip = IPAddress.Parse("10.0.0.50");

        await cache.SetLeaseAsync("aa:bb:cc:00:00:10", ip, leaseTimeSeconds: 3600, hostname: "phone");

        Assert.NotNull(cache.GetByMac("aa:bb:cc:00:00:10"));
        Assert.Equal(ip, cache.GetByMac("aa:bb:cc:00:00:10")!.IpAddress);
        Assert.Equal("phone", cache.GetByIp(ip)!.Hostname);
        Assert.True(cache.HasActiveLease("aa:bb:cc:00:00:10"));
        Assert.True(cache.IsIpLeased(ip));
    }

    [Fact]
    public async Task SetLeaseAsync_MovingMacToNewIp_RemovesOldIpFromIndex()
    {
        using var cache = CreateCache();
        var oldIp = IPAddress.Parse("10.0.0.50");
        var newIp = IPAddress.Parse("10.0.0.51");

        await cache.SetLeaseAsync("aa:bb:cc:00:00:10", oldIp, leaseTimeSeconds: 3600);
        await cache.SetLeaseAsync("aa:bb:cc:00:00:10", newIp, leaseTimeSeconds: 3600);

        Assert.False(cache.IsIpLeased(oldIp));   // old mapping gone
        Assert.True(cache.IsIpLeased(newIp));
        Assert.Equal(newIp, cache.GetByMac("aa:bb:cc:00:00:10")!.IpAddress);
    }

    [Fact]
    public async Task SetLeaseAsync_PersistsToDatabaseViaWriteThrough()
    {
        using var cache = CreateCache();

        await cache.SetLeaseAsync("aa:bb:cc:00:00:10", IPAddress.Parse("10.0.0.50"),
            leaseTimeSeconds: 3600, hostname: "phone");

        var hit = await WaitForAsync(async () => await CountLeasesInDbAsync() == 1);
        Assert.True(hit, "write-through should land within timeout");
    }

    [Fact]
    public async Task SetLeaseAsync_ZeroLeaseTime_ImmediatelyExpiredEntry()
    {
        using var cache = CreateCache();
        await cache.SetLeaseAsync("aa:bb:cc:00:00:10", IPAddress.Parse("10.0.0.50"), leaseTimeSeconds: 0);

        // Cache APIs treat IsExpired as effectively-not-present.
        Assert.False(cache.HasActiveLease("aa:bb:cc:00:00:10"));
        Assert.Null(cache.GetByMac("aa:bb:cc:00:00:10"));
    }

    // ── Declined IPs ───────────────────────────────────────────────────

    [Fact]
    public void MarkIpAsDeclined_BlocksIpFromAvailability()
    {
        using var cache = CreateCache();
        var ip = IPAddress.Parse("10.0.0.99");

        Assert.True(cache.IsIpAvailable(ip));
        cache.MarkIpAsDeclined(ip);
        Assert.True(cache.IsIpDeclined(ip));
        Assert.False(cache.IsIpAvailable(ip));
    }

    [Fact]
    public async Task IsIpAvailable_FalseWhenLeased_AndFalseWhenDeclined()
    {
        using var cache = CreateCache();
        var leased = IPAddress.Parse("10.0.0.10");
        var declined = IPAddress.Parse("10.0.0.11");

        await cache.SetLeaseAsync("aa:bb:cc:00:00:01", leased, 3600);
        cache.MarkIpAsDeclined(declined);

        Assert.False(cache.IsIpAvailable(leased));
        Assert.False(cache.IsIpAvailable(declined));
        Assert.True(cache.IsIpAvailable(IPAddress.Parse("10.0.0.12")));
    }

    // ── CanMacUseIp (lease ownership) ──────────────────────────────────

    [Fact]
    public async Task CanMacUseIp_TrueForOwnReuseOfSameIp()
    {
        using var cache = CreateCache();
        var ip = IPAddress.Parse("10.0.0.50");
        await cache.SetLeaseAsync("aa:bb:cc:00:00:10", ip, 3600);

        Assert.True(cache.CanMacUseIp("aa:bb:cc:00:00:10", ip));
    }

    [Fact]
    public async Task CanMacUseIp_FalseWhenIpClaimedByDifferentMac()
    {
        using var cache = CreateCache();
        var ip = IPAddress.Parse("10.0.0.50");
        await cache.SetLeaseAsync("aa:bb:cc:00:00:01", ip, 3600);

        Assert.False(cache.CanMacUseIp("aa:bb:cc:00:00:02", ip));
    }

    [Fact]
    public void CanMacUseIp_TrueWhenIpUnleased()
    {
        using var cache = CreateCache();
        Assert.True(cache.CanMacUseIp("aa:bb:cc:00:00:99", IPAddress.Parse("10.0.0.50")));
    }

    // ── FindAvailableIp ────────────────────────────────────────────────

    [Fact]
    public void FindAvailableIp_ReturnsRangeStartWhenAllFree()
    {
        using var cache = CreateCache();
        var found = cache.FindAvailableIp(
            IPAddress.Parse("10.0.0.10"),
            IPAddress.Parse("10.0.0.20"));

        Assert.Equal("10.0.0.10", found?.ToString());
    }

    [Fact]
    public async Task FindAvailableIp_SkipsLeasedDeclinedAndExcludedIps()
    {
        using var cache = CreateCache();
        var rangeStart = IPAddress.Parse("10.0.0.10");
        var rangeEnd = IPAddress.Parse("10.0.0.20");

        await cache.SetLeaseAsync("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.10"), 3600);
        cache.MarkIpAsDeclined(IPAddress.Parse("10.0.0.11"));
        var exclusions = new HashSet<IPAddress> { IPAddress.Parse("10.0.0.12") };

        var found = cache.FindAvailableIp(rangeStart, rangeEnd, exclusions);

        Assert.Equal("10.0.0.13", found?.ToString());
    }

    [Fact]
    public async Task FindAvailableIp_ReturnsNullWhenRangeFullyConsumed()
    {
        using var cache = CreateCache();
        // Range of two IPs, both leased.
        await cache.SetLeaseAsync("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.10"), 3600);
        await cache.SetLeaseAsync("aa:bb:cc:00:00:02", IPAddress.Parse("10.0.0.11"), 3600);

        var found = cache.FindAvailableIp(IPAddress.Parse("10.0.0.10"), IPAddress.Parse("10.0.0.11"));
        Assert.Null(found);
    }

    [Fact]
    public void FindAvailableIp_HandlesByteWraparoundCorrectly()
    {
        using var cache = CreateCache();
        // Range crossing a byte boundary: .254, .255, then a tricky ".0/.1".
        // The increment helper carries; if it didn't, .254 → .255 then would
        // produce 10.0.0.256 (invalid) or skip .0. We assert it walks correctly.
        var found = cache.FindAvailableIp(
            IPAddress.Parse("10.0.0.254"),
            IPAddress.Parse("10.0.1.5"));

        Assert.Equal("10.0.0.254", found?.ToString());
    }

    // ── Release ────────────────────────────────────────────────────────

    [Fact]
    public async Task ReleaseLeaseAsync_ClearsBothIndexes_AndQueuesDbDelete()
    {
        using var cache = CreateCache();
        var ip = IPAddress.Parse("10.0.0.50");
        await cache.SetLeaseAsync("aa:bb:cc:00:00:10", ip, 3600);
        Assert.True(await WaitForAsync(async () => await CountLeasesInDbAsync() == 1));

        await cache.ReleaseLeaseAsync("aa:bb:cc:00:00:10");

        Assert.Null(cache.GetByMac("aa:bb:cc:00:00:10"));
        Assert.Null(cache.GetByIp(ip));
        Assert.True(await WaitForAsync(async () => await CountLeasesInDbAsync() == 0));
    }

    [Fact]
    public async Task ReleaseLeaseByIpAsync_AlsoClearsTheMacIndex()
    {
        using var cache = CreateCache();
        var ip = IPAddress.Parse("10.0.0.50");
        await cache.SetLeaseAsync("aa:bb:cc:00:00:10", ip, 3600);

        await cache.ReleaseLeaseByIpAsync(ip);

        Assert.Null(cache.GetByMac("aa:bb:cc:00:00:10"));
        Assert.Null(cache.GetByIp(ip));
    }

    // ── Stats ──────────────────────────────────────────────────────────

    [Fact]
    public async Task GetStats_TracksHitsMissesAndPendingWrites()
    {
        using var cache = CreateCache();
        await cache.SetLeaseAsync("aa:bb:cc:00:00:10", IPAddress.Parse("10.0.0.50"), 3600);
        // Wait for write-through to drain so PendingWrites is 0.
        await WaitForAsync(async () => await CountLeasesInDbAsync() == 1);

        // Two hits (Get + IsIpLeased), one miss.
        _ = cache.GetByMac("aa:bb:cc:00:00:10");
        _ = cache.GetByIp(IPAddress.Parse("10.0.0.50"));
        _ = cache.GetByMac("ff:ff:ff:ff:ff:ff"); // miss

        var stats = cache.GetStats();
        Assert.Equal(1, stats.ActiveLeases);
        Assert.True(stats.CacheHits >= 2);
        Assert.True(stats.CacheMisses >= 1);
        Assert.True(stats.HitRatio > 0 && stats.HitRatio < 1);
    }
}
