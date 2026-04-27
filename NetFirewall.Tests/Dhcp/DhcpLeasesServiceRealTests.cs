using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// Real-Postgres coverage of <see cref="DhcpLeasesService"/>. The pre-existing
/// <c>DhcpLeasesServiceTests</c> file only mocks the interface — this suite
/// drives the actual SQL paths against a fresh DB.
/// Both fast (cache + write-through) and slow (direct DB) paths are exercised.
/// </summary>
[Collection("Postgres")]
public sealed class DhcpLeasesServiceRealTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private LeaseCache _cache = null!;
    private DhcpLeasesService _slow = null!;        // no cache → direct DB
    private DhcpLeasesService _fast = null!;        // with cache → write-through

    public DhcpLeasesServiceRealTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _cache = new LeaseCache(_pg.DataSource, NullLogger<LeaseCache>.Instance,
            batchSize: 100, batchIntervalMs: 20, cleanupIntervalSeconds: 60);
        _slow = new DhcpLeasesService(_pg.DataSource, NullLogger<DhcpLeasesService>.Instance, leaseCache: null);
        _fast = new DhcpLeasesService(_pg.DataSource, NullLogger<DhcpLeasesService>.Instance, leaseCache: _cache);
    }

    public Task DisposeAsync()
    {
        _cache.Dispose();
        return Task.CompletedTask;
    }

    private async Task<int> CountLeasesAsync(string? mac = null)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        var sql = mac is null
            ? "SELECT COUNT(*) FROM dhcp_leases"
            : "SELECT COUNT(*) FROM dhcp_leases WHERE mac_address = @mac::macaddr";
        await using var cmd = new NpgsqlCommand(sql, conn);
        if (mac is not null) cmd.Parameters.AddWithValue("mac", mac);
        return Convert.ToInt32(await cmd.ExecuteScalarAsync());
    }

    private async Task SeedReservationAsync(string mac, string ip)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(@"
            INSERT INTO dhcp_mac_reservations (id, mac_address, reserved_ip)
            VALUES (gen_random_uuid(), @mac::macaddr, @ip)", conn);
        cmd.Parameters.AddWithValue("mac", mac);
        cmd.Parameters.AddWithValue("ip", IPAddress.Parse(ip));
        await cmd.ExecuteNonQueryAsync();
    }

    private static async Task<bool> WaitForAsync(Func<Task<bool>> p, int timeoutMs = 1500)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTime.UtcNow < deadline)
        {
            if (await p()) return true;
            await Task.Delay(20);
        }
        return false;
    }

    // ── AssignLeaseAsync (slow path: direct DB) ────────────────────────

    [Fact]
    public async Task AssignLeaseAsync_SlowPath_PersistsRow()
    {
        await _slow.AssignLeaseAsync("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.50"),
            leaseTime: 3600, hostname: "phone");

        Assert.Equal(1, await CountLeasesAsync("aa:bb:cc:00:00:01"));
    }

    [Fact]
    public async Task AssignLeaseAsync_SlowPath_DuplicateMac_UpsertsViaOnConflict()
    {
        await _slow.AssignLeaseAsync("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.50"), 3600);
        await _slow.AssignLeaseAsync("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.51"), 3600);

        // Still one row for that MAC, with the second IP.
        Assert.Equal(1, await CountLeasesAsync("aa:bb:cc:00:00:01"));

        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT ip_address FROM dhcp_leases WHERE mac_address = 'aa:bb:cc:00:00:01'::macaddr", conn);
        var ip = (IPAddress)(await cmd.ExecuteScalarAsync())!;
        Assert.Equal("10.0.0.51", ip.ToString());
    }

    // ── AssignLeaseAsync (fast path: cache + write-through) ────────────

    [Fact]
    public async Task AssignLeaseAsync_FastPath_AvailableInCacheImmediately_AndPersistsAsync()
    {
        await _fast.AssignLeaseAsync("aa:bb:cc:00:00:02", IPAddress.Parse("10.0.0.60"),
            leaseTime: 3600, hostname: "tablet");

        // Cache is hot the moment the call returns.
        Assert.NotNull(_cache.GetByMac("aa:bb:cc:00:00:02"));

        // DB catches up via the write-through batch loop.
        Assert.True(await WaitForAsync(async () => await CountLeasesAsync() == 1));
    }

    // ── CanAssignIpAsync ────────────────────────────────────────────────

    [Fact]
    public async Task CanAssignIpAsync_FreeIp_ReturnsTrue()
    {
        Assert.True(await _slow.CanAssignIpAsync("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.10")));
    }

    [Fact]
    public async Task CanAssignIpAsync_IpHeldByOtherMac_ReturnsFalse_FastPath()
    {
        // Use the fast path (cache-backed CanMacUseIp).
        await _fast.AssignLeaseAsync("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.10"), 3600);

        Assert.False(await _fast.CanAssignIpAsync("aa:bb:cc:00:00:02", IPAddress.Parse("10.0.0.10")));
    }

    [Fact]
    public async Task CanAssignIpAsync_IpHeldByOtherMac_ReturnsFalse_SlowPath()
    {
        // SLOW path: direct DB query.
        await _slow.AssignLeaseAsync("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.10"), 3600);

        Assert.False(await _slow.CanAssignIpAsync("aa:bb:cc:00:00:02", IPAddress.Parse("10.0.0.10")));
    }

    [Fact]
    public async Task CanAssignIpAsync_SameMacReusingSameIp_ReturnsTrue_SlowPath()
    {
        await _slow.AssignLeaseAsync("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.10"), 3600);

        Assert.True(await _slow.CanAssignIpAsync("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.10")));
    }

    [Fact]
    public async Task CanAssignIpAsync_MacHasReservation_OnlyAcceptsReservedIp()
    {
        await SeedReservationAsync("aa:bb:cc:00:00:01", "10.0.0.42");

        Assert.True(await _slow.CanAssignIpAsync("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.42")));
        Assert.False(await _slow.CanAssignIpAsync("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.99")));
    }

    [Fact]
    public async Task CanAssignIpAsync_IpReservedForDifferentMac_RejectsRequester()
    {
        await SeedReservationAsync("aa:bb:cc:00:00:01", "10.0.0.42");

        // A different MAC asks for the same IP — reservations override availability.
        Assert.False(await _slow.CanAssignIpAsync("aa:bb:cc:00:00:99", IPAddress.Parse("10.0.0.42")));
    }

    // ── ReleaseLeaseAsync ──────────────────────────────────────────────

    [Fact]
    public async Task ReleaseLeaseAsync_SlowPath_DeletesRow()
    {
        await _slow.AssignLeaseAsync("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.10"), 3600);
        Assert.Equal(1, await CountLeasesAsync());

        await _slow.ReleaseLeaseAsync("aa:bb:cc:00:00:01");

        Assert.Equal(0, await CountLeasesAsync());
    }

    [Fact]
    public async Task ReleaseLeaseAsync_FastPath_RemovesFromCache_AndQueuesDelete()
    {
        await _fast.AssignLeaseAsync("aa:bb:cc:00:00:02", IPAddress.Parse("10.0.0.20"), 3600);
        Assert.True(await WaitForAsync(async () => await CountLeasesAsync() == 1));

        await _fast.ReleaseLeaseAsync("aa:bb:cc:00:00:02");

        Assert.Null(_cache.GetByMac("aa:bb:cc:00:00:02"));
        Assert.True(await WaitForAsync(async () => await CountLeasesAsync() == 0));
    }

    // ── MarkIpAsDeclinedAsync ──────────────────────────────────────────

    [Fact]
    public async Task MarkIpAsDeclinedAsync_FastPath_PopulatesCacheDeclinedSet()
    {
        var ip = IPAddress.Parse("10.0.0.99");
        await _fast.MarkIpAsDeclinedAsync(ip);

        Assert.True(_fast.IsIpDeclined(ip));
    }

    // ── GetAssignedIpAsync ─────────────────────────────────────────────

    [Fact]
    public async Task GetAssignedIpAsync_FastPath_HitsCacheBeforeDb()
    {
        var ip = IPAddress.Parse("10.0.0.30");
        await _fast.AssignLeaseAsync("aa:bb:cc:00:00:03", ip, 3600);

        var fetched = await _fast.GetAssignedIpAsync("aa:bb:cc:00:00:03");

        Assert.Equal(ip, fetched);
    }

    [Fact]
    public async Task GetAssignedIpAsync_UnknownMac_ReturnsNull()
    {
        Assert.Null(await _slow.GetAssignedIpAsync("ff:ff:ff:ff:ff:ff"));
    }

    // ── CleanupExpiredLeasesAsync ──────────────────────────────────────

    [Fact]
    public async Task CleanupExpiredLeasesAsync_DeletesOnlyExpiredRows()
    {
        // Insert one expired and one active lease directly.
        await using (var conn = await _pg.DataSource.OpenConnectionAsync())
        {
            await using var cmd1 = new NpgsqlCommand(@"
                INSERT INTO dhcp_leases (id, mac_address, ip_address, start_time, end_time)
                VALUES (gen_random_uuid(), '11:11:11:11:11:11'::macaddr, '10.0.0.1', now() - interval '1 day', now() - interval '1 hour');
                INSERT INTO dhcp_leases (id, mac_address, ip_address, start_time, end_time)
                VALUES (gen_random_uuid(), '22:22:22:22:22:22'::macaddr, '10.0.0.2', now(), now() + interval '1 hour');", conn);
            await cmd1.ExecuteNonQueryAsync();
        }
        Assert.Equal(2, await CountLeasesAsync());

        var deleted = await _slow.CleanupExpiredLeasesAsync();

        Assert.Equal(1, deleted);
        Assert.Equal(1, await CountLeasesAsync());
        Assert.Equal(1, await CountLeasesAsync("22:22:22:22:22:22")); // active survived
    }

    // ── GetAllActiveLeasesAsync ────────────────────────────────────────

    [Fact]
    public async Task GetAllActiveLeasesAsync_ReturnsOnlyActive_NotExpired()
    {
        await using (var conn = await _pg.DataSource.OpenConnectionAsync())
        {
            await using var cmd = new NpgsqlCommand(@"
                INSERT INTO dhcp_leases (id, mac_address, ip_address, start_time, end_time) VALUES
                  (gen_random_uuid(), '11:11:11:11:11:11'::macaddr, '10.0.0.1', now() - interval '1 day', now() - interval '1 hour'),
                  (gen_random_uuid(), '22:22:22:22:22:22'::macaddr, '10.0.0.2', now(),                     now() + interval '1 hour');", conn);
            await cmd.ExecuteNonQueryAsync();
        }

        var active = await _slow.GetAllActiveLeasesAsync();

        Assert.Single(active);
        Assert.Equal("10.0.0.2", active[0].IpAddress.ToString());
    }

    // ── GetAllReservationsAsync ────────────────────────────────────────

    [Fact]
    public async Task GetAllReservationsAsync_ReturnsSeededReservations()
    {
        await SeedReservationAsync("aa:bb:cc:00:00:01", "10.0.0.42");
        await SeedReservationAsync("aa:bb:cc:00:00:02", "10.0.0.43");

        var rows = await _slow.GetAllReservationsAsync();

        Assert.Equal(2, rows.Count);
        Assert.Contains(rows, r => r.ReservedIp.ToString() == "10.0.0.42");
        Assert.Contains(rows, r => r.ReservedIp.ToString() == "10.0.0.43");
    }
}
