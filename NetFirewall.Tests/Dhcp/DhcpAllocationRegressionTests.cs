using System.Net;
using System.Net.NetworkInformation;
using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetFirewall.Tests.Infra;
using Npgsql;
using RepoDb;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// Real-Postgres regression coverage for the allocation bugs found in the
/// hardening review:
/// 1. The DB path's optimized allocation SQL used `inet @param` typename-
///    literal syntax — a hard syntax error on every execution, whose aborted
///    transaction also killed the fallback (25P02): a cache-miss DISCOVER
///    could NEVER allocate a fresh IP from the DB.
/// 2. The cache fast path ignored MAC reservations entirely: reserved devices
///    were offered arbitrary IPs (NAK loop), and an offline device's reserved
///    IP at the head of the range was offered to every new client.
/// 3. CanAssignIpAsync approved a reserved MAC's claim even while a squatter
///    held an active lease on the reserved address (live ARP conflict).
/// 4. DhcpMacReservation mapped ReservedIp to a nonexistent column, breaking
///    the COPY-based bulk import on first use.
/// </summary>
[Collection("Postgres")]
public sealed class DhcpAllocationRegressionTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private LeaseCache _cache = null!;
    private DhcpLeasesService _slow = null!;   // no cache → DB allocation path
    private DhcpLeasesService _fast = null!;   // cache-backed fast path

    static DhcpAllocationRegressionTests()
    {
        // RepoDb needs its provider registered before BinaryBulkInsertAsync —
        // production does this in each host's Program.cs. Idempotent.
        GlobalConfiguration.Setup().UsePostgreSql();
    }

    public DhcpAllocationRegressionTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _cache = new LeaseCache(_pg.DataSource, NullLogger<LeaseCache>.Instance,
            batchSize: 100, batchIntervalMs: 20, cleanupIntervalSeconds: 3600);
        _slow = new DhcpLeasesService(_pg.DataSource, NullLogger<DhcpLeasesService>.Instance, leaseCache: null);
        _fast = new DhcpLeasesService(_pg.DataSource, NullLogger<DhcpLeasesService>.Instance, leaseCache: _cache);
    }

    public Task DisposeAsync()
    {
        _cache.Dispose();
        return Task.CompletedTask;
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

    // ── Bug 1: DB path allocation ──────────────────────────────────────

    [Fact]
    public async Task OfferLease_DbPath_EmptyTables_AllocatesRangeStart()
    {
        // Before the SQL fix this returned null — always.
        var offered = await _slow.OfferLeaseAsync("aa:bb:cc:00:10:01",
            IPAddress.Parse("10.60.0.10"), IPAddress.Parse("10.60.0.20"));

        Assert.Equal(IPAddress.Parse("10.60.0.10"), offered);
    }

    [Fact]
    public async Task OfferLease_DbPath_SkipsLeasedAndReservedAddresses()
    {
        await _slow.AssignLeaseAsync("11:11:11:00:00:01", IPAddress.Parse("10.60.1.10"), 3600);
        await SeedReservationAsync("22:22:22:00:00:02", "10.60.1.11");

        var offered = await _slow.OfferLeaseAsync("aa:bb:cc:00:10:02",
            IPAddress.Parse("10.60.1.10"), IPAddress.Parse("10.60.1.20"));

        Assert.Equal(IPAddress.Parse("10.60.1.12"), offered);
    }

    [Fact]
    public async Task OfferLease_DbPath_RangeExhausted_ReturnsNull()
    {
        await _slow.AssignLeaseAsync("11:11:11:00:00:01", IPAddress.Parse("10.60.2.10"), 3600);
        await _slow.AssignLeaseAsync("11:11:11:00:00:02", IPAddress.Parse("10.60.2.11"), 3600);

        var offered = await _slow.OfferLeaseAsync("aa:bb:cc:00:10:03",
            IPAddress.Parse("10.60.2.10"), IPAddress.Parse("10.60.2.11"));

        Assert.Null(offered);
    }

    // ── Bug 2: reservations on the cache fast path ─────────────────────

    [Fact]
    public async Task OfferLease_FastPath_ReservedMac_GetsItsReservation()
    {
        await SeedReservationAsync("aa:bb:cc:00:20:01", "10.61.0.50");

        var offered = await _fast.OfferLeaseAsync("aa:bb:cc:00:20:01",
            IPAddress.Parse("10.61.0.10"), IPAddress.Parse("10.61.0.20"));

        Assert.Equal(IPAddress.Parse("10.61.0.50"), offered);
    }

    [Fact]
    public async Task OfferLease_FastPath_OtherMacsReservationAtRangeHead_Skipped()
    {
        // The offline device's reservation is the lowest free address — every
        // new client used to be offered it, then denied at REQUEST time.
        await SeedReservationAsync("aa:bb:cc:00:21:01", "10.61.1.10");

        var offered = await _fast.OfferLeaseAsync("dd:ee:ff:00:21:02",
            IPAddress.Parse("10.61.1.10"), IPAddress.Parse("10.61.1.20"));

        Assert.Equal(IPAddress.Parse("10.61.1.11"), offered);
    }

    // ── Bug 3: reserved IP squatted by another client ──────────────────

    [Fact]
    public async Task CanAssign_ReservedMacRequestingOwnIp_DeniedWhileSquatterHoldsIt()
    {
        await SeedReservationAsync("aa:bb:cc:00:30:01", "10.62.0.30");
        // Squatter got there first and holds an ACTIVE lease.
        await _slow.AssignLeaseAsync("99:99:99:00:30:99", IPAddress.Parse("10.62.0.30"), 3600);

        var canAssign = await _slow.CanAssignIpAsync("aa:bb:cc:00:30:01", IPAddress.Parse("10.62.0.30"));

        Assert.False(canAssign);
    }

    [Fact]
    public async Task CanAssign_ReservedMacRequestingOwnIp_AllowedWhenFree()
    {
        await SeedReservationAsync("aa:bb:cc:00:31:01", "10.62.1.30");

        Assert.True(await _slow.CanAssignIpAsync("aa:bb:cc:00:31:01", IPAddress.Parse("10.62.1.30")));
    }

    [Fact]
    public async Task CanAssign_ReservedMacRequestingDifferentIp_StillDenied()
    {
        await SeedReservationAsync("aa:bb:cc:00:32:01", "10.62.2.30");

        Assert.False(await _slow.CanAssignIpAsync("aa:bb:cc:00:32:01", IPAddress.Parse("10.62.2.99")));
    }

    // ── Bug 4: bulk import column mapping ──────────────────────────────

    [Fact]
    public async Task BulkImportReservations_RoundTrips()
    {
        // Exercises the [Map("reserved_ip")] fix — the old ip_address mapping
        // made the COPY target a nonexistent column (42703).
        var imported = await _slow.BulkImportReservationsAsync(new[]
        {
            new DhcpMacReservation
            {
                MacAddress = PhysicalAddress.Parse("AA-BB-CC-00-40-01"),
                ReservedIp = IPAddress.Parse("10.63.0.10"),
                Description = "bulk-1"
            },
            new DhcpMacReservation
            {
                MacAddress = PhysicalAddress.Parse("AA-BB-CC-00-40-02"),
                ReservedIp = IPAddress.Parse("10.63.0.11"),
                Description = "bulk-2"
            }
        });

        Assert.Equal(2, imported);

        var all = await _slow.GetAllReservationsAsync();
        Assert.Contains(all, r => r.ReservedIp.Equals(IPAddress.Parse("10.63.0.10")));
        Assert.Contains(all, r => r.ReservedIp.Equals(IPAddress.Parse("10.63.0.11")));
    }
}
