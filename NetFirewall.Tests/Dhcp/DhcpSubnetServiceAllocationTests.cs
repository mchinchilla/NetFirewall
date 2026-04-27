using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// Real-Postgres coverage for the IP-allocation hot path:
/// <see cref="DhcpSubnetService.FindAvailableIpInSubnetAsync"/>. Hooks the real
/// <see cref="LeaseCache"/> in so we exercise the cache-vs-DB precedence rules
/// (declined IPs, in-cache leases) the same way the worker does in production.
/// </summary>
[Collection("Postgres")]
public sealed class DhcpSubnetServiceAllocationTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private DhcpSubnetService _svc = null!;
    private LeaseCache _leaseCache = null!;

    public DhcpSubnetServiceAllocationTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _leaseCache = new LeaseCache(
            _pg.DataSource, NullLogger<LeaseCache>.Instance,
            batchSize: 100, batchIntervalMs: 20, cleanupIntervalSeconds: 60);
        _svc = new DhcpSubnetService(_pg.DataSource, NullLogger<DhcpSubnetService>.Instance, _leaseCache);
    }

    public Task DisposeAsync()
    {
        _leaseCache.Dispose();
        return Task.CompletedTask;
    }

    private static DhcpRequest MakeRequest(string mac = "aa:bb:cc:00:00:01") => new()
    {
        ClientMac = mac,
        CiAddr = IPAddress.Any,
        GiAddr = IPAddress.Any,
        YiAddr = IPAddress.Any,
        SiAddr = IPAddress.Any,
        RequestedIp = IPAddress.Any
    };

    private async Task<DhcpSubnet> CreateSubnetAsync(string name, string cidr) =>
        await _svc.CreateSubnetAsync(new DhcpSubnet
        {
            Name = name,
            Network = cidr,
            SubnetMask = IPAddress.Parse("255.255.255.0"),
            Router = IPAddress.Parse(cidr.Split('/')[0].Replace(".0", ".1")),
            Enabled = true
        });

    private async Task<DhcpPool> CreatePoolAsync(Guid subnetId, string start, string end,
        int priority = 100, bool enabled = true, bool denyBootp = false, bool allowUnknown = true) =>
        await _svc.CreatePoolAsync(new DhcpPool
        {
            SubnetId = subnetId,
            Name = $"pool-{start}",
            RangeStart = IPAddress.Parse(start),
            RangeEnd = IPAddress.Parse(end),
            Priority = priority,
            Enabled = enabled,
            DenyBootp = denyBootp,
            AllowUnknownClients = allowUnknown
        });

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

    private async Task SeedExclusionAsync(Guid subnetId, string start, string? end = null)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(@"
            INSERT INTO dhcp_exclusions (id, subnet_id, ip_start, ip_end, created_at)
            VALUES (gen_random_uuid(), @sid, @s, @e, now())", conn);
        cmd.Parameters.AddWithValue("sid", subnetId);
        cmd.Parameters.AddWithValue("s", IPAddress.Parse(start));
        cmd.Parameters.AddWithValue("e", end is null ? (object)DBNull.Value : IPAddress.Parse(end));
        await cmd.ExecuteNonQueryAsync();
    }

    // ── reservation short-circuits everything ──────────────────────────

    [Fact]
    public async Task FindAvailableIp_MacWithReservation_ReturnsReservedIp_AndNoPool()
    {
        var subnet = await CreateSubnetAsync("home", "192.168.1.0/24");
        await CreatePoolAsync(subnet.Id, "192.168.1.100", "192.168.1.200");
        await SeedReservationAsync("aa:bb:cc:00:00:01", "192.168.1.42");

        var (ip, pool) = await _svc.FindAvailableIpInSubnetAsync(subnet, "aa:bb:cc:00:00:01", MakeRequest());

        Assert.Equal("192.168.1.42", ip?.ToString());
        Assert.Null(pool); // explicit: reservations don't carry a pool ref
    }

    // ── happy path ─────────────────────────────────────────────────────

    [Fact]
    public async Task FindAvailableIp_FirstFreeIpInSinglePool_IsReturned()
    {
        var subnet = await CreateSubnetAsync("home", "192.168.1.0/24");
        var pool = await CreatePoolAsync(subnet.Id, "192.168.1.100", "192.168.1.105");
        _svc.InvalidateCache();

        var (ip, pickedPool) = await _svc.FindAvailableIpInSubnetAsync(subnet, "aa:bb:cc:00:00:01", MakeRequest());

        Assert.Equal("192.168.1.100", ip?.ToString());
        Assert.NotNull(pickedPool);
        Assert.Equal(pool.Id, pickedPool!.Id);
    }

    // ── empty / disabled pools ─────────────────────────────────────────

    [Fact]
    public async Task FindAvailableIp_SubnetWithoutPools_ReturnsNull()
    {
        var subnet = await CreateSubnetAsync("home", "192.168.1.0/24");
        _svc.InvalidateCache();

        var (ip, pool) = await _svc.FindAvailableIpInSubnetAsync(subnet, "aa:bb:cc:00:00:01", MakeRequest());

        Assert.Null(ip);
        Assert.Null(pool);
    }

    [Fact]
    public async Task FindAvailableIp_OnlyDisabledPool_ReturnsNull()
    {
        var subnet = await CreateSubnetAsync("home", "192.168.1.0/24");
        await CreatePoolAsync(subnet.Id, "192.168.1.100", "192.168.1.200", enabled: false);
        _svc.InvalidateCache();

        var (ip, pool) = await _svc.FindAvailableIpInSubnetAsync(subnet, "aa:bb:cc:00:00:01", MakeRequest());

        Assert.Null(ip);
        Assert.Null(pool);
    }

    // ── exclusions ─────────────────────────────────────────────────────

    [Fact]
    public async Task FindAvailableIp_FirstIpExcluded_AdvancesPastExclusion()
    {
        var subnet = await CreateSubnetAsync("home", "192.168.1.0/24");
        await CreatePoolAsync(subnet.Id, "192.168.1.100", "192.168.1.110");
        // Exclude 100-103 inclusive.
        await SeedExclusionAsync(subnet.Id, "192.168.1.100", "192.168.1.103");
        _svc.InvalidateCache();

        var (ip, _) = await _svc.FindAvailableIpInSubnetAsync(subnet, "aa:bb:cc:00:00:01", MakeRequest());

        // First IP outside the exclusion is .104.
        Assert.Equal("192.168.1.104", ip?.ToString());
    }

    // ── existing leases in cache ───────────────────────────────────────

    [Fact]
    public async Task FindAvailableIp_SkipsIpsAlreadyLeasedInCache()
    {
        var subnet = await CreateSubnetAsync("home", "192.168.1.0/24");
        await CreatePoolAsync(subnet.Id, "192.168.1.100", "192.168.1.105");
        // Pre-populate cache (which write-throughs to DB) with leases on .100-.102.
        await _leaseCache.SetLeaseAsync("aa:bb:cc:00:00:99", IPAddress.Parse("192.168.1.100"), 3600);
        await _leaseCache.SetLeaseAsync("aa:bb:cc:00:00:98", IPAddress.Parse("192.168.1.101"), 3600);
        await _leaseCache.SetLeaseAsync("aa:bb:cc:00:00:97", IPAddress.Parse("192.168.1.102"), 3600);
        // Wait for write-through so the SQL "used_ips" CTE sees them.
        await Task.Delay(100);
        _svc.InvalidateCache();

        var (ip, _) = await _svc.FindAvailableIpInSubnetAsync(subnet, "aa:bb:cc:00:00:01", MakeRequest());

        Assert.Equal("192.168.1.103", ip?.ToString());
    }

    [Fact]
    public async Task FindAvailableIp_SkipsDeclinedIps()
    {
        var subnet = await CreateSubnetAsync("home", "192.168.1.0/24");
        await CreatePoolAsync(subnet.Id, "192.168.1.100", "192.168.1.105");
        _svc.InvalidateCache();

        // Cache says .100 is declined (ARP conflict).
        _leaseCache.MarkIpAsDeclined(IPAddress.Parse("192.168.1.100"));

        var (ip, _) = await _svc.FindAvailableIpInSubnetAsync(subnet, "aa:bb:cc:00:00:01", MakeRequest());

        // The SQL returns .100 first; the in-memory check rejects it. The fallback
        // iterator then walks from .100 onwards, also skipping the declined one.
        Assert.NotEqual("192.168.1.100", ip?.ToString());
        Assert.NotNull(ip);
    }

    // ── multi-pool priority ────────────────────────────────────────────

    [Fact]
    public async Task FindAvailableIp_LowerPriorityNumberPoolUsedFirst()
    {
        var subnet = await CreateSubnetAsync("home", "192.168.1.0/24");
        // High-numbered priority pool: priority=200, range .200-.210.
        await CreatePoolAsync(subnet.Id, "192.168.1.200", "192.168.1.210", priority: 200);
        // Low-numbered priority pool: priority=10, range .50-.60 — should win.
        await CreatePoolAsync(subnet.Id, "192.168.1.50", "192.168.1.60", priority: 10);
        _svc.InvalidateCache();

        var (ip, _) = await _svc.FindAvailableIpInSubnetAsync(subnet, "aa:bb:cc:00:00:01", MakeRequest());

        Assert.Equal("192.168.1.50", ip?.ToString());
    }

    [Fact]
    public async Task FindAvailableIp_FirstPoolFull_FallsThroughToSecondPool()
    {
        var subnet = await CreateSubnetAsync("home", "192.168.1.0/24");
        // Tiny first pool that we will fully consume.
        await CreatePoolAsync(subnet.Id, "192.168.1.100", "192.168.1.101", priority: 10);
        await CreatePoolAsync(subnet.Id, "192.168.1.200", "192.168.1.210", priority: 20);

        await _leaseCache.SetLeaseAsync("aa:bb:cc:00:00:91", IPAddress.Parse("192.168.1.100"), 3600);
        await _leaseCache.SetLeaseAsync("aa:bb:cc:00:00:92", IPAddress.Parse("192.168.1.101"), 3600);
        await Task.Delay(100); // write-through
        _svc.InvalidateCache();

        var (ip, _) = await _svc.FindAvailableIpInSubnetAsync(subnet, "aa:bb:cc:00:00:01", MakeRequest());

        Assert.Equal("192.168.1.200", ip?.ToString());
    }

    // ── client eligibility ─────────────────────────────────────────────

    [Fact]
    public async Task FindAvailableIp_PoolDeniesBootpClient_FallsThroughToOtherPool()
    {
        var subnet = await CreateSubnetAsync("home", "192.168.1.0/24");
        await CreatePoolAsync(subnet.Id, "192.168.1.50", "192.168.1.60", priority: 10, denyBootp: true);
        await CreatePoolAsync(subnet.Id, "192.168.1.100", "192.168.1.110", priority: 20);
        _svc.InvalidateCache();

        var bootpRequest = MakeRequest();
        bootpRequest.IsBootp = true;

        var (ip, _) = await _svc.FindAvailableIpInSubnetAsync(subnet, "aa:bb:cc:00:00:01", bootpRequest);

        // First pool refuses BOOTP → falls through to second pool.
        Assert.Equal("192.168.1.100", ip?.ToString());
    }

    [Fact]
    public async Task FindAvailableIp_AllPoolsDenyClient_ReturnsNull()
    {
        var subnet = await CreateSubnetAsync("home", "192.168.1.0/24");
        await CreatePoolAsync(subnet.Id, "192.168.1.50", "192.168.1.60", denyBootp: true);
        _svc.InvalidateCache();

        var bootpRequest = MakeRequest();
        bootpRequest.IsBootp = true;

        var (ip, _) = await _svc.FindAvailableIpInSubnetAsync(subnet, "aa:bb:cc:00:00:01", bootpRequest);

        Assert.Null(ip);
    }

    // ── exhausted pool ─────────────────────────────────────────────────

    [Fact]
    public async Task FindAvailableIp_PoolFullyLeased_ReturnsNull()
    {
        var subnet = await CreateSubnetAsync("home", "192.168.1.0/24");
        // 3-IP pool, all leased.
        await CreatePoolAsync(subnet.Id, "192.168.1.100", "192.168.1.102");
        await _leaseCache.SetLeaseAsync("aa:bb:cc:00:00:91", IPAddress.Parse("192.168.1.100"), 3600);
        await _leaseCache.SetLeaseAsync("aa:bb:cc:00:00:92", IPAddress.Parse("192.168.1.101"), 3600);
        await _leaseCache.SetLeaseAsync("aa:bb:cc:00:00:93", IPAddress.Parse("192.168.1.102"), 3600);
        await Task.Delay(100);
        _svc.InvalidateCache();

        var (ip, _) = await _svc.FindAvailableIpInSubnetAsync(subnet, "aa:bb:cc:00:00:01", MakeRequest());

        Assert.Null(ip);
    }
}
