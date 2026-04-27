using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// Real-Postgres coverage for <see cref="DhcpSubnetService"/> — CRUD, subnet
/// selection priority chain (SourceInterface → GiAddr → CiAddr → RequestedIp →
/// default), pool CRUD, and the cache invalidation contract.
///
/// IP-allocation hot path (<c>FindAvailableIpInSubnetAsync</c>) needs a real
/// <c>LeaseCache</c> warmed against actual leases — tracked separately.
/// </summary>
[Collection("Postgres")]
public sealed class DhcpSubnetServiceTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private DhcpSubnetService _svc = null!;

    public DhcpSubnetServiceTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        // leaseCache=null is OK — the methods we test never touch it.
        _svc = new DhcpSubnetService(_pg.DataSource, NullLogger<DhcpSubnetService>.Instance, leaseCache: null);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private static DhcpSubnet MakeSubnet(string name, string cidr, string router) => new()
    {
        Name = name,
        Network = cidr,
        SubnetMask = IPAddress.Parse("255.255.255.0"),
        Router = IPAddress.Parse(router),
        DnsServers = new[] { IPAddress.Parse("8.8.8.8") },
        DefaultLeaseTime = 3600,
        MaxLeaseTime = 7200,
        Enabled = true
    };

    private static DhcpRequest MakeRequest(
        string mac = "00:11:22:33:44:55",
        IPAddress? ci = null, IPAddress? gi = null, IPAddress? requested = null,
        string? iface = null) => new()
    {
        ClientMac = mac,
        CiAddr = ci ?? IPAddress.Any,
        GiAddr = gi ?? IPAddress.Any,
        YiAddr = IPAddress.Any,
        SiAddr = IPAddress.Any,
        RequestedIp = requested ?? IPAddress.Any,
        SourceInterfaceName = iface
    };

    // ── Subnet CRUD ────────────────────────────────────────────────────

    [Fact]
    public async Task CreateSubnetAsync_PersistsAndReturnsRow()
    {
        var s = await _svc.CreateSubnetAsync(MakeSubnet("home", "192.168.1.0/24", "192.168.1.1"));

        Assert.NotEqual(Guid.Empty, s.Id);

        var fetched = await _svc.GetSubnetWithPoolsAsync(s.Id);
        Assert.NotNull(fetched);
        Assert.Equal("home", fetched!.Name);
        Assert.Equal("192.168.1.0/24", fetched.Network);
        Assert.Equal("192.168.1.1", fetched.Router?.ToString());
        Assert.True(fetched.Enabled);
    }

    [Fact]
    public async Task UpdateSubnetAsync_ModifiesPersistedRow()
    {
        var s = await _svc.CreateSubnetAsync(MakeSubnet("home", "192.168.1.0/24", "192.168.1.1"));
        s.Name = "renamed";
        s.DefaultLeaseTime = 9000;

        await _svc.UpdateSubnetAsync(s);
        // After mutating, force a cache refresh so the next read sees the update.
        _svc.InvalidateCache();

        var fetched = await _svc.GetSubnetWithPoolsAsync(s.Id);
        Assert.Equal("renamed", fetched!.Name);
        Assert.Equal(9000, fetched.DefaultLeaseTime);
    }

    [Fact]
    public async Task DeleteSubnetAsync_RemovesRow_AndReturnsTrue()
    {
        var s = await _svc.CreateSubnetAsync(MakeSubnet("doomed", "10.10.0.0/24", "10.10.0.1"));

        var ok = await _svc.DeleteSubnetAsync(s.Id);
        _svc.InvalidateCache();

        Assert.True(ok);
        Assert.Null(await _svc.GetSubnetWithPoolsAsync(s.Id));
    }

    [Fact]
    public async Task DeleteSubnetAsync_UnknownId_ReturnsFalse()
    {
        Assert.False(await _svc.DeleteSubnetAsync(Guid.NewGuid()));
    }

    // ── Pool CRUD ──────────────────────────────────────────────────────

    [Fact]
    public async Task CreatePoolAsync_PersistsUnderSubnet_AndGetPoolsReturnsIt()
    {
        var subnet = await _svc.CreateSubnetAsync(MakeSubnet("home", "192.168.1.0/24", "192.168.1.1"));

        var pool = await _svc.CreatePoolAsync(new DhcpPool
        {
            SubnetId = subnet.Id,
            Name = "main",
            RangeStart = IPAddress.Parse("192.168.1.100"),
            RangeEnd = IPAddress.Parse("192.168.1.200"),
            Priority = 10,
            Enabled = true
        });
        _svc.InvalidateCache();

        Assert.NotEqual(Guid.Empty, pool.Id);
        var pools = await _svc.GetPoolsForSubnetAsync(subnet.Id);
        var fetched = Assert.Single(pools);
        Assert.Equal("main", fetched.Name);
        Assert.Equal("192.168.1.100", fetched.RangeStart.ToString());
        Assert.Equal("192.168.1.200", fetched.RangeEnd.ToString());
    }

    [Fact]
    public async Task DeletePoolAsync_RemovesPool_AndReturnsTrue()
    {
        var subnet = await _svc.CreateSubnetAsync(MakeSubnet("home", "192.168.1.0/24", "192.168.1.1"));
        var pool = await _svc.CreatePoolAsync(new DhcpPool
        {
            SubnetId = subnet.Id,
            RangeStart = IPAddress.Parse("192.168.1.100"),
            RangeEnd = IPAddress.Parse("192.168.1.200")
        });

        var ok = await _svc.DeletePoolAsync(pool.Id);
        _svc.InvalidateCache();

        Assert.True(ok);
        Assert.Empty(await _svc.GetPoolsForSubnetAsync(subnet.Id));
    }

    // ── Lookups & CIDR matching ────────────────────────────────────────

    [Fact]
    public async Task FindSubnetByNetworkAsync_MatchesByCidrContainment()
    {
        await _svc.CreateSubnetAsync(MakeSubnet("home", "192.168.1.0/24", "192.168.1.1"));
        await _svc.CreateSubnetAsync(MakeSubnet("guest", "10.20.0.0/24", "10.20.0.1"));

        Assert.NotNull(await _svc.FindSubnetByNetworkAsync(IPAddress.Parse("192.168.1.50")));
        Assert.NotNull(await _svc.FindSubnetByNetworkAsync(IPAddress.Parse("10.20.0.99")));
        // IP outside any subnet
        Assert.Null(await _svc.FindSubnetByNetworkAsync(IPAddress.Parse("172.16.0.1")));
    }

    [Fact]
    public async Task FindSubnetByNetworkAsync_DisabledSubnetIsSkipped()
    {
        var s = MakeSubnet("home", "192.168.1.0/24", "192.168.1.1");
        s.Enabled = false;
        await _svc.CreateSubnetAsync(s);

        Assert.Null(await _svc.FindSubnetByNetworkAsync(IPAddress.Parse("192.168.1.50")));
    }

    // ── Selection priority chain ───────────────────────────────────────

    [Fact]
    public async Task FindSubnetForRequestAsync_PrefersSourceInterface_OverGiAddr()
    {
        // Tie SourceInterface to a fw_interface, then to a subnet.
        await using (var conn = await _pg.DataSource.OpenConnectionAsync())
        await using (var cmd = new NpgsqlCommand(@"
            INSERT INTO fw_interfaces (id, name, type, addressing_mode, auto_start, enabled, created_at, updated_at)
            VALUES (@id, 'eth1', 'LAN', 'static', true, true, now(), now())", conn))
        {
            cmd.Parameters.AddWithValue("id", Guid.NewGuid());
            await cmd.ExecuteNonQueryAsync();
        }
        // Look up the interface so we can FK it.
        Guid ifaceId;
        await using (var conn = await _pg.DataSource.OpenConnectionAsync())
        await using (var cmd = new NpgsqlCommand("SELECT id FROM fw_interfaces WHERE name = 'eth1'", conn))
            ifaceId = (Guid)(await cmd.ExecuteScalarAsync())!;

        var sourced = MakeSubnet("sourced", "10.0.0.0/24", "10.0.0.1");
        sourced.InterfaceId = ifaceId;
        var giaddrTarget = MakeSubnet("via-gi", "10.99.0.0/24", "10.99.0.1");
        await _svc.CreateSubnetAsync(sourced);
        await _svc.CreateSubnetAsync(giaddrTarget);
        _svc.InvalidateCache();

        var request = MakeRequest(iface: "eth1", gi: IPAddress.Parse("10.99.0.50"));
        var picked = await _svc.FindSubnetForRequestAsync(request);

        Assert.NotNull(picked);
        Assert.Equal("sourced", picked!.Name); // SourceInterface beats GiAddr
    }

    [Fact]
    public async Task FindSubnetForRequestAsync_GiAddrUsedWhenInterfaceMisses()
    {
        await _svc.CreateSubnetAsync(MakeSubnet("via-gi", "10.99.0.0/24", "10.99.0.1"));

        var request = MakeRequest(iface: "no-such-iface", gi: IPAddress.Parse("10.99.0.50"));
        var picked = await _svc.FindSubnetForRequestAsync(request);

        Assert.Equal("via-gi", picked!.Name);
    }

    [Fact]
    public async Task FindSubnetForRequestAsync_CiAddrUsedWhenNoGiAddr()
    {
        await _svc.CreateSubnetAsync(MakeSubnet("home", "192.168.1.0/24", "192.168.1.1"));

        var request = MakeRequest(ci: IPAddress.Parse("192.168.1.42"));
        var picked = await _svc.FindSubnetForRequestAsync(request);

        Assert.Equal("home", picked!.Name);
    }

    [Fact]
    public async Task FindSubnetForRequestAsync_RequestedIpUsedWhenNoCiAddrOrGiAddr()
    {
        await _svc.CreateSubnetAsync(MakeSubnet("home", "192.168.1.0/24", "192.168.1.1"));

        var request = MakeRequest(requested: IPAddress.Parse("192.168.1.42"));
        var picked = await _svc.FindSubnetForRequestAsync(request);

        Assert.Equal("home", picked!.Name);
    }

    [Fact]
    public async Task FindSubnetForRequestAsync_FallsBackToFirstEnabledByName()
    {
        // Two subnets with no IP/interface clue → ORDER BY name picks "alpha".
        await _svc.CreateSubnetAsync(MakeSubnet("zulu", "10.99.0.0/24", "10.99.0.1"));
        await _svc.CreateSubnetAsync(MakeSubnet("alpha", "10.10.0.0/24", "10.10.0.1"));

        var request = MakeRequest(); // no clues
        var picked = await _svc.FindSubnetForRequestAsync(request);

        Assert.Equal("alpha", picked!.Name);
    }

    [Fact]
    public async Task FindSubnetForRequestAsync_NoSubnets_ReturnsNull()
    {
        Assert.Null(await _svc.FindSubnetForRequestAsync(MakeRequest()));
    }

    // ── Exclusions ─────────────────────────────────────────────────────

    [Fact]
    public async Task GetExclusionsForSubnetAsync_ReturnsRowsForSubnet()
    {
        var subnet = await _svc.CreateSubnetAsync(MakeSubnet("home", "192.168.1.0/24", "192.168.1.1"));

        // Insert two exclusions directly.
        await using (var conn = await _pg.DataSource.OpenConnectionAsync())
        await using (var cmd = new NpgsqlCommand(@"
            INSERT INTO dhcp_exclusions (id, subnet_id, ip_start, ip_end, reason, created_at)
            VALUES (gen_random_uuid(), @sid, @start, @end, @reason, now())", conn))
        {
            cmd.Parameters.AddWithValue("sid", subnet.Id);
            cmd.Parameters.AddWithValue("start", IPAddress.Parse("192.168.1.50"));
            cmd.Parameters.AddWithValue("end", IPAddress.Parse("192.168.1.55"));
            cmd.Parameters.AddWithValue("reason", "reserved-for-printers");
            await cmd.ExecuteNonQueryAsync();
        }
        _svc.InvalidateCache();

        var exclusions = await _svc.GetExclusionsForSubnetAsync(subnet.Id);
        var ex = Assert.Single(exclusions);
        Assert.Equal("192.168.1.50", ex.IpStart.ToString());
        Assert.Equal("192.168.1.55", ex.IpEnd?.ToString());
        Assert.Equal("reserved-for-printers", ex.Reason);
    }

    // ── Cache invalidation ─────────────────────────────────────────────

    [Fact]
    public async Task InvalidateCache_ForcesRefetchOnNextRead()
    {
        var s = await _svc.CreateSubnetAsync(MakeSubnet("home", "192.168.1.0/24", "192.168.1.1"));
        // Warm the cache with one query.
        _ = await _svc.GetAllSubnetsAsync();

        // Mutate directly via SQL so the service's cache doesn't auto-update.
        await using (var conn = await _pg.DataSource.OpenConnectionAsync())
        await using (var cmd = new NpgsqlCommand("UPDATE dhcp_subnets SET name = 'renamed' WHERE id = @id", conn))
        {
            cmd.Parameters.AddWithValue("id", s.Id);
            await cmd.ExecuteNonQueryAsync();
        }

        // Without invalidation, cache could still show "home".
        _svc.InvalidateCache();

        var fetched = await _svc.GetSubnetWithPoolsAsync(s.Id);
        Assert.Equal("renamed", fetched!.Name);
    }

    [Fact]
    public async Task GetAllSubnetsAsync_ReturnsOnlyEnabled()
    {
        await _svc.CreateSubnetAsync(MakeSubnet("on", "192.168.1.0/24", "192.168.1.1"));
        var disabled = MakeSubnet("off", "10.20.0.0/24", "10.20.0.1");
        disabled.Enabled = false;
        await _svc.CreateSubnetAsync(disabled);

        var all = await _svc.GetAllSubnetsAsync();

        // Cache only loads enabled rows; "off" should not appear.
        Assert.Single(all);
        Assert.Equal("on", all[0].Name);
    }
}
