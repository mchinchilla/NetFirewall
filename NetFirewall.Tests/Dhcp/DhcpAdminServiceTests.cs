using System.Net;
using System.Net.NetworkInformation;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// Real-Postgres coverage for the slices of <see cref="DhcpAdminService"/> not
/// already exercised by <c>DhcpSubnetServiceTests</c>: reservation validation
/// (duplicate-IP / duplicate-MAC), client class CRUD with jsonb, exclusion
/// CRUD, and stats aggregation.
/// </summary>
[Collection("Postgres")]
public sealed class DhcpAdminServiceTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private readonly Mock<IDhcpCacheNotifier> _notifier = new();
    private DhcpAdminService _svc = null!;

    public DhcpAdminServiceTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _notifier.Setup(n => n.NotifySubnetChangedAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        _svc = new DhcpAdminService(_pg.DataSource, NullLogger<DhcpAdminService>.Instance, _notifier.Object);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private static PhysicalAddress Mac(string s) =>
        PhysicalAddress.Parse(s.Replace(":", "-").ToUpperInvariant());

    private async Task<Guid> SeedSubnetAsync(string name, string cidr)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(@"
            INSERT INTO dhcp_subnets (id, name, network, subnet_mask, enabled, created_at, updated_at)
            VALUES (gen_random_uuid(), @n, @cidr::cidr, '255.255.255.0'::inet, true, now(), now())
            RETURNING id", conn);
        cmd.Parameters.AddWithValue("n", name);
        cmd.Parameters.AddWithValue("cidr", cidr);
        return (Guid)(await cmd.ExecuteScalarAsync())!;
    }

    // ── Reservations ───────────────────────────────────────────────────

    [Fact]
    public async Task CreateReservationAsync_PersistsRow_AndNotifies()
    {
        var r = await _svc.CreateReservationAsync(new DhcpMacReservation
        {
            MacAddress = Mac("aa:bb:cc:00:00:01"),
            ReservedIp = IPAddress.Parse("10.0.0.42"),
            Description = "phone"
        });

        Assert.NotEqual(Guid.Empty, r.Id);

        var fetched = await _svc.GetReservationsAsync();
        Assert.Single(fetched);
        Assert.Equal("10.0.0.42", fetched[0].ReservedIp.ToString());
        _notifier.Verify(n => n.NotifySubnetChangedAsync(
            It.Is<string>(s => s.StartsWith("reservation.create:")), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task CreateReservationAsync_DuplicateIp_ThrowsInvalidOperationException()
    {
        await _svc.CreateReservationAsync(new DhcpMacReservation
        {
            MacAddress = Mac("aa:bb:cc:00:00:01"),
            ReservedIp = IPAddress.Parse("10.0.0.42")
        });

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _svc.CreateReservationAsync(new DhcpMacReservation
            {
                MacAddress = Mac("aa:bb:cc:00:00:99"), // different MAC
                ReservedIp = IPAddress.Parse("10.0.0.42") // same IP
            }));

        Assert.Contains("already reserved", ex.Message);
    }

    [Fact]
    public async Task CreateReservationAsync_DuplicateMac_ThrowsInvalidOperationException()
    {
        await _svc.CreateReservationAsync(new DhcpMacReservation
        {
            MacAddress = Mac("aa:bb:cc:00:00:01"),
            ReservedIp = IPAddress.Parse("10.0.0.42")
        });

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _svc.CreateReservationAsync(new DhcpMacReservation
            {
                MacAddress = Mac("aa:bb:cc:00:00:01"),    // same MAC
                ReservedIp = IPAddress.Parse("10.0.0.99") // different IP
            }));

        Assert.Contains("already has a reservation", ex.Message);
    }

    [Fact]
    public async Task DeleteReservationAsync_RemovesRow_AndNotifies()
    {
        var r = await _svc.CreateReservationAsync(new DhcpMacReservation
        {
            MacAddress = Mac("aa:bb:cc:00:00:01"),
            ReservedIp = IPAddress.Parse("10.0.0.42")
        });

        var ok = await _svc.DeleteReservationAsync(r.Id);

        Assert.True(ok);
        Assert.Empty(await _svc.GetReservationsAsync());
        _notifier.Verify(n => n.NotifySubnetChangedAsync(
            It.Is<string>(s => s.StartsWith("reservation.delete:")), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ── Client classes ─────────────────────────────────────────────────

    [Fact]
    public async Task CreateClassAsync_PersistsWithJsonbOptions()
    {
        var c = await _svc.CreateClassAsync(new DhcpClass
        {
            Name = "PXE",
            MatchType = "vendor_class",
            MatchValue = "PXEClient",
            Options = """{"66": "tftp.local", "67": "pxelinux.0"}""",
            Priority = 50,
            Enabled = true
        });

        Assert.NotEqual(Guid.Empty, c.Id);

        var fetched = await _svc.GetClassByIdAsync(c.Id);
        Assert.NotNull(fetched);
        Assert.Equal("PXE", fetched!.Name);
        Assert.Contains("tftp.local", fetched.Options);
    }

    [Fact]
    public async Task GetClassesAsync_OrdersByPriority_ThenName()
    {
        await _svc.CreateClassAsync(new DhcpClass { Name = "ZZZ", MatchType = "mac_prefix", MatchValue = "00", Priority = 100 });
        await _svc.CreateClassAsync(new DhcpClass { Name = "AAA", MatchType = "mac_prefix", MatchValue = "01", Priority = 100 });
        await _svc.CreateClassAsync(new DhcpClass { Name = "MMM", MatchType = "mac_prefix", MatchValue = "02", Priority = 50 });

        var all = await _svc.GetClassesAsync();

        Assert.Equal(new[] { "MMM", "AAA", "ZZZ" }, all.Select(c => c.Name));
    }

    [Fact]
    public async Task DeleteClassAsync_RemovesRow_AndNotifies()
    {
        var c = await _svc.CreateClassAsync(new DhcpClass
        {
            Name = "tmp", MatchType = "mac_prefix", MatchValue = "ff:ff"
        });

        Assert.True(await _svc.DeleteClassAsync(c.Id));
        Assert.Null(await _svc.GetClassByIdAsync(c.Id));
        _notifier.Verify(n => n.NotifySubnetChangedAsync(
            It.Is<string>(s => s.StartsWith("class.delete:")), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ── Exclusions ─────────────────────────────────────────────────────

    [Fact]
    public async Task CreateExclusionAsync_PersistsWithRange()
    {
        var subnetId = await SeedSubnetAsync("home", "192.168.1.0/24");

        var ex = await _svc.CreateExclusionAsync(new DhcpExclusion
        {
            SubnetId = subnetId,
            IpStart = IPAddress.Parse("192.168.1.50"),
            IpEnd = IPAddress.Parse("192.168.1.55"),
            Reason = "printers"
        });

        var fetched = await _svc.GetExclusionsAsync(subnetId);
        var single = Assert.Single(fetched);
        Assert.Equal("192.168.1.50", single.IpStart.ToString());
        Assert.Equal("192.168.1.55", single.IpEnd?.ToString());
        Assert.Equal("printers", single.Reason);
    }

    [Fact]
    public async Task GetExclusionsAsync_FilterBySubnet_ReturnsOnlyMatching()
    {
        var s1 = await SeedSubnetAsync("a", "10.0.1.0/24");
        var s2 = await SeedSubnetAsync("b", "10.0.2.0/24");

        await _svc.CreateExclusionAsync(new DhcpExclusion { SubnetId = s1, IpStart = IPAddress.Parse("10.0.1.5") });
        await _svc.CreateExclusionAsync(new DhcpExclusion { SubnetId = s2, IpStart = IPAddress.Parse("10.0.2.5") });

        var s1Only = await _svc.GetExclusionsAsync(s1);
        Assert.Single(s1Only);
        Assert.Equal(s1, s1Only[0].SubnetId);
    }

    [Fact]
    public async Task DeleteExclusionAsync_RemovesRow()
    {
        var subnetId = await SeedSubnetAsync("home", "192.168.1.0/24");
        var ex = await _svc.CreateExclusionAsync(new DhcpExclusion
        {
            SubnetId = subnetId, IpStart = IPAddress.Parse("192.168.1.99")
        });

        Assert.True(await _svc.DeleteExclusionAsync(ex.Id));
        Assert.Empty(await _svc.GetExclusionsAsync(subnetId));
    }

    // ── Stats ──────────────────────────────────────────────────────────

    [Fact]
    public async Task GetStatsAsync_AggregatesAcrossSubnetsAndLeases()
    {
        var s1 = await SeedSubnetAsync("a", "10.0.1.0/24");
        // Insert a small pool (5 IPs) and a couple of leases.
        await using (var conn = await _pg.DataSource.OpenConnectionAsync())
        await using (var cmd = new NpgsqlCommand(@"
            INSERT INTO dhcp_pools (id, subnet_id, range_start, range_end, enabled)
            VALUES (gen_random_uuid(), @sid, '10.0.1.10', '10.0.1.14', true);
            INSERT INTO dhcp_leases (id, mac_address, ip_address, start_time, end_time)
              VALUES (gen_random_uuid(), '11:11:11:11:11:11'::macaddr, '10.0.1.10', now(), now() + interval '1 hour');
            INSERT INTO dhcp_leases (id, mac_address, ip_address, start_time, end_time)
              VALUES (gen_random_uuid(), '22:22:22:22:22:22'::macaddr, '10.0.1.11', now() - interval '1 day', now() - interval '1 hour');
            INSERT INTO dhcp_mac_reservations (id, mac_address, reserved_ip)
              VALUES (gen_random_uuid(), '33:33:33:33:33:33'::macaddr, '10.0.1.99');", conn))
        {
            cmd.Parameters.AddWithValue("sid", s1);
            await cmd.ExecuteNonQueryAsync();
        }

        var stats = await _svc.GetStatsAsync();

        Assert.Equal(1, stats.TotalSubnets);
        Assert.Equal(1, stats.ActiveSubnets);
        Assert.Equal(2, stats.TotalLeases);
        Assert.Equal(1, stats.ActiveLeases);
        Assert.Equal(1, stats.TotalReservations);
        Assert.True(stats.TotalPoolSize >= 5);
    }
}
