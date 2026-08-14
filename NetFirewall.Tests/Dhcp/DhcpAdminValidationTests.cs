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
/// Real-Postgres coverage of the admin-service validation added in the
/// hardening pass: pool range sanity (inverted / overlapping), reservation
/// subnet containment, lost-update detection on Update*, friendly errors for
/// invalid CIDR input, and the Web-release → NOTIFY handshake.
/// </summary>
[Collection("Postgres")]
public sealed class DhcpAdminValidationTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private readonly Mock<IDhcpCacheNotifier> _notifier = new();
    private DhcpAdminService _svc = null!;

    public DhcpAdminValidationTests(PostgresFixture pg) => _pg = pg;

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

    // ── Pool range validation ──────────────────────────────────────────

    [Fact]
    public async Task CreatePool_InvertedRange_ThrowsFriendlyError()
    {
        var subnetId = await SeedSubnetAsync("s1", "10.0.1.0/24");

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _svc.CreatePoolAsync(new DhcpPool
            {
                SubnetId = subnetId,
                Name = "inverted",
                RangeStart = IPAddress.Parse("10.0.1.200"),
                RangeEnd = IPAddress.Parse("10.0.1.100"),
                Enabled = true
            }));

        Assert.Contains("inverted", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CreatePool_OverlappingSibling_Throws()
    {
        var subnetId = await SeedSubnetAsync("s2", "10.0.2.0/24");
        await _svc.CreatePoolAsync(new DhcpPool
        {
            SubnetId = subnetId, Name = "first",
            RangeStart = IPAddress.Parse("10.0.2.10"), RangeEnd = IPAddress.Parse("10.0.2.100"),
            Enabled = true
        });

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _svc.CreatePoolAsync(new DhcpPool
            {
                SubnetId = subnetId, Name = "second",
                RangeStart = IPAddress.Parse("10.0.2.50"), RangeEnd = IPAddress.Parse("10.0.2.150"),
                Enabled = true
            }));

        Assert.Contains("overlaps", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CreatePool_AdjacentNonOverlapping_Succeeds()
    {
        var subnetId = await SeedSubnetAsync("s3", "10.0.3.0/24");
        await _svc.CreatePoolAsync(new DhcpPool
        {
            SubnetId = subnetId, Name = "low",
            RangeStart = IPAddress.Parse("10.0.3.10"), RangeEnd = IPAddress.Parse("10.0.3.100"),
            Enabled = true
        });

        var pool = await _svc.CreatePoolAsync(new DhcpPool
        {
            SubnetId = subnetId, Name = "high",
            RangeStart = IPAddress.Parse("10.0.3.101"), RangeEnd = IPAddress.Parse("10.0.3.200"),
            Enabled = true
        });

        Assert.NotEqual(Guid.Empty, pool.Id);
    }

    [Fact]
    public async Task UpdatePool_KeepingOwnRange_DoesNotSelfOverlap()
    {
        var subnetId = await SeedSubnetAsync("s4", "10.0.4.0/24");
        var pool = await _svc.CreatePoolAsync(new DhcpPool
        {
            SubnetId = subnetId, Name = "solo",
            RangeStart = IPAddress.Parse("10.0.4.10"), RangeEnd = IPAddress.Parse("10.0.4.100"),
            Enabled = true
        });

        pool.Name = "solo-renamed";
        var updated = await _svc.UpdatePoolAsync(pool);

        Assert.Equal("solo-renamed", updated.Name);
    }

    // ── Lost-update detection ──────────────────────────────────────────

    [Fact]
    public async Task UpdatePool_DeletedUnderneath_Throws()
    {
        var subnetId = await SeedSubnetAsync("s5", "10.0.5.0/24");
        var pool = await _svc.CreatePoolAsync(new DhcpPool
        {
            SubnetId = subnetId, Name = "doomed",
            RangeStart = IPAddress.Parse("10.0.5.10"), RangeEnd = IPAddress.Parse("10.0.5.20"),
            Enabled = true
        });
        await _svc.DeletePoolAsync(pool.Id);

        await Assert.ThrowsAsync<InvalidOperationException>(() => _svc.UpdatePoolAsync(pool));
    }

    [Fact]
    public async Task UpdateReservation_DeletedUnderneath_Throws()
    {
        await SeedSubnetAsync("s6", "10.0.6.0/24");
        var r = await _svc.CreateReservationAsync(new DhcpMacReservation
        {
            MacAddress = Mac("aa:bb:cc:00:06:01"),
            ReservedIp = IPAddress.Parse("10.0.6.5")
        });
        await _svc.DeleteReservationAsync(r.Id);

        await Assert.ThrowsAsync<InvalidOperationException>(() => _svc.UpdateReservationAsync(r));
    }

    // ── Reservation subnet containment ─────────────────────────────────

    [Fact]
    public async Task CreateReservation_OutsideEverySubnet_Throws()
    {
        await SeedSubnetAsync("s7", "10.0.7.0/24");

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _svc.CreateReservationAsync(new DhcpMacReservation
            {
                MacAddress = Mac("aa:bb:cc:00:07:01"),
                ReservedIp = IPAddress.Parse("203.0.113.5")
            }));

        Assert.Contains("subnet", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CreateReservation_NoSubnetsConfigured_Allowed()
    {
        // Fresh install: reservations may be seeded before subnets exist.
        var r = await _svc.CreateReservationAsync(new DhcpMacReservation
        {
            MacAddress = Mac("aa:bb:cc:00:08:01"),
            ReservedIp = IPAddress.Parse("192.168.99.4")
        });

        Assert.NotEqual(Guid.Empty, r.Id);
    }

    [Fact]
    public async Task CreateReservation_InsideASubnet_Succeeds()
    {
        await SeedSubnetAsync("s9", "10.0.9.0/24");

        var r = await _svc.CreateReservationAsync(new DhcpMacReservation
        {
            MacAddress = Mac("aa:bb:cc:00:09:01"),
            ReservedIp = IPAddress.Parse("10.0.9.44")
        });

        Assert.NotEqual(Guid.Empty, r.Id);
    }

    // ── Subnet input validation ────────────────────────────────────────

    [Fact]
    public async Task CreateSubnet_InvalidCidr_ThrowsFriendlyError()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _svc.CreateSubnetAsync(new DhcpSubnet
            {
                Name = "bad",
                Network = "not-a-network",
                SubnetMask = IPAddress.Parse("255.255.255.0")
            }));

        Assert.Contains("CIDR", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CreateSubnet_MissingMask_ThrowsFriendlyError()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _svc.CreateSubnetAsync(new DhcpSubnet
            {
                Name = "no-mask",
                Network = "10.0.10.0/24",
                SubnetMask = null
            }));

        Assert.Contains("mask", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ── Web release → NOTIFY handshake ─────────────────────────────────

    [Fact]
    public async Task ReleaseLease_SendsLeaseReleaseNotify_WithIp()
    {
        // Seed a lease row directly.
        Guid leaseId;
        await using (var conn = await _pg.DataSource.OpenConnectionAsync())
        {
            await using var cmd = new NpgsqlCommand(@"
                INSERT INTO dhcp_leases (id, mac_address, ip_address, start_time, end_time)
                VALUES (gen_random_uuid(), 'aa:bb:cc:00:0a:01'::macaddr, '10.0.11.7', now(), now() + interval '1 hour')
                RETURNING id", conn);
            leaseId = (Guid)(await cmd.ExecuteScalarAsync())!;
        }

        Assert.True(await _svc.ReleaseLeaseAsync(leaseId));

        _notifier.Verify(n => n.NotifySubnetChangedAsync(
            "lease.release:10.0.11.7", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ReleaseLease_UnknownId_ReturnsFalse_NoNotify()
    {
        Assert.False(await _svc.ReleaseLeaseAsync(Guid.NewGuid()));

        _notifier.Verify(n => n.NotifySubnetChangedAsync(
            It.Is<string>(s => s.StartsWith("lease.release:")), It.IsAny<CancellationToken>()), Times.Never);
    }
}
