using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using NetFirewall.DhcpServer;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// The four critical findings of the 2026-11 DHCP review, each pinned:
/// 1. a REQUEST for an address outside the subnet / pools / exclusions is NAKed (RFC 2131 §4.3.2);
/// 2. an internal error ends in silence, never a NAK (a NAK drops a renewing client's address);
/// 3. option 121 always carries a default route (RFC 3442 clients ignore option 3);
/// 4. one interface that can't be opened no longer takes DHCP down on every interface.
/// </summary>
public sealed class DhcpCriticalFixesTests
{
    private const string Mac = "aa:bb:cc:00:00:01";
    private readonly Mock<IDhcpLeasesService> _leases = new(MockBehavior.Strict);
    private readonly Mock<IDhcpSubnetService> _subnets = new(MockBehavior.Strict);

    private static readonly DhcpSubnet Lan = new()
    {
        Id = Guid.NewGuid(), Name = "LAN", Network = "192.168.50.0/24",
        SubnetMask = IPAddress.Parse("255.255.255.0"), Router = IPAddress.Parse("192.168.50.1"),
        DefaultLeaseTime = 3600,
    };

    private DhcpServerService Svc() => new(_leases.Object, _subnets.Object, NullLogger<DhcpServerService>.Instance,
        Options.Create(new DhcpConfig
        {
            ServerIp = IPAddress.Parse("10.0.0.1"), IpRangeStart = IPAddress.Parse("10.0.0.100"),
            IpRangeEnd = IPAddress.Parse("10.0.0.200"), SubnetMask = IPAddress.Parse("255.255.255.0"),
            Gateway = IPAddress.Parse("10.0.0.1"), DnsServers = [IPAddress.Parse("8.8.8.8")], LeaseTime = 3600,
        }));

    private static DhcpRequest Request(string requestedIp) => new()
    {
        ClientMac = Mac,
        ChAddr = [0xAA, 0xBB, 0xCC, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        Xid = [1, 2, 3, 4],
        CiAddr = IPAddress.Any, YiAddr = IPAddress.Any, SiAddr = IPAddress.Any, GiAddr = IPAddress.Any,
        MessageType = DhcpMessageType.Request,
        RequestedIp = IPAddress.Parse(requestedIp),   // INIT-REBOOT: option 50, no server id
    };

    private void Subnet(DhcpSubnet? s)
    {
        _subnets.Setup(x => x.FindSubnetForRequestAsync(It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>())).ReturnsAsync(s);
        _subnets.Setup(x => x.MatchClientClassAsync(It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>())).ReturnsAsync((DhcpClass?)null);
    }

    private static byte? MessageType(DhcpResponseBuffer r)
    {
        if (r.IsEmpty) return null;
        var s = r.Span;
        for (var i = 240; i < s.Length - 2;)
        {
            if (s[i] == 255) break;
            if (s[i] == 0) { i++; continue; }
            if (s[i] == 53) return s[i + 2];
            i += 2 + s[i + 1];
        }
        return null;
    }

    // ── 1. REQUEST outside what we hand out → NAK, nothing assigned ──

    [Theory]
    [InlineData(RequestedIpVerdict.WrongNetwork)]
    [InlineData(RequestedIpVerdict.NotAssignable)]
    public async Task Request_ForAnAddressWeWouldNotHandOut_IsNakd_AndNothingIsAssigned(RequestedIpVerdict verdict)
    {
        Subnet(Lan);
        _subnets.Setup(x => x.CheckRequestedIpAsync(Lan, Mac, IPAddress.Parse("10.1.2.3"), It.IsAny<CancellationToken>()))
            .ReturnsAsync(verdict);

        using var r = await Svc().CreateDhcpResponseAsync(Request("10.1.2.3"));

        Assert.Equal((byte)DhcpMessageType.Nak, MessageType(r));
        // Strict mocks: CanAssign/Assign were never reached (they'd have thrown → silence, not NAK).
    }

    [Fact]
    public async Task Request_InsideThePool_IsStillAcked()
    {
        Subnet(Lan);
        var ip = IPAddress.Parse("192.168.50.120");
        _subnets.Setup(x => x.CheckRequestedIpAsync(Lan, Mac, ip, It.IsAny<CancellationToken>())).ReturnsAsync(RequestedIpVerdict.Allowed);
        _leases.Setup(x => x.CanAssignIpAsync(Mac, ip)).ReturnsAsync(true);
        _leases.Setup(x => x.AssignLeaseAsync(Mac, ip, 3600, null)).Returns(Task.CompletedTask);

        using var r = await Svc().CreateDhcpResponseAsync(Request("192.168.50.120"));

        Assert.Equal((byte)DhcpMessageType.Ack, MessageType(r));
    }

    [Fact]
    public async Task Request_InFallbackMode_OutsideTheConfiguredRange_IsNakd()
    {
        Subnet(null);
        using var r = await Svc().CreateDhcpResponseAsync(Request("172.16.5.5"));
        Assert.Equal((byte)DhcpMessageType.Nak, MessageType(r));
    }

    // ── 2. Internal error → silence (the client keeps its lease and retries) ──

    [Fact]
    public async Task Request_WhenTheLeaseStoreFails_IsAnsweredWithSilence_NotANak()
    {
        Subnet(Lan);
        var ip = IPAddress.Parse("192.168.50.120");
        _subnets.Setup(x => x.CheckRequestedIpAsync(Lan, Mac, ip, It.IsAny<CancellationToken>())).ReturnsAsync(RequestedIpVerdict.Allowed);
        _leases.Setup(x => x.CanAssignIpAsync(Mac, ip)).ThrowsAsync(new NpgsqlException("connection refused"));

        using var r = await Svc().CreateDhcpResponseAsync(Request("192.168.50.120"));

        Assert.True(r.IsEmpty);
    }

    [Fact]
    public async Task AnyMessage_WhenSubnetLookupFails_IsAnsweredWithSilence()
    {
        _subnets.Setup(x => x.FindSubnetForRequestAsync(It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new TimeoutException("db"));
        using var r = await Svc().CreateDhcpResponseAsync(Request("192.168.50.120"));
        Assert.True(r.IsEmpty);
    }

    // ── 3. Option 121 carries a default route ──

    private static readonly IPAddress Gw = IPAddress.Parse("192.168.50.1");

    [Fact]
    public void Option121_WithoutADefault_GetsOneViaTheRouter()
    {
        byte[] routes = [16, 10, 20, 192, 168, 50, 254];          // 10.20.0.0/16 via .254
        Span<byte> scratch = stackalloc byte[routes.Length + 5];
        var result = DhcpServerService.WithDefaultRoute(routes, Gw, scratch).ToArray();
        Assert.Equal([16, 10, 20, 192, 168, 50, 254, 0, 192, 168, 50, 1], result);
    }

    [Fact]
    public void Option121_ThatAlreadyHasADefault_IsLeftAlone()
    {
        byte[] routes = [0, 192, 168, 50, 9, 24, 10, 0, 5, 192, 168, 50, 254];
        Span<byte> scratch = stackalloc byte[routes.Length + 5];
        Assert.Equal(routes, DhcpServerService.WithDefaultRoute(routes, Gw, scratch).ToArray());
    }

    [Fact]
    public void Option121_WithNoRouterToPointAt_IsLeftAlone()
    {
        byte[] routes = [16, 10, 20, 192, 168, 50, 254];
        Span<byte> scratch = stackalloc byte[routes.Length + 5];
        Assert.Equal(routes, DhcpServerService.WithDefaultRoute(routes, null, scratch).ToArray());
    }

    [Fact]
    public async Task Offer_WithStaticRoutes_EndsOption121WithTheDefaultRoute()
    {
        var subnet = new DhcpSubnet
        {
            Id = Guid.NewGuid(), Name = "LAN", Network = "192.168.50.0/24",
            SubnetMask = IPAddress.Parse("255.255.255.0"), Router = Gw, DefaultLeaseTime = 3600,
            StaticRoutesJson = """[{"network":"10.20.0.0/16","gateway":"192.168.50.254"}]""",
        };
        Subnet(subnet);
        _subnets.Setup(x => x.FindAvailableIpInSubnetAsync(subnet, Mac, It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((IPAddress.Parse("192.168.50.120"), null));
        var req = Request("0.0.0.0"); req.MessageType = DhcpMessageType.Discover; req.RequestedIp = null;

        using var r = await Svc().CreateDhcpResponseAsync(req);

        var s = r.Span; byte[]? opt121 = null;
        for (var i = 240; i < s.Length - 1;)
        {
            if (s[i] == 255) break;
            if (s[i] == 0) { i++; continue; }
            if (s[i] == 121) { opt121 = s.Slice(i + 2, s[i + 1]).ToArray(); break; }
            i += 2 + s[i + 1];
        }
        Assert.NotNull(opt121);
        Assert.Equal([0, 192, 168, 50, 1], opt121![^5..]);
    }

    // ── 4. One bad interface no longer stops the others ──

    private sealed class FlakyWorker(params string[] broken)
        : DhcpWorker(NullLogger<DhcpWorker>.Instance, new ServiceCollection().BuildServiceProvider().GetRequiredService<IServiceScopeFactory>(),
                     new ConfigurationBuilder().Build())
    {
        public readonly List<string> Opened = [];
        internal override void OpenInterface(string iface)
        {
            if (broken.Contains(iface)) throw new InvalidOperationException($"No such device: {iface}");
            Opened.Add(iface);
        }
    }

    [Fact]
    public void OpenInterfaces_SkipsTheBrokenOne_AndServesTheRest()
    {
        var w = new FlakyWorker("eth9");
        var opened = w.OpenInterfaces(["eth1", "eth9", "eth2"]);
        Assert.Equal(["eth1", "eth2"], opened);
    }

    [Fact]
    public void OpenInterfaces_WhenNoneOpens_FailsLoudly()
    {
        var w = new FlakyWorker("eth1", "eth2");
        Assert.Throws<InvalidOperationException>(() => w.OpenInterfaces(["eth1", "eth2"]));
    }
}

/// <summary>Real-Postgres coverage of <see cref="DhcpSubnetService.CheckRequestedIpAsync"/>.</summary>
[Collection("Postgres")]
public sealed class DhcpRequestedIpCheckTests(PostgresFixture pg) : IAsyncLifetime
{
    private DhcpSubnetService _svc = null!;
    private DhcpSubnet _subnet = null!;

    public async Task InitializeAsync()
    {
        await pg.ResetSchemaAsync();
        await pg.BootstrapApplicationSchemaAsync();
        _svc = new DhcpSubnetService(pg.DataSource, NullLogger<DhcpSubnetService>.Instance);
        _subnet = await _svc.CreateSubnetAsync(new DhcpSubnet
        {
            Name = "home", Network = "10.91.0.0/24", SubnetMask = IPAddress.Parse("255.255.255.0"),
            Router = IPAddress.Parse("10.91.0.1"), Enabled = true,
        });
        await _svc.CreatePoolAsync(new DhcpPool { SubnetId = _subnet.Id, Name = "p", RangeStart = IPAddress.Parse("10.91.0.100"), RangeEnd = IPAddress.Parse("10.91.0.200"), Enabled = true });
        await Exec($"INSERT INTO dhcp_exclusions (subnet_id, ip_start, ip_end) VALUES ('{_subnet.Id}', '10.91.0.150', '10.91.0.159')");
        await Exec("INSERT INTO dhcp_mac_reservations (id, mac_address, reserved_ip) VALUES (uuid_generate_v4(), 'aa:bb:cc:00:00:07', '10.91.0.20')");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private async Task Exec(string sql)
    {
        await using var conn = await pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(sql, conn);
        await cmd.ExecuteNonQueryAsync();
    }

    [Theory]
    [InlineData("aa:bb:cc:00:00:01", "10.91.0.120", RequestedIpVerdict.Allowed)]        // in the pool
    [InlineData("aa:bb:cc:00:00:01", "192.168.1.57", RequestedIpVerdict.WrongNetwork)]  // roamed from another LAN
    [InlineData("aa:bb:cc:00:00:01", "10.91.0.50", RequestedIpVerdict.NotAssignable)]   // in the subnet, outside every pool
    [InlineData("aa:bb:cc:00:00:01", "10.91.0.155", RequestedIpVerdict.NotAssignable)]  // excluded
    [InlineData("aa:bb:cc:00:00:01", "10.91.0.1", RequestedIpVerdict.NotAssignable)]    // the router
    [InlineData("aa:bb:cc:00:00:01", "10.91.0.255", RequestedIpVerdict.NotAssignable)]  // broadcast
    [InlineData("aa:bb:cc:00:00:01", "10.91.0.0", RequestedIpVerdict.NotAssignable)]    // network
    [InlineData("aa:bb:cc:00:00:07", "10.91.0.20", RequestedIpVerdict.Allowed)]         // its own reservation, outside the pool
    public async Task CheckRequestedIp(string mac, string ip, RequestedIpVerdict expected) =>
        Assert.Equal(expected, await _svc.CheckRequestedIpAsync(_subnet, mac, IPAddress.Parse(ip)));
}
