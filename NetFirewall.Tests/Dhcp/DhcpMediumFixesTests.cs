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
/// The medium findings of the 2026-11 DHCP review (giaddr precedence is pinned in
/// <see cref="DhcpSubnetServiceTests"/>): server identifier = our own address, option 82 echoed,
/// a re-DISCOVERing client keeps its address / gets the one it asks for, offered addresses held.
/// </summary>
public sealed class DhcpMediumFixesTests
{
    private const string Mac = "aa:bb:cc:00:00:01";
    private readonly Mock<IDhcpLeasesService> _leases = new(MockBehavior.Strict);
    private readonly Mock<IDhcpSubnetService> _subnets = new(MockBehavior.Strict);

    private static readonly DhcpSubnet Lan = new()
    {
        Id = Guid.NewGuid(), Name = "LAN", Network = "192.168.50.0/24",
        SubnetMask = IPAddress.Parse("255.255.255.0"),
        Router = IPAddress.Parse("192.168.50.254"),        // the gateway is ANOTHER box
        DefaultLeaseTime = 3600,
    };

    private sealed class FixedAddresses(params (string Iface, string Ip, int Prefix)[] entries) : IInterfaceAddressProvider
    {
        public IReadOnlyList<(IPAddress Address, int PrefixLength)> GetIPv4(string interfaceName) =>
            entries.Where(e => e.Iface == interfaceName).Select(e => (IPAddress.Parse(e.Ip), e.Prefix)).ToArray();
    }

    private DhcpServerService Svc(IInterfaceAddressProvider? addresses = null) => new(
        _leases.Object, _subnets.Object, NullLogger<DhcpServerService>.Instance,
        Options.Create(new DhcpConfig
        {
            ServerIp = IPAddress.Parse("10.0.0.1"), IpRangeStart = IPAddress.Parse("10.0.0.100"),
            IpRangeEnd = IPAddress.Parse("10.0.0.200"), SubnetMask = IPAddress.Parse("255.255.255.0"),
            Gateway = IPAddress.Parse("10.0.0.1"), DnsServers = [IPAddress.Parse("8.8.8.8")], LeaseTime = 3600,
        }),
        failoverService: null, interfaceAddresses: addresses);

    private static DhcpRequest Discover(string iface = "eth1", IPAddress? giaddr = null, byte[]? option82 = null) => new()
    {
        ClientMac = Mac,
        ChAddr = [0xAA, 0xBB, 0xCC, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        Xid = [1, 2, 3, 4],
        CiAddr = IPAddress.Any, YiAddr = IPAddress.Any, SiAddr = IPAddress.Any, GiAddr = giaddr ?? IPAddress.Any,
        MessageType = DhcpMessageType.Discover,
        SourceInterfaceName = iface,
        RelayAgentInformation = option82,
    };

    private void Offering(string ip)
    {
        _subnets.Setup(x => x.FindSubnetForRequestAsync(It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>())).ReturnsAsync(Lan);
        _subnets.Setup(x => x.MatchClientClassAsync(It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>())).ReturnsAsync((DhcpClass?)null);
        _subnets.Setup(x => x.FindAvailableIpInSubnetAsync(Lan, Mac, It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((IPAddress.Parse(ip), null));
    }

    private static byte[]? Option(DhcpResponseBuffer r, byte code)
    {
        var s = r.Span;
        for (var i = 240; i < s.Length - 1;)
        {
            if (s[i] == 255) break;
            if (s[i] == 0) { i++; continue; }
            if (s[i] == code) return s.Slice(i + 2, s[i + 1]).ToArray();
            i += 2 + s[i + 1];
        }
        return null;
    }

    // ── Server identifier = this server, not the subnet's gateway ──

    [Fact]
    public async Task ServerIdentifier_IsOurAddressOnTheReceivingInterface_NotTheGateway()
    {
        Offering("192.168.50.120");
        var svc = Svc(new FixedAddresses(("eth1", "10.9.9.9", 24), ("eth1", "192.168.50.1", 24)));

        using var r = await svc.CreateDhcpResponseAsync(Discover());

        Assert.Equal(IPAddress.Parse("192.168.50.1").GetAddressBytes(), Option(r, 54));   // in the client's subnet
    }

    [Fact]
    public async Task ServerIdentifier_ForARelayedClient_IsTheAddressTheRelayTalksTo()
    {
        Offering("192.168.50.120");
        var svc = Svc(new FixedAddresses(("eth0", "172.16.0.1", 24)));

        using var r = await svc.CreateDhcpResponseAsync(Discover(iface: "eth0", giaddr: IPAddress.Parse("192.168.50.254")));

        Assert.Equal(IPAddress.Parse("172.16.0.1").GetAddressBytes(), Option(r, 54));
    }

    [Fact]
    public async Task ServerIdentifier_WithUnknownInterface_FallsBackToTheRouter()
    {
        Offering("192.168.50.120");
        using var r = await Svc(new FixedAddresses()).CreateDhcpResponseAsync(Discover());
        Assert.Equal(Lan.Router!.GetAddressBytes(), Option(r, 54));
    }

    [Fact]
    public async Task Request_AddressedToOurInterfaceAddress_IsNotIgnored()
    {
        // The SELECTING check must use the same identity the OFFER carried.
        _subnets.Setup(x => x.FindSubnetForRequestAsync(It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>())).ReturnsAsync(Lan);
        _subnets.Setup(x => x.MatchClientClassAsync(It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>())).ReturnsAsync((DhcpClass?)null);
        var ip = IPAddress.Parse("192.168.50.120");
        _subnets.Setup(x => x.CheckRequestedIpAsync(Lan, Mac, ip, It.IsAny<CancellationToken>())).ReturnsAsync(RequestedIpVerdict.Allowed);
        _leases.Setup(x => x.CanAssignIpAsync(Mac, ip)).ReturnsAsync(true);
        _leases.Setup(x => x.AssignLeaseAsync(Mac, ip, 3600, null)).Returns(Task.CompletedTask);
        var req = Discover(); req.MessageType = DhcpMessageType.Request;
        req.RequestedIp = ip; req.ServerIdentifier = IPAddress.Parse("192.168.50.1");

        using var r = await Svc(new FixedAddresses(("eth1", "192.168.50.1", 24))).CreateDhcpResponseAsync(req);

        Assert.Equal((byte)DhcpMessageType.Ack, Option(r, 53)![0]);
    }

    // ── Option 82 echoed verbatim, last before End ──

    [Fact]
    public async Task Option82_FromTheRelay_IsEchoedVerbatim_AsTheLastOption()
    {
        Offering("192.168.50.120");
        byte[] rai = [1, 4, 0x00, 0x0A, 0x00, 0x01, 2, 3, 0xAB, 0xCD, 0xEF];   // circuit-id + remote-id
        using var r = await Svc().CreateDhcpResponseAsync(Discover(giaddr: IPAddress.Parse("192.168.50.254"), option82: rai));

        Assert.Equal(rai, Option(r, 82));
        var s = r.Span;
        Assert.Equal(255, s[r.Length - 1]);
        Assert.Equal(82, s[r.Length - 1 - rai.Length - 2]);
    }

    [Fact]
    public async Task NoOption82_InTheRequest_NoneInTheReply()
    {
        Offering("192.168.50.120");
        using var r = await Svc().CreateDhcpResponseAsync(Discover());
        Assert.Null(Option(r, 82));
    }

    [Fact]
    public void Worker_ParsesOption82()
    {
        var pkt = new byte[300];
        pkt[0] = 1; pkt[1] = 1; pkt[2] = 6;
        pkt[28] = 0xAA; pkt[29] = 0xBB; pkt[30] = 0xCC; pkt[33] = 1;
        pkt[236] = 99; pkt[237] = 130; pkt[238] = 83; pkt[239] = 99;
        byte[] opts = [53, 1, 1, 82, 4, 1, 2, 0x0A, 0x0B, 255];
        opts.CopyTo(pkt, 240);
        var worker = new DhcpWorker(NullLogger<DhcpWorker>.Instance,
            new ServiceCollection().BuildServiceProvider().GetRequiredService<IServiceScopeFactory>(), new ConfigurationBuilder().Build());

        Assert.True(worker.TryParseDhcpRequest(pkt, new IPEndPoint(IPAddress.Any, 68), out var req));
        Assert.Equal([1, 2, 0x0A, 0x0B], req.RelayAgentInformation);
    }
}

/// <summary>Real Postgres + real LeaseCache: address stability and offer holds on DISCOVER.</summary>
[Collection("Postgres")]
public sealed class DhcpOfferStabilityTests(PostgresFixture pg) : IAsyncLifetime
{
    private DhcpSubnetService _svc = null!;
    private LeaseCache _cache = null!;
    private DhcpSubnet _subnet = null!;

    public async Task InitializeAsync()
    {
        await pg.ResetSchemaAsync();
        await pg.BootstrapApplicationSchemaAsync();
        _cache = new LeaseCache(pg.DataSource, NullLogger<LeaseCache>.Instance, batchSize: 100, batchIntervalMs: 20, cleanupIntervalSeconds: 60);
        _svc = new DhcpSubnetService(pg.DataSource, NullLogger<DhcpSubnetService>.Instance, _cache);
        _subnet = await _svc.CreateSubnetAsync(new DhcpSubnet
        {
            Name = "home", Network = "10.91.0.0/24", SubnetMask = IPAddress.Parse("255.255.255.0"),
            Router = IPAddress.Parse("10.91.0.1"), Enabled = true,
        });
        await _svc.CreatePoolAsync(new DhcpPool { SubnetId = _subnet.Id, Name = "p", RangeStart = IPAddress.Parse("10.91.0.100"), RangeEnd = IPAddress.Parse("10.91.0.200"), Enabled = true });
    }

    public Task DisposeAsync() { _cache.Dispose(); return Task.CompletedTask; }

    private static DhcpRequest Discover(string mac, string? wanted = null) => new()
    {
        ClientMac = mac, MessageType = DhcpMessageType.Discover,
        CiAddr = IPAddress.Any, GiAddr = IPAddress.Any, YiAddr = IPAddress.Any, SiAddr = IPAddress.Any,
        RequestedIp = wanted is null ? null : IPAddress.Parse(wanted),
    };

    private Task<(IPAddress? Ip, DhcpPool? Pool)> Offer(string mac, string? wanted = null) =>
        _svc.FindAvailableIpInSubnetAsync(_subnet, mac, Discover(mac, wanted));

    [Fact]
    public async Task ReDiscover_KeepsTheClientsCurrentAddress()
    {
        await _cache.SetLeaseAsync("aa:bb:cc:00:00:01", IPAddress.Parse("10.91.0.150"), 3600);
        var (ip, _) = await Offer("aa:bb:cc:00:00:01");
        Assert.Equal(IPAddress.Parse("10.91.0.150"), ip);   // not .100, the first free one
    }

    [Fact]
    public async Task Discover_WithOption50_GetsTheAddressItAsksFor_WhenFree()
    {
        var (ip, _) = await Offer("aa:bb:cc:00:00:02", wanted: "10.91.0.177");
        Assert.Equal(IPAddress.Parse("10.91.0.177"), ip);
    }

    [Theory]
    [InlineData("10.91.0.50")]      // in the subnet, outside the pool
    [InlineData("192.168.7.7")]     // another network
    public async Task Discover_WithOption50_ForAnAddressWeWouldNotHandOut_GetsAPoolAddress(string wanted)
    {
        var (ip, _) = await Offer("aa:bb:cc:00:00:03", wanted);
        Assert.Equal(IPAddress.Parse("10.91.0.100"), ip);
    }

    [Fact]
    public async Task Discover_WithOption50_ForAnotherClientsAddress_GetsAPoolAddress()
    {
        await _cache.SetLeaseAsync("aa:bb:cc:00:00:09", IPAddress.Parse("10.91.0.177"), 3600);
        var (ip, _) = await Offer("aa:bb:cc:00:00:04", wanted: "10.91.0.177");
        Assert.NotEqual(IPAddress.Parse("10.91.0.177"), ip);
    }

    [Fact]
    public async Task TwoClientsDiscoveringTogether_AreOfferedDifferentAddresses()
    {
        var (a, _) = await Offer("aa:bb:cc:00:00:0a");
        var (b, _) = await Offer("aa:bb:cc:00:00:0b");
        Assert.NotNull(a); Assert.NotNull(b);
        Assert.NotEqual(a, b);                                  // the first offer is held
        Assert.False(_cache.CanMacUseIp("aa:bb:cc:00:00:0b", a!)); // B can't REQUEST A's offer either
        Assert.True(_cache.CanMacUseIp("aa:bb:cc:00:00:0a", a!));
    }
}
