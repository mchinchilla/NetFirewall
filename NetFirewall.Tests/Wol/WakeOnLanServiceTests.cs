using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.Wol;
using NetFirewall.Services.Diagnostics;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Wol;

namespace NetFirewall.Tests.Wol;

/// <summary>
/// The daemon-side decision: which link a wake leaves through, and every way a
/// request is refused before anything reaches the wire. The socket is mocked.
/// </summary>
public class WakeOnLanServiceTests
{
    private readonly Mock<IWolPacketSender> _sender = new();
    private readonly Mock<IInterfaceHealthService> _links = new();
    private readonly Mock<IFirewallService> _fw = new();

    private static InterfaceHealth Link(string name, string? oper = "up", bool? carrier = true, params string[] addrs) =>
        new(name, true, oper, carrier, 1500, addrs, null, null, 0, 0, 0, 0, 0, 0);

    private WakeOnLanService Svc(IReadOnlyList<InterfaceHealth>? links = null, IReadOnlyList<FwInterface>? configured = null)
    {
        _links.Setup(l => l.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync(links ??
        [
            Link("lo", "unknown", null, "127.0.0.1/8"),
            Link("ens192", "up", true, "203.0.113.10/24"),
            Link("ens256", "up", true, "192.168.10.1/24"),
            Link("ens256.30", "up", true, "192.168.30.1/24"),
            Link("wg0", "unknown", null, "10.99.0.1/24"),
        ]);
        _fw.Setup(f => f.GetInterfacesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(configured ??
        [
            new FwInterface { Name = "ens192", Type = "WAN" },
            new FwInterface { Name = "ens256", Type = "LAN" },
            new FwInterface { Name = "wg0", Type = "VPN" },
        ]);
        return new WakeOnLanService(_sender.Object, _links.Object, _fw.Object, new DiagnosticInputValidator(),
            NullLogger<WakeOnLanService>.Instance);
    }

    private void VerifyNothingSent() =>
        _sender.Verify(s => s.SendAsync(It.IsAny<ReadOnlyMemory<byte>>(), It.IsAny<string>(), It.IsAny<IPAddress>(),
            It.IsAny<int>(), It.IsAny<int>(), It.IsAny<CancellationToken>()), Times.Never);

    [Fact]
    public async Task ExplicitInterface_SendsTheMagicPacketAsLimitedBroadcastOnThatLink()
    {
        ReadOnlyMemory<byte> sent = default;
        _sender.Setup(s => s.SendAsync(It.IsAny<ReadOnlyMemory<byte>>(), "ens256", IPAddress.Broadcast, 9, WolDefaults.Copies, It.IsAny<CancellationToken>()))
            .Callback<ReadOnlyMemory<byte>, string, IPAddress, int, int, CancellationToken>((p, _, _, _, _, _) => sent = p)
            .Returns(Task.CompletedTask);

        var r = await Svc().WakeAsync(new WolWakeRequest("00-11-32-ab-cd-ef", "ens256"));

        Assert.True(r.Success, r.Message);
        Assert.Equal("00:11:32:AB:CD:EF", r.Data!.Mac);
        Assert.Equal("ens256", r.Data.Interface);
        Assert.Equal("requested", r.Data.InterfaceSource);
        Assert.Equal("255.255.255.255", r.Data.Destination);
        Assert.Equal(MagicPacket.Build([0x00, 0x11, 0x32, 0xAB, 0xCD, 0xEF]), sent.ToArray());
    }

    [Fact]
    public async Task IpHint_PicksTheLinkWhoseSubnetHoldsIt()
    {
        var r = await Svc().WakeAsync(new WolWakeRequest("001132ABCDEF", IpHint: "192.168.30.44", Port: 7));

        Assert.True(r.Success, r.Message);
        Assert.Equal("ens256.30", r.Data!.Interface);
        Assert.Equal("subnet 192.168.30.0/24", r.Data.InterfaceSource);
        _sender.Verify(s => s.SendAsync(It.IsAny<ReadOnlyMemory<byte>>(), "ens256.30", IPAddress.Broadcast, 7, WolDefaults.Copies, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ExplicitInterface_WinsOverTheHint()
    {
        var r = await Svc().WakeAsync(new WolWakeRequest("001132ABCDEF", "ens256", "192.168.30.44"));

        Assert.True(r.Success, r.Message);
        Assert.Equal("ens256", r.Data!.Interface);
    }

    [Theory]
    [InlineData("ens192")]   // WAN
    [InlineData("wg0")]      // VPN
    [InlineData("lo")]
    public async Task NonLanLinks_AreRefused(string iface)
    {
        var r = await Svc().WakeAsync(new WolWakeRequest("001132ABCDEF", iface));

        Assert.False(r.Success);
        Assert.Contains("not a LAN interface", r.Message);
        VerifyNothingSent();
    }

    [Fact]
    public async Task HintOnTheWanSubnet_FindsNoLan()
    {
        var r = await Svc().WakeAsync(new WolWakeRequest("001132ABCDEF", IpHint: "203.0.113.50"));

        Assert.False(r.Success);
        Assert.Contains("No LAN interface", r.Message);
        VerifyNothingSent();
    }

    [Theory]
    [InlineData("00:11:32:ab:cd", null, null, null, "MAC address")]
    [InlineData("FF:FF:FF:FF:FF:FF", "ens256", null, null, "multicast/broadcast")]
    [InlineData("001132ABCDEF", "eth9", null, null, "Unknown interface")]
    [InlineData("001132ABCDEF", "ens256; reboot", null, null, "Interface name")]
    [InlineData("001132ABCDEF", null, "10.1", null, "not an IPv4 address")]
    [InlineData("001132ABCDEF", null, null, null, "Pick the interface")]
    [InlineData("001132ABCDEF", "ens256", null, 70000, "Port")]
    public async Task BadRequests_AreRefusedBeforeTheWire(string mac, string? iface, string? hint, int? port, string expected)
    {
        var r = await Svc().WakeAsync(new WolWakeRequest(mac, iface, hint, port));

        Assert.False(r.Success);
        Assert.Contains(expected, r.Message);
        VerifyNothingSent();
    }

    [Fact]
    public async Task LinkWithoutCarrier_IsRefused()
    {
        var svc = Svc(links: [Link("ens256", "down", false, "192.168.10.1/24")]);

        var r = await svc.WakeAsync(new WolWakeRequest("001132ABCDEF", "ens256"));

        Assert.False(r.Success);
        Assert.Contains("down", r.Message);
        VerifyNothingSent();
    }

    [Fact]
    public async Task SocketFailure_BecomesAFailedResponse()
    {
        _sender.Setup(s => s.SendAsync(It.IsAny<ReadOnlyMemory<byte>>(), It.IsAny<string>(), It.IsAny<IPAddress>(), It.IsAny<int>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new SocketException((int)SocketError.AccessDenied));

        var r = await Svc().WakeAsync(new WolWakeRequest("001132ABCDEF", "ens256"));

        Assert.False(r.Success);
        Assert.StartsWith("Could not send on ens256", r.Message);
    }

    [Fact]
    public async Task NoLinksVisible_SaysWhereWakesAreSentFrom()
    {
        var r = await Svc(links: []).WakeAsync(new WolWakeRequest("001132ABCDEF", "ens256"));

        Assert.False(r.Success);
        Assert.Contains("daemon", r.Message);
    }

    // ── PickBySubnet (pure) ────────────────────────────────────────────

    [Fact]
    public void PickBySubnet_LongestPrefixWins()
    {
        var links = new[]
        {
            Link("br0", "up", true, "10.0.0.1/16"),
            Link("br0.5", "up", true, "10.0.5.1/24"),
        };

        var pick = WakeOnLanService.PickBySubnet(links, IPAddress.Parse("10.0.5.77"), new HashSet<string>());

        Assert.Equal(("br0.5", "10.0.5.0/24"), pick);
    }

    [Fact]
    public void PickBySubnet_IgnoresPointToPointAndIpv6()
    {
        var links = new[] { Link("tun0", "up", true, "10.8.0.1/32", "fe80::1/64") };

        Assert.Null(WakeOnLanService.PickBySubnet(links, IPAddress.Parse("10.8.0.1"), new HashSet<string>()));
    }
}
