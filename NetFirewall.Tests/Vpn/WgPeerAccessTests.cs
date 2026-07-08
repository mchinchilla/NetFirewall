using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Vpn;
using Xunit;

namespace NetFirewall.Tests.Vpn;

/// <summary>
/// Pins the per-client access model (LAN axis × internet axis, migration 00037):
/// every generated rule is pinned to the client's own tunnel IP (saddr) so one
/// permissive client can never widen another's access, narrowing intent removes
/// the old wider rules (reconcile), and a client with no access at all is
/// rejected at the controller.
/// </summary>
public sealed class WgPeerAccessTests
{
    private static readonly Guid WgIfaceId = Guid.NewGuid();
    private static readonly Guid LanIfaceId = Guid.NewGuid();
    private static readonly Guid WanIfaceId = Guid.NewGuid();

    private static WgServer Server() => new()
    {
        Id = Guid.NewGuid(), Name = "wg0", Mode = "server",
        PrivateKey = "PRIV", PublicKey = "PUB", AddressCidr = "10.10.0.1/24", Enabled = true,
    };

    private static WgPeer Client(string routeMode, bool internet, string[]? subnets = null) => new()
    {
        Id = Guid.NewGuid(), ServerId = Guid.NewGuid(), Name = "laptop",
        PublicKey = "LAPTOP_KEY", Role = "client", Enabled = true,
        AllowedIps = new[] { "10.10.0.5/32" },
        RouteMode = routeMode, AllowInternet = internet,
        AllowedSubnets = subnets ?? Array.Empty<string>(),
    };

    private static (VpnRoutingService svc, Mock<IFirewallService> fw) Make(
        IReadOnlyList<FwFilterRule>? existingForward = null)
    {
        var fw = new Mock<IFirewallService>();
        fw.Setup(x => x.GetInterfaceByNameAsync("wg0", It.IsAny<CancellationToken>()))
          .ReturnsAsync(new FwInterface { Id = WgIfaceId, Name = "wg0", Type = "VPN", Enabled = true });
        fw.Setup(x => x.GetInterfacesAsync(It.IsAny<CancellationToken>()))
          .ReturnsAsync(new[]
          {
              new FwInterface { Id = LanIfaceId, Name = "ens256", Type = "LAN", Enabled = true },
              new FwInterface { Id = WanIfaceId, Name = "ens192", Type = "WAN", Role = "primary_wan", Enabled = true },
          });
        fw.Setup(x => x.GetNatRulesAsync(It.IsAny<CancellationToken>()))
          .ReturnsAsync(Array.Empty<FwNatRule>());
        fw.Setup(x => x.GetFilterRulesAsync("forward", It.IsAny<CancellationToken>()))
          .ReturnsAsync(existingForward ?? Array.Empty<FwFilterRule>());

        var routing = new Mock<IPolicyRoutingService>();
        var svc = new VpnRoutingService(fw.Object, routing.Object, NullLogger<VpnRoutingService>.Instance);
        return (svc, fw);
    }

    [Fact]
    public async Task RestrictedClient_ForwardRules_ArePinnedToItsTunnelIp_AndDests()
    {
        var peer = Client("restricted", internet: false, subnets: new[] { "192.168.99.10/32", "192.168.3.0/24" });
        var (svc, fw) = Make();

        await svc.EnsurePeerForwardingAsync(Server(), peer);

        fw.Verify(x => x.CreateFilterRuleAsync(
            It.Is<FwFilterRule>(f =>
                f.InterfaceInId == WgIfaceId && f.InterfaceOutId == LanIfaceId
                && f.SourceAddresses!.Single() == "10.10.0.5/32"
                && f.DestinationAddresses!.Length == 2),
            It.IsAny<CancellationToken>()), Times.Once);
        // No internet: no masquerade, no wg→WAN forward.
        fw.Verify(x => x.CreateNatRuleAsync(It.IsAny<FwNatRule>(), It.IsAny<CancellationToken>()), Times.Never);
        fw.Verify(x => x.CreateFilterRuleAsync(
            It.Is<FwFilterRule>(f => f.InterfaceOutId == WanIfaceId), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task InternetOnlyClient_GetsWanRules_ButNoLanForward()
    {
        var peer = Client("none", internet: true);
        var (svc, fw) = Make();

        await svc.EnsurePeerForwardingAsync(Server(), peer);

        fw.Verify(x => x.CreateFilterRuleAsync(
            It.Is<FwFilterRule>(f => f.InterfaceOutId == LanIfaceId), It.IsAny<CancellationToken>()), Times.Never);
        fw.Verify(x => x.CreateNatRuleAsync(
            It.Is<FwNatRule>(n => n.Type == "masquerade"
                                  && n.SourceNetwork == "10.10.0.5/32"
                                  && n.OutputInterfaceId == WanIfaceId),
            It.IsAny<CancellationToken>()), Times.Once);
        fw.Verify(x => x.CreateFilterRuleAsync(
            It.Is<FwFilterRule>(f => f.InterfaceOutId == WanIfaceId
                                     && f.SourceAddresses!.Single() == "10.10.0.5/32"),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task WholeLanPlusInternet_GetsBothAxes_AllPinnedToPeer()
    {
        var peer = Client("split", internet: true);
        var (svc, fw) = Make();

        await svc.EnsurePeerForwardingAsync(Server(), peer);

        // LAN: no dest restriction, but still pinned to the peer's tunnel IP.
        fw.Verify(x => x.CreateFilterRuleAsync(
            It.Is<FwFilterRule>(f => f.InterfaceOutId == LanIfaceId
                                     && f.SourceAddresses!.Single() == "10.10.0.5/32"
                                     && f.DestinationAddresses == null),
            It.IsAny<CancellationToken>()), Times.Once);
        fw.Verify(x => x.CreateNatRuleAsync(It.IsAny<FwNatRule>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task NarrowingAccess_RemovesThePeersOldWiderRules()
    {
        var peer = Client("restricted", internet: false, subnets: new[] { "192.168.99.10/32" });
        // The peer previously had whole-LAN access — its old [vpn-auto] rule is live.
        var oldRule = new FwFilterRule
        {
            Id = Guid.NewGuid(), Chain = "forward", Action = "accept",
            InterfaceInId = WgIfaceId, InterfaceOutId = LanIfaceId,
            Description = $"[vpn-auto] peer {peer.Id} wg→ens256", Enabled = true,
        };
        var (svc, fw) = Make(existingForward: new[] { oldRule });

        await svc.EnsurePeerForwardingAsync(Server(), peer);

        fw.Verify(x => x.DeleteFilterRuleAsync(oldRule.Id, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task UpstreamPeer_GetsNoForwardingAtAll()
    {
        var peer = Client("full", internet: true);
        peer.Role = "upstream";
        var (svc, fw) = Make();

        await svc.EnsurePeerForwardingAsync(Server(), peer);

        fw.Verify(x => x.CreateFilterRuleAsync(It.IsAny<FwFilterRule>(), It.IsAny<CancellationToken>()), Times.Never);
        fw.Verify(x => x.CreateNatRuleAsync(It.IsAny<FwNatRule>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task ControllerSave_ClientWithNoAccessAtAll_IsRejected()
    {
        var server = Server();
        var wg = new Mock<IWireGuardService>();
        wg.Setup(x => x.GetServerAsync(It.IsAny<CancellationToken>())).ReturnsAsync(server);
        var daemon = new Mock<NetFirewall.Services.Daemon.IDaemonClient>();

        var controller = new NetFirewall.Web.Controllers.WireGuardPeersController(
            wg.Object,
            new Mock<IWireGuardConfigService>().Object,
            new Mock<IVpnRoutingService>().Object,
            new Mock<IFirewallService>().Object,
            daemon.Object,
            new Mock<NetFirewall.Services.Settings.IAppSettingsService>().Object,
            NullLogger<NetFirewall.Web.Controllers.WireGuardPeersController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() }
        };

        await controller.Save(new NetFirewall.Web.Models.Vpn.WgPeerFormViewModel
        {
            ServerId = server.Id, Name = "laptop", Role = "client",
            AllowedIpsRaw = "10.10.0.5/32", RouteMode = "none", AllowInternet = false,
        }, CancellationToken.None);

        // Rejected before any key generation or persistence.
        daemon.Verify(x => x.GenerateWireGuardKeyPairAsync(It.IsAny<CancellationToken>()), Times.Never);
        wg.Verify(x => x.CreatePeerAsync(It.IsAny<WgPeer>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}
