using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Vpn;
using Xunit;

namespace NetFirewall.Tests.Vpn;

/// <summary>
/// Pins the teardown safety contract: rows WE generated ([vpn-auto]/[vpn-egress])
/// are deleted, hand-authored rules referencing the interface are DISABLED (their
/// FK is SET NULL — deleting the interface under an enabled rule would silently
/// widen its match), the scaffold is removed, and the server row goes last.
/// </summary>
public sealed class WireGuardTeardownServiceTests
{
    private static readonly Guid IfaceId = Guid.NewGuid();
    private static readonly Guid TableRowId = Guid.NewGuid();

    private static WgServer Server() => new()
    {
        Id = Guid.NewGuid(), Name = "wg0", Mode = "client",
        PrivateKey = "PRIV", PublicKey = "PUB", AddressCidr = "10.10.0.2/32", Enabled = true,
    };

    private sealed class Fixture
    {
        public Mock<IWireGuardService> Wg { get; } = new();
        public Mock<IFirewallService> Fw { get; } = new();
        public Mock<IPolicyRoutingService> Routing { get; } = new();
        public Mock<IVpnRoutingService> VpnRouting { get; } = new();
        public Mock<IVpnHealthService> Health { get; } = new();

        public FwNatRule AutoNat { get; } = new()
            { Id = Guid.NewGuid(), Type = "masquerade", Description = "[vpn-auto] peer x → wan", Enabled = true };
        public FwNatRule HandNat { get; } = new()
            { Id = Guid.NewGuid(), Type = "masquerade", Description = "my hand nat via wg0",
              OutputInterfaceId = IfaceId, Enabled = true };
        public FwFilterRule AutoFwd { get; } = new()
            { Id = Guid.NewGuid(), Description = "[vpn-auto] peer x wg→lan", Enabled = true };
        public FwFilterRule HandFilter { get; } = new()
            { Id = Guid.NewGuid(), Description = "block guests to wg0", InterfaceOutId = IfaceId, Enabled = true };
        public FwFilterRule UnrelatedFilter { get; } = new()
            { Id = Guid.NewGuid(), Description = "lan to wan", Enabled = true };
        public FwMangleRule EgressMangle { get; } = new()
            { Id = Guid.NewGuid(), Description = "[vpn-egress] devices routed via wg0", Enabled = true };
        public FwStaticRoute TableRoute { get; } = new()
            { Id = Guid.NewGuid(), InterfaceId = IfaceId, TableId = TableRowId, Description = "[vpn-auto] default via wg0" };

        public WireGuardTeardownService Make(WgServer server)
        {
            Fw.Setup(x => x.GetInterfaceByNameAsync("wg0", It.IsAny<CancellationToken>()))
              .ReturnsAsync(new FwInterface { Id = IfaceId, Name = "wg0", Type = "VPN" });
            Fw.Setup(x => x.GetNatRulesAsync(It.IsAny<CancellationToken>()))
              .ReturnsAsync(new[] { AutoNat, HandNat });
            Fw.Setup(x => x.GetFilterRulesAsync(null, It.IsAny<CancellationToken>()))
              .ReturnsAsync(new[] { AutoFwd, HandFilter, UnrelatedFilter });
            Fw.Setup(x => x.GetMangleRulesAsync(null, It.IsAny<CancellationToken>()))
              .ReturnsAsync(new[] { EgressMangle });
            Fw.Setup(x => x.GetPortForwardsAsync(It.IsAny<CancellationToken>()))
              .ReturnsAsync(Array.Empty<FwPortForward>());
            Fw.Setup(x => x.GetStaticRoutesAsync(null, It.IsAny<CancellationToken>()))
              .ReturnsAsync(new[] { TableRoute });
            Fw.Setup(x => x.GetTrafficMarksAsync(It.IsAny<CancellationToken>()))
              .ReturnsAsync(new[] { new FwTrafficMark { Id = Guid.NewGuid(), MarkValue = 1280, RouteTable = "wg0" } });

            Routing.Setup(x => x.GetRouteTableByNameAsync("wg0", It.IsAny<CancellationToken>()))
                   .ReturnsAsync(new FwRouteTable { Id = TableRowId, TableId = 202, Name = "wg0" });
            Routing.Setup(x => x.GetPolicyRuleByTableNameAsync("wg0", It.IsAny<CancellationToken>()))
                   .ReturnsAsync(new FwPolicyRule { Id = Guid.NewGuid(), Fwmark = 1280, TableName = "wg0" });

            VpnRouting.Setup(x => x.GetEgressSourcesAsync(server, It.IsAny<CancellationToken>()))
                      .ReturnsAsync(new[] { "192.168.99.50/32" });

            Wg.Setup(x => x.GetPeersAsync(server.Id, It.IsAny<CancellationToken>()))
              .ReturnsAsync(new[]
              {
                  new WgPeer { Id = Guid.NewGuid(), ServerId = server.Id, Name = "us-vpn", PublicKey = "UP", Role = "upstream", Enabled = true },
                  new WgPeer { Id = Guid.NewGuid(), ServerId = server.Id, Name = "laptop", PublicKey = "LP", Role = "client", Enabled = true },
              });

            Health.Setup(x => x.ActiveAlertsAsync(It.IsAny<CancellationToken>()))
                  .ReturnsAsync(new[] { new SystemAlert { Source = "vpn", Severity = "danger", DedupeKey = $"vpn:{server.Id}:UP", Title = "t" } });
            Health.Setup(x => x.GetStateAsync(It.IsAny<CancellationToken>()))
                  .ReturnsAsync(new[] { new VpnHealthState { ServerId = server.Id, PublicKey = "UP" } });

            return new WireGuardTeardownService(
                Wg.Object, Fw.Object, Routing.Object, VpnRouting.Object, Health.Object,
                NullLogger<WireGuardTeardownService>.Instance);
        }
    }

    [Fact]
    public async Task ComputeImpact_SeparatesAutoRules_FromHandAuthoredOrphans()
    {
        var server = Server();
        var fx = new Fixture();
        var impact = await fx.Make(server).ComputeImpactAsync(server);

        Assert.Equal(new[] { "us-vpn" }, impact.TunnelNames);
        Assert.Equal(new[] { "laptop" }, impact.ClientNames);
        Assert.Equal(1, impact.AutoNatRuleCount);
        Assert.Equal(1, impact.AutoForwardRuleCount);
        Assert.Equal(1, impact.EgressMangleRuleCount);
        // Orphans: only hand rules referencing wg0 — the unrelated filter stays out.
        Assert.Equal(2, impact.OrphanedRules.Length);
        Assert.Contains(impact.OrphanedRules, o => o.Kind == "nat");
        Assert.Contains(impact.OrphanedRules, o => o.Kind == "filter");
        Assert.True(impact.HasInterfaceRow);
        Assert.True(impact.HasRouteTable);
        Assert.True(impact.HasPolicyRule);
        Assert.Equal(1, impact.TrafficMarkCount);
        Assert.Equal(1, impact.StaticRouteCount);
        Assert.Equal(1, impact.ActiveAlertCount);
    }

    [Fact]
    public async Task Teardown_DeletesTagged_DisablesHandRules_NeverDeletesThem()
    {
        var server = Server();
        var fx = new Fixture();
        await fx.Make(server).TeardownAsync(server);

        // Ours → deleted.
        fx.Fw.Verify(x => x.DeleteNatRuleAsync(fx.AutoNat.Id, It.IsAny<CancellationToken>()), Times.Once);
        fx.Fw.Verify(x => x.DeleteFilterRuleAsync(fx.AutoFwd.Id, It.IsAny<CancellationToken>()), Times.Once);
        fx.Fw.Verify(x => x.DeleteMangleRuleAsync(fx.EgressMangle.Id, It.IsAny<CancellationToken>()), Times.Once);

        // Hand-authored → disabled with a breadcrumb, NEVER deleted.
        fx.Fw.Verify(x => x.UpdateFilterRuleAsync(
            It.Is<FwFilterRule>(f => f.Id == fx.HandFilter.Id && !f.Enabled
                                     && f.Description!.Contains("[orphaned:")),
            It.IsAny<CancellationToken>()), Times.Once);
        fx.Fw.Verify(x => x.UpdateNatRuleAsync(
            It.Is<FwNatRule>(n => n.Id == fx.HandNat.Id && !n.Enabled
                                  && n.Description!.Contains("[orphaned:")),
            It.IsAny<CancellationToken>()), Times.Once);
        fx.Fw.Verify(x => x.DeleteFilterRuleAsync(fx.HandFilter.Id, It.IsAny<CancellationToken>()), Times.Never);
        fx.Fw.Verify(x => x.DeleteNatRuleAsync(fx.HandNat.Id, It.IsAny<CancellationToken>()), Times.Never);
        // The rule not referencing wg0 is untouched.
        fx.Fw.Verify(x => x.UpdateFilterRuleAsync(
            It.Is<FwFilterRule>(f => f.Id == fx.UnrelatedFilter.Id), It.IsAny<CancellationToken>()), Times.Never);
    }

    // ── Controller gate: the confirmation must hold server-side too ──

    [Fact]
    public async Task ControllerDelete_WrongConfirmName_TouchesNothing()
    {
        var server = Server();
        var wg = new Mock<IWireGuardService>();
        wg.Setup(x => x.GetServerAsync(It.IsAny<CancellationToken>())).ReturnsAsync(server);
        var teardown = new Mock<IWireGuardTeardownService>();
        var daemon = new Mock<NetFirewall.Services.Daemon.IDaemonClient>();

        var controller = new NetFirewall.Web.Controllers.WireGuardController(
            wg.Object, new Mock<IVpnRoutingService>().Object, teardown.Object, daemon.Object,
            NullLogger<NetFirewall.Web.Controllers.WireGuardController>.Instance)
        {
            ControllerContext = new Microsoft.AspNetCore.Mvc.ControllerContext
            {
                HttpContext = new Microsoft.AspNetCore.Http.DefaultHttpContext()
            }
        };

        await controller.Delete("wg9", CancellationToken.None);

        daemon.Verify(x => x.StopWireGuardAsync(It.IsAny<CancellationToken>()), Times.Never);
        teardown.Verify(x => x.TeardownAsync(It.IsAny<WgServer>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task ControllerDelete_DaemonStopFails_DoesNotTouchDb()
    {
        var server = Server();
        var wg = new Mock<IWireGuardService>();
        wg.Setup(x => x.GetServerAsync(It.IsAny<CancellationToken>())).ReturnsAsync(server);
        var teardown = new Mock<IWireGuardTeardownService>();
        var daemon = new Mock<NetFirewall.Services.Daemon.IDaemonClient>();
        daemon.Setup(x => x.StopWireGuardAsync(It.IsAny<CancellationToken>()))
              .ReturnsAsync(NetFirewall.Models.ServiceResponse<NetFirewall.Services.Daemon.NftApplyResultDto>.Fail("daemon unreachable"));

        var controller = new NetFirewall.Web.Controllers.WireGuardController(
            wg.Object, new Mock<IVpnRoutingService>().Object, teardown.Object, daemon.Object,
            NullLogger<NetFirewall.Web.Controllers.WireGuardController>.Instance)
        {
            ControllerContext = new Microsoft.AspNetCore.Mvc.ControllerContext
            {
                HttpContext = new Microsoft.AspNetCore.Http.DefaultHttpContext()
            }
        };

        await controller.Delete("wg0", CancellationToken.None);

        teardown.Verify(x => x.TeardownAsync(It.IsAny<WgServer>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Teardown_RemovesScaffold_ResolvesAlerts_DeletesServer()
    {
        var server = Server();
        var fx = new Fixture();
        await fx.Make(server).TeardownAsync(server);

        fx.Fw.Verify(x => x.DeleteStaticRouteAsync(fx.TableRoute.Id, It.IsAny<CancellationToken>()), Times.Once);
        fx.Routing.Verify(x => x.DeletePolicyRuleAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Once);
        fx.Fw.Verify(x => x.DeleteTrafficMarkAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Once);
        fx.Routing.Verify(x => x.DeleteRouteTableAsync(TableRowId, It.IsAny<CancellationToken>()), Times.Once);
        fx.Fw.Verify(x => x.DeleteInterfaceAsync(IfaceId, It.IsAny<CancellationToken>()), Times.Once);

        fx.Health.Verify(x => x.ResolveAlertAsync($"vpn:{server.Id}:UP", It.IsAny<CancellationToken>()), Times.Once);
        fx.Health.Verify(x => x.DeleteStateAsync(server.Id, "UP", It.IsAny<CancellationToken>()), Times.Once);

        fx.Wg.Verify(x => x.DeleteServerAsync(server.Id, It.IsAny<CancellationToken>()), Times.Once);
    }
}
