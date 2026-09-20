using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Vpn;

namespace NetFirewall.Tests.Vpn;

public class WireGuardBringUpServiceTests
{
    private static readonly WgServer Server = new()
    {
        Id = Guid.NewGuid(), Name = "wg0", Mode = "server",
        PrivateKey = "PRIV", PublicKey = "PUB", AddressCidr = "192.168.3.3/24", Enabled = true,
    };
    private static readonly IReadOnlyList<WgPeer> NoPeers = Array.Empty<WgPeer>();

    private static RoutingStep RouteStep(bool ok) =>
        new("ip-route", "ip route replace default dev wg0 metric 100 table wg0", true, ok, ok ? null : "RTNETLINK answers: No such device");

    private static (WireGuardBringUpService svc, Mock<IWireGuardApplyService> apply, Mock<IPolicyRoutingApplyService> routing) Make(
        NftApplyResult applyResult, PolicyRoutingApplyResult? routingResult)
    {
        var apply = new Mock<IWireGuardApplyService>();
        apply.Setup(a => a.ApplyAsync(It.IsAny<WgServer>(), It.IsAny<IReadOnlyList<WgPeer>>(), It.IsAny<CancellationToken>()))
             .ReturnsAsync(applyResult);
        var routing = new Mock<IPolicyRoutingApplyService>();
        if (routingResult is not null)
            routing.Setup(r => r.ReapplyRoutesForDeviceAsync("wg0", It.IsAny<CancellationToken>()))
                   .ReturnsAsync(routingResult);
        var svc = new WireGuardBringUpService(apply.Object, routing.Object, NullLogger<WireGuardBringUpService>.Instance);
        return (svc, apply, routing);
    }

    [Fact]
    public async Task LinkUp_ReappliesTheTunnelsRoutes_AndSaysSo()
    {
        var (svc, _, routing) = Make(
            new NftApplyResult { Success = true, ExitCode = 0, Output = "[#] wg-quick up wg0" },
            new PolicyRoutingApplyResult(true, false, new[] { RouteStep(true) }, null));

        var result = await svc.ApplyAsync(Server, NoPeers);

        Assert.True(result.Success);
        Assert.Equal(1, result.RoutesReapplied);
        Assert.Equal("WireGuard wg0 applied (exit 0); 1 policy route re-applied.", result.Describe("wg0"));
        Assert.Contains("ip route replace default dev wg0", result.CombinedOutput);
        routing.Verify(r => r.ReapplyRoutesForDeviceAsync("wg0", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task LinkFailedToComeUp_DoesNotTouchRouting()
    {
        var (svc, _, routing) = Make(
            new NftApplyResult { Success = false, ExitCode = 1, Error = "wg-quick: `wg0' already exists" },
            routingResult: null);

        var result = await svc.ApplyAsync(Server, NoPeers);

        Assert.False(result.Success);
        Assert.Null(result.Routing);
        Assert.Equal("wg-quick: `wg0' already exists", result.Describe("wg0"));
        routing.Verify(r => r.ReapplyRoutesForDeviceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task LinkUp_ButRoutesFailed_IsReportedAsAFailure_WithTheRemedy()
    {
        var (svc, _, _) = Make(
            new NftApplyResult { Success = true, ExitCode = 0, Output = "up" },
            new PolicyRoutingApplyResult(false, false, new[] { RouteStep(false) }, "1 route(s) failed"));

        var result = await svc.ApplyAsync(Server, NoPeers);

        Assert.False(result.Success);
        Assert.Equal(0, result.RoutesReapplied);
        Assert.Contains("wg0 is up, but re-applying its policy routes failed: 1 route(s) failed", result.Describe("wg0"));
        Assert.Contains("Policy routing", result.Describe("wg0"));
        Assert.Contains("# FAILED: RTNETLINK answers: No such device", result.CombinedOutput);
    }

    [Fact]
    public async Task LinkUp_WithNoTunnelRoutesInDb_StillSucceeds_AndSaysNothingRodeTheTunnel()
    {
        var (svc, _, _) = Make(
            new NftApplyResult { Success = true, ExitCode = 0, Output = "up" },
            new PolicyRoutingApplyResult(true, false, new[] { new RoutingStep("ip-route-noop", "# no per-table routes ride on wg0", true, true, null) }, null));

        var result = await svc.ApplyAsync(Server, NoPeers);

        Assert.True(result.Success);
        Assert.Equal("WireGuard wg0 applied (exit 0); no policy routes ride on wg0.", result.Describe("wg0"));
    }
}
