using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.System;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;
using NetFirewall.Services.Processes;
using Xunit;

namespace NetFirewall.Tests.Network;

/// <summary>
/// Mock-only coverage of <see cref="StaticRouteApplicator"/> — the orchestrator
/// that combines the route service, the network-config writer, and a live
/// <c>ip route</c> hot-add. Verifies the orchestration order and the
/// "persistent config OK but live add failed" warning path.
/// </summary>
public class StaticRouteApplicatorTests
{
    private readonly Mock<IFirewallService> _firewall = new();
    private readonly Mock<INetworkConfigResolver> _resolver = new();
    private readonly Mock<IProcessRunner> _runner = new();
    private readonly Mock<INetworkConfigService> _writer = new();

    private StaticRouteApplicator CreateSvc()
    {
        _resolver.Setup(r => r.ResolveAsync(It.IsAny<CancellationToken>())).ReturnsAsync(_writer.Object);
        return new(_firewall.Object, _resolver.Object, _runner.Object,
            NullLogger<StaticRouteApplicator>.Instance);
    }

    private static FwStaticRoute Route(Guid id, Guid ifaceId, string dest = "10.20.0.0/16",
        string? gw = "192.168.1.254", int metric = 100, bool enabled = true) => new()
    {
        Id = id,
        InterfaceId = ifaceId,
        Destination = dest,
        Gateway = gw is null ? null : IPAddress.Parse(gw),
        Metric = metric,
        Enabled = enabled
    };

    private static FwInterface Iface(Guid id, string name = "eth0") => new()
    {
        Id = id, Name = name, AddressingMode = "static"
    };

    private void StubGet(FwStaticRoute? route, FwInterface? iface, IReadOnlyList<FwStaticRoute>? all = null)
    {
        if (route is not null)
            _firewall.Setup(f => f.GetStaticRouteByIdAsync(route.Id, It.IsAny<CancellationToken>()))
                     .ReturnsAsync(route);
        else
            _firewall.Setup(f => f.GetStaticRouteByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
                     .ReturnsAsync((FwStaticRoute?)null);

        if (iface is not null)
            _firewall.Setup(f => f.GetInterfaceByIdAsync(iface.Id, It.IsAny<CancellationToken>()))
                     .ReturnsAsync(iface);
        else
            _firewall.Setup(f => f.GetInterfaceByIdAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
                     .ReturnsAsync((FwInterface?)null);

        _firewall.Setup(f => f.GetStaticRoutesAsync(It.IsAny<Guid?>(), It.IsAny<CancellationToken>()))
                 .ReturnsAsync(all ?? new List<FwStaticRoute>());
    }

    // ── ApplyAsync ─────────────────────────────────────────────────────

    [Fact]
    public async Task ApplyAsync_RouteMissing_ReturnsFail_NoSideEffects()
    {
        StubGet(route: null, iface: null);

        var result = await CreateSvc().ApplyAsync(Guid.NewGuid());

        Assert.False(result.Success);
        Assert.Contains("not found", result.Message);
        _writer.Verify(w => w.ApplyConfigAsync(It.IsAny<FwInterface>(), It.IsAny<IEnumerable<FwStaticRoute>>()), Times.Never);
    }

    [Fact]
    public async Task ApplyAsync_InterfaceMissing_ReturnsFail()
    {
        var route = Route(Guid.NewGuid(), Guid.NewGuid());
        StubGet(route, iface: null);

        var result = await CreateSvc().ApplyAsync(route.Id);

        Assert.False(result.Success);
        Assert.Contains("Interface", result.Message);
    }

    [Fact]
    public async Task ApplyAsync_HappyPath_RegeneratesPersistentConfig_AndHotAdds()
    {
        var iface = Iface(Guid.NewGuid());
        var route = Route(Guid.NewGuid(), iface.Id);
        StubGet(route, iface, all: new[] { route });

        _writer.Setup(w => w.ApplyConfigAsync(iface, It.IsAny<IEnumerable<FwStaticRoute>>()))
            .ReturnsAsync(new NetworkApplyResult { Success = true, Message = "applied" });
        _runner.Setup(r => r.RunAsync("ip", It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ProcessResult(0, "", ""));

        var result = await CreateSvc().ApplyAsync(route.Id);

        Assert.True(result.Success);
        // Persistent config regenerated with all enabled routes.
        _writer.Verify(w => w.ApplyConfigAsync(iface,
            It.Is<IEnumerable<FwStaticRoute>>(rs => rs.Count() == 1)), Times.Once);
        // Hot-add called with `ip route replace ... dev eth0 metric 100`.
        _runner.Verify(r => r.RunAsync(
            "ip",
            It.Is<string>(s => s.StartsWith("route replace 10.20.0.0/16") &&
                                s.Contains("via 192.168.1.254") &&
                                s.Contains("dev eth0") &&
                                s.Contains("metric 100")),
            It.IsAny<TimeSpan?>(),
            It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task ApplyAsync_RouteWithoutGateway_OmitsViaToken()
    {
        var iface = Iface(Guid.NewGuid());
        var route = Route(Guid.NewGuid(), iface.Id, gw: null);
        StubGet(route, iface, all: new[] { route });

        _writer.Setup(w => w.ApplyConfigAsync(iface, It.IsAny<IEnumerable<FwStaticRoute>>()))
            .ReturnsAsync(new NetworkApplyResult { Success = true });
        _runner.Setup(r => r.RunAsync("ip", It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ProcessResult(0, "", ""));

        await CreateSvc().ApplyAsync(route.Id);

        _runner.Verify(r => r.RunAsync(
            "ip",
            It.Is<string>(s => !s.Contains("via")),
            It.IsAny<TimeSpan?>(),
            It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task ApplyAsync_PersistentConfigSucceeds_LiveAddFails_StillReturnsSuccess()
    {
        // Operator-visible contract: persistent change succeeded, kernel hot-add was
        // best-effort. The applicator logs the warning but doesn't surface a failure.
        var iface = Iface(Guid.NewGuid());
        var route = Route(Guid.NewGuid(), iface.Id);
        StubGet(route, iface, all: new[] { route });

        _writer.Setup(w => w.ApplyConfigAsync(iface, It.IsAny<IEnumerable<FwStaticRoute>>()))
            .ReturnsAsync(new NetworkApplyResult { Success = true });
        _runner.Setup(r => r.RunAsync("ip", It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ProcessResult(2, "", "RTNETLINK answers: File exists"));

        var result = await CreateSvc().ApplyAsync(route.Id);

        Assert.True(result.Success);
    }

    [Fact]
    public async Task ApplyAsync_DisabledRoute_DoesNotCallIpRouteReplace()
    {
        var iface = Iface(Guid.NewGuid());
        var route = Route(Guid.NewGuid(), iface.Id, enabled: false);
        StubGet(route, iface, all: new[] { route });

        _writer.Setup(w => w.ApplyConfigAsync(iface, It.IsAny<IEnumerable<FwStaticRoute>>()))
            .ReturnsAsync(new NetworkApplyResult { Success = true });

        await CreateSvc().ApplyAsync(route.Id);

        _runner.Verify(r => r.RunAsync(
            "ip", It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task ApplyAsync_PersistentApplyFails_ReturnsFail_NoLiveAdd()
    {
        var iface = Iface(Guid.NewGuid());
        var route = Route(Guid.NewGuid(), iface.Id);
        StubGet(route, iface, all: new[] { route });

        _writer.Setup(w => w.ApplyConfigAsync(iface, It.IsAny<IEnumerable<FwStaticRoute>>()))
            .ReturnsAsync(new NetworkApplyResult { Success = false, Message = "permission denied" });

        var result = await CreateSvc().ApplyAsync(route.Id);

        Assert.False(result.Success);
        Assert.Contains("permission denied", result.Message);
        _runner.Verify(r => r.RunAsync(
            "ip", It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    // ── RemoveAsync ────────────────────────────────────────────────────

    [Fact]
    public async Task RemoveAsync_HappyPath_LiveDel_ThenDeleteFromDb_ThenRegenerateConfig()
    {
        var iface = Iface(Guid.NewGuid());
        var route = Route(Guid.NewGuid(), iface.Id);
        StubGet(route, iface, all: new List<FwStaticRoute>()); // after delete, no routes left

        _writer.Setup(w => w.ApplyConfigAsync(iface, It.IsAny<IEnumerable<FwStaticRoute>>()))
            .ReturnsAsync(new NetworkApplyResult { Success = true });
        _runner.Setup(r => r.RunAsync("ip", It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ProcessResult(0, "", ""));
        _firewall.Setup(f => f.DeleteStaticRouteAsync(route.Id, It.IsAny<CancellationToken>()))
                 .ReturnsAsync(true);

        var result = await CreateSvc().RemoveAsync(route.Id);

        Assert.True(result.Success);
        // Verify ip route del invoked.
        _runner.Verify(r => r.RunAsync(
            "ip",
            It.Is<string>(s => s.StartsWith("route del 10.20.0.0/16") && s.Contains("dev eth0")),
            It.IsAny<TimeSpan?>(),
            It.IsAny<CancellationToken>()),
            Times.Once);
        _firewall.Verify(f => f.DeleteStaticRouteAsync(route.Id, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task RemoveAsync_LiveDelFails_StillDeletesFromDbAndReturnsSuccess()
    {
        // "ip route del" failing is fine — the route may already be gone.
        var iface = Iface(Guid.NewGuid());
        var route = Route(Guid.NewGuid(), iface.Id);
        StubGet(route, iface, all: new List<FwStaticRoute>());

        _writer.Setup(w => w.ApplyConfigAsync(iface, It.IsAny<IEnumerable<FwStaticRoute>>()))
            .ReturnsAsync(new NetworkApplyResult { Success = true });
        _runner.Setup(r => r.RunAsync("ip", It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ProcessResult(2, "", "no such route"));
        _firewall.Setup(f => f.DeleteStaticRouteAsync(route.Id, It.IsAny<CancellationToken>()))
                 .ReturnsAsync(true);

        var result = await CreateSvc().RemoveAsync(route.Id);

        Assert.True(result.Success);
        _firewall.Verify(f => f.DeleteStaticRouteAsync(route.Id, It.IsAny<CancellationToken>()), Times.Once);
    }
}
