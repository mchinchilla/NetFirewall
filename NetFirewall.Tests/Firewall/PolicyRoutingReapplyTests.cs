using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;
using NetFirewall.Services.Processes;
using NetFirewall.Tests.Infra;
using System.Net;
using System.Runtime.Versioning;
using Xunit;

namespace NetFirewall.Tests.Firewall;

/// <summary>
/// <see cref="PolicyRoutingApplyService.ReapplyRoutesForDeviceAsync"/>: the
/// scoped re-install a WireGuard bring-up runs. Real Postgres for the rows,
/// mocked runner for the kernel.
/// </summary>
// PolicyRoutingApplyService is [SupportedOSPlatform("linux")]; the runner is mocked
// here, so nothing platform-specific executes and the tests run cross-platform.
// Marking the class silences CA1416 without skipping them off Linux — the same
// treatment ConntrackSamplerClassificationTests gets.
[SupportedOSPlatform("linux")]
[Collection("Postgres")]
public sealed class PolicyRoutingReapplyTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private readonly Mock<IProcessRunner> _runner = new();
    private FirewallService _fw = null!;
    private PolicyRoutingService _routing = null!;
    private PolicyRoutingApplyService _apply = null!;

    public PolicyRoutingReapplyTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _fw = new FirewallService(
            _pg.DataSource,
            new Mock<INetworkObjectResolver>().Object,
            new Mock<INetworkServiceResolver>().Object,
            NullLogger<FirewallService>.Instance);
        _routing = new PolicyRoutingService(_pg.DataSource, NullLogger<PolicyRoutingService>.Instance);
        _runner.Setup(r => r.RunAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
               .ReturnsAsync(new ProcessResult(0, "", ""));
        _runner.Setup(r => r.RunAsync(It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
               .ReturnsAsync(new ProcessResult(0, "[]", ""));
        _apply = new PolicyRoutingApplyService(_pg.DataSource, _runner.Object, NullLogger<PolicyRoutingApplyService>.Instance);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    [InlineData("wg0",    "wg0",  "wg0", true)]   // `dev wg0` route
    [InlineData(null,     "wg0",  "wg0", true)]   // `via` route inside the tunnel's table
    [InlineData("ens192", "wan1", "wg0", false)]
    [InlineData(null,     "wan1", "wg0", false)]
    public void RouteRidesOnDevice_MatchesByDeviceOrByTableName(string? deviceName, string table, string device, bool expected) =>
        Assert.Equal(expected, PolicyRoutingApplyService.RouteRidesOnDevice(deviceName, table, device));

    [Fact]
    public async Task ReapplyRoutesForDevice_AlsoReinstallsTheDevicesMainTableRoutes_OnlyThose()
    {
        // A site link's remote LAN on a Table=off interface: a main-table `dev wg0` route
        // (no table row) that the kernel purged with the link.
        var wg  = await _fw.CreateInterfaceAsync(new FwInterface { Name = "wg0",    Type = "VPN", AddressingMode = "static", Enabled = true, AutoStart = true });
        var wan = await _fw.CreateInterfaceAsync(new FwInterface { Name = "ens192", Type = "WAN", AddressingMode = "static", Enabled = true, AutoStart = true });
        await _fw.CreateStaticRouteAsync(new FwStaticRoute { InterfaceId = wg.Id,  Destination = "192.168.50.0/24", Enabled = true });
        await _fw.CreateStaticRouteAsync(new FwStaticRoute { InterfaceId = wan.Id, Destination = "10.99.0.0/16", Gateway = IPAddress.Parse("203.0.113.1"), Enabled = true });

        var result = await _apply.ReapplyRoutesForDeviceAsync("wg0");

        Assert.True(result.Success, result.Error);
        var cmd = Assert.Single(result.Steps.Where(s => s.Phase == "ip-route").Select(s => s.Command));
        Assert.StartsWith("ip route replace 192.168.50.0/24 dev wg0", cmd);
        Assert.EndsWith($"proto {PolicyRoutingApplyService.MainTableRouteProto} table main", cmd);
    }

    [Fact]
    public async Task ReapplyRoutesForDevice_PrunesOurStaleMainTableRoutes_Only()
    {
        // Kernel holds two of OUR routes on wg0; only 192.168.50.0/24 still has a row.
        var wg = await _fw.CreateInterfaceAsync(new FwInterface { Name = "wg0", Type = "VPN", AddressingMode = "static", Enabled = true, AutoStart = true });
        await _fw.CreateStaticRouteAsync(new FwStaticRoute { InterfaceId = wg.Id, Destination = "192.168.50.0/24", Enabled = true });
        _runner.Setup(r => r.RunAsync("ip", It.Is<IReadOnlyList<string>>(a => a.Contains("show")), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
               .ReturnsAsync(new ProcessResult(0, """[{"dst":"192.168.50.0/24","dev":"wg0"},{"dst":"192.168.77.0/24","dev":"wg0"}]""", ""));

        var result = await _apply.ReapplyRoutesForDeviceAsync("wg0");

        Assert.True(result.Success, result.Error);
        _runner.Verify(r => r.RunAsync("ip", It.Is<IReadOnlyList<string>>(a => a.Contains("del") && a.Contains("192.168.77.0/24")),
            It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()), Times.Once);
        _runner.Verify(r => r.RunAsync("ip", It.Is<IReadOnlyList<string>>(a => a.Contains("del") && a.Contains("192.168.50.0/24")),
            It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Theory]
    [InlineData("""[{"dst":"10.0.0.5"}]""", "10.0.0.5/32")]
    [InlineData("""[{"dst":"default"}]""", "default")]
    [InlineData("not json", null)]
    public void ParseRouteDestinations_NormalizesHosts(string json, string? expected)
    {
        var got = PolicyRoutingApplyService.ParseRouteDestinations(json);
        if (expected is null) Assert.Empty(got); else Assert.Equal(expected, Assert.Single(got));
    }

    [Fact]
    public async Task ReapplyRoutesForDevice_ReinstallsOnlyTheTunnelsRoutes()
    {
        var wg  = await _fw.CreateInterfaceAsync(new FwInterface { Name = "wg0",    Type = "VPN", AddressingMode = "static", Enabled = true, AutoStart = true });
        var wan = await _fw.CreateInterfaceAsync(new FwInterface { Name = "ens192", Type = "WAN", AddressingMode = "static", Enabled = true, AutoStart = true });
        var wgTable  = await _routing.EnsureRouteTableAsync(201, "wg0",  null);
        var wanTable = await _routing.EnsureRouteTableAsync(200, "wan1", null);
        await _fw.CreateStaticRouteAsync(new FwStaticRoute { InterfaceId = wg.Id,  Destination = "0.0.0.0/0", TableId = wgTable.Id,  Enabled = true });
        await _fw.CreateStaticRouteAsync(new FwStaticRoute { InterfaceId = wan.Id, Destination = "0.0.0.0/0", Gateway = IPAddress.Parse("203.0.113.1"), TableId = wanTable.Id, Enabled = true });

        var result = await _apply.ReapplyRoutesForDeviceAsync("wg0");

        Assert.True(result.Success, result.Error);
        var cmd = Assert.Single(result.Steps.Where(s => s.Phase == "ip-route").Select(s => s.Command));
        Assert.StartsWith("ip route replace default dev wg0", cmd);
        Assert.EndsWith("table wg0", cmd);
        _runner.Verify(r => r.RunAsync("ip",
            It.Is<string>(a => a.StartsWith("route replace default dev wg0") && a.EndsWith("table wg0")),
            It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()), Times.Once);
        _runner.Verify(r => r.RunAsync("ip", It.Is<string>(a => a.Contains("wan1")),
            It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task ReapplyRoutesForDevice_WithNothingInDb_IsANoOpSuccess()
    {
        var result = await _apply.ReapplyRoutesForDeviceAsync("wg0");

        Assert.True(result.Success);
        Assert.Contains(result.Steps, s => s.Phase == "ip-route-noop");
        _runner.Verify(r => r.RunAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}
