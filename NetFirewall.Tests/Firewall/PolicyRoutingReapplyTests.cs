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
