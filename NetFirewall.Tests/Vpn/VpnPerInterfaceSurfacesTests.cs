using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Diagnostics.Vpn;
using NetFirewall.Services.Monitoring;
using NetFirewall.Services.Network;
using NetFirewall.Services.Processes;
using NetFirewall.Services.Vpn;
using Xunit;

namespace NetFirewall.Tests.Vpn;

/// <summary>Surfaces that used to assume a single wg0 now follow every configured interface.</summary>
[SupportedOSPlatform("linux")]   // pure logic, mocked runner: silences CA1416, runs everywhere
public sealed class VpnPerInterfaceSurfacesTests
{
    private sealed class Links(params string[] up) : INetworkLinkProbe
    {
        public bool Exists(string interfaceName) => up.Contains(interfaceName);
    }

    [Fact]
    public async Task ServiceHealth_ListsEveryWireGuardInterface_FromItsLink_NotAWgQuickUnit()
    {
        var runner = new Mock<IProcessRunner>();
        runner.Setup(r => r.RunAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
              .ReturnsAsync(new ProcessResult(0, "ActiveState=active\nUnitFileState=enabled\n", ""));
        var wg = new Mock<IWireGuardService>();
        wg.Setup(x => x.ListServersAsync(It.IsAny<CancellationToken>())).ReturnsAsync(
        [
            new WgServer { Name = "wg0", Mode = "server", Enabled = true },
            new WgServer { Name = "wgc1", Mode = "client", Enabled = true },
            new WgServer { Name = "wgc2", Mode = "client", Enabled = false },
        ]);
        var scopes = new ServiceCollection().AddScoped(_ => wg.Object).BuildServiceProvider()
            .GetRequiredService<IServiceScopeFactory>();

        var all = await new SystemServiceHealthService(runner.Object, NullLogger<SystemServiceHealthService>.Instance,
            new Links("wg0"), scopes).GetAllAsync();

        Assert.DoesNotContain(all, s => s.UnitName.StartsWith("wg-quick@"));
        var w = all.Where(s => s.UnitName.StartsWith("wireguard:")).ToDictionary(s => s.UnitName);
        Assert.Equal(("active", "link up"), (w["wireguard:wg0"].ActiveState, w["wireguard:wg0"].SubState));
        Assert.Equal(("inactive", "link down"), (w["wireguard:wgc1"].ActiveState, w["wireguard:wgc1"].SubState));
        Assert.Equal("disabled", w["wireguard:wgc2"].SubState);
        Assert.Contains("outbound", w["wireguard:wgc1"].DisplayName);
    }

    [Fact]
    public void DoctorRemedies_PointAtTheDiagnosedInterface()
    {
        var check = DiagCheck.Fail("x", "Config", "t", "s", VpnRemedies.ServerForm());
        var other = DiagCheck.Fail("y", "Routing", "t", "s", VpnRemedies.PolicyRouting());

        Assert.Equal("/Vpn/WireGuard?iface=wgc1", VpnDoctorService.ForInterface(check, "wgc1").Remedy!.Href);
        Assert.Equal("/Firewall/Apply", VpnDoctorService.ForInterface(other, "wgc1").Remedy!.Href);   // untouched
        Assert.DoesNotContain("wg0", VpnRemedies.ApplyVpn().Hint);
    }
}
