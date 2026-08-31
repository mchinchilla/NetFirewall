using Moq;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Monitoring;

namespace NetFirewall.Tests.Monitoring;

public class WanTrafficServiceTests
{
    private static FwInterface Wan(string name, string? role = null, bool enabled = true) => new()
    {
        Id = Guid.NewGuid(),
        Name = name,
        Type = "WAN",
        Role = role,
        Enabled = enabled
    };

    private static NetworkMetrics Nic(string name, double rxBps, double txBps) => new()
    {
        InterfaceName = name,
        BytesReceivedPerSecond = rxBps,
        BytesSentPerSecond = txBps
    };

    [Fact]
    public void RoleLabel_MapsKnownRoles()
    {
        Assert.Equal("Primary", WanTrafficService.RoleLabel("primary_wan"));
        Assert.Equal("Secondary", WanTrafficService.RoleLabel("secondary_wan"));
        Assert.Equal("WAN", WanTrafficService.RoleLabel(null));
        Assert.Equal("WAN", WanTrafficService.RoleLabel("local_network"));
    }

    [Fact]
    public void Downsample_KeepsLastPoint()
    {
        var src = Enumerable.Range(0, 500)
            .Select(i => new WanInterfaceRatePoint(DateTime.UtcNow.AddSeconds(i), i, i))
            .ToList();
        var got = WanTrafficService.Downsample(src, 240);
        Assert.Equal(240, got.Count);
        Assert.Equal(src[^1].RxBytesPerSec, got[^1].RxBytesPerSec);
    }

    [Fact]
    public async Task GetLiveAsync_EmitsOneSeriesPerEnabledWan_AndSkipsLan()
    {
        var firewall = new Mock<IFirewallService>();
        firewall.Setup(f => f.GetInterfacesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new[]
            {
                Wan("ens192", "primary_wan"),
                Wan("ens224", "secondary_wan"),
                new FwInterface { Name = "ens160", Type = "LAN", Enabled = true },
                Wan("ens999", enabled: false)
            });

        var query = new Mock<IMetricsQueryService>();
        query.Setup(q => q.GetWanRatePerInterfaceAsync(It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new[]
            {
                new WanInterfaceRateSeries("ens192", new[]
                {
                    new WanInterfaceRatePoint(DateTime.UtcNow.AddSeconds(-10), 1_250_000, 125_000)
                })
            });

        var monitor = new Mock<ISystemMonitorService>();
        monitor.Setup(m => m.GetSnapshotAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SystemMetricsSnapshot
            {
                Timestamp = DateTime.UtcNow,
                Network =
                [
                    Nic("ens192", 2_000_000, 250_000),
                    Nic("ens224", 500_000, 50_000),
                    Nic("ens160", 9_000_000, 9_000_000)
                ]
            });

        var svc = new WanTrafficService(firewall.Object, query.Object, monitor.Object);
        var series = await svc.GetLiveAsync(15);

        Assert.Equal(2, series.Count);
        Assert.Equal(new[] { "ens192", "ens224" }, series.Select(s => s.Name));
        Assert.Equal("Primary", series[0].Label);
        Assert.Equal("Secondary", series[1].Label);

        // 2_000_000 B/s * 8 / 1e6 = 16 Mbps
        Assert.Equal(16, series[0].InMbps);
        Assert.Equal(2, series[0].OutMbps);
        // 500_000 B/s * 8 / 1e6 = 4 Mbps
        Assert.Equal(4, series[1].InMbps);
        Assert.Equal(0.4, series[1].OutMbps);
    }

    [Fact]
    public async Task GetLiveAsync_EmptyWans_ReturnsEmpty()
    {
        var firewall = new Mock<IFirewallService>();
        firewall.Setup(f => f.GetInterfacesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(Array.Empty<FwInterface>());
        var query = new Mock<IMetricsQueryService>();
        query.Setup(q => q.GetWanRatePerInterfaceAsync(It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Array.Empty<WanInterfaceRateSeries>());
        var monitor = new Mock<ISystemMonitorService>();
        monitor.Setup(m => m.GetSnapshotAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SystemMetricsSnapshot());

        var svc = new WanTrafficService(firewall.Object, query.Object, monitor.Object);
        Assert.Empty(await svc.GetLiveAsync(15));
    }

    [Fact]
    public async Task GetLiveAsync_SnapshotFailure_StillReturnsHistory()
    {
        var firewall = new Mock<IFirewallService>();
        firewall.Setup(f => f.GetInterfacesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new[] { Wan("ens192") });
        var query = new Mock<IMetricsQueryService>();
        query.Setup(q => q.GetWanRatePerInterfaceAsync(It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new[]
            {
                new WanInterfaceRateSeries("ens192", new[]
                {
                    new WanInterfaceRatePoint(DateTime.UtcNow.AddMinutes(-1), 125_000, 0)
                })
            });
        var monitor = new Mock<ISystemMonitorService>();
        monitor.Setup(m => m.GetSnapshotAsync(It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("no /proc"));

        var svc = new WanTrafficService(firewall.Object, query.Object, monitor.Object);
        var series = Assert.Single(await svc.GetLiveAsync(15));
        Assert.Equal(1, series.InMbps); // 125_000 * 8 / 1e6
        Assert.Equal(0, series.OutMbps);
    }
}
