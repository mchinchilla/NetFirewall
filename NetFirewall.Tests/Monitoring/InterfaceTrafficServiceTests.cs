using Moq;
using NetFirewall.Services.Monitoring;

namespace NetFirewall.Tests.Monitoring;

public class InterfaceTrafficServiceTests
{
    [Fact]
    public void SeriesLabel_PrefersWanRole()
    {
        Assert.Equal("Primary", InterfaceTrafficService.SeriesLabel("primary_wan", "WAN"));
        Assert.Equal("Secondary", InterfaceTrafficService.SeriesLabel("secondary_wan", "WAN"));
        Assert.Equal("LAN", InterfaceTrafficService.SeriesLabel(null, "LAN"));
        Assert.Equal("other", InterfaceTrafficService.SeriesLabel(null, ""));
    }

    [Fact]
    public async Task GetHourlyAsync_AlignsBuckets_AndDefaultsWanVisible()
    {
        var h1 = new DateTime(2026, 4, 27, 10, 0, 0, DateTimeKind.Utc);
        var h2 = new DateTime(2026, 4, 27, 11, 0, 0, DateTimeKind.Utc);
        var query = new Mock<IMetricsQueryService>();
        query.Setup(q => q.GetInterfaceTrafficHourlyAsync(It.IsAny<DateTime>(), It.IsAny<DateTime>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new[]
            {
                new InterfaceHourlyPoint(h1, "ens192", "WAN", "primary_wan", 45_000_000, 4_500_000),
                new InterfaceHourlyPoint(h2, "ens192", "WAN", "primary_wan", 90_000_000, 9_000_000),
                new InterfaceHourlyPoint(h2, "ens160", "LAN", null, 10_000_000, 1_000_000),
            });

        var svc = new InterfaceTrafficService(query.Object);
        var got = await svc.GetHourlyAsync(24);

        Assert.Equal(2, got.Labels.Length);
        Assert.Equal(2, got.Interfaces.Count);
        Assert.Equal("ens192", got.Interfaces[0].Name);
        Assert.Equal("Primary", got.Interfaces[0].Label);
        Assert.True(got.Interfaces[0].DefaultVisible);
        Assert.Equal("ens160", got.Interfaces[1].Name);
        Assert.False(got.Interfaces[1].DefaultVisible);

        // ens160 missing hour 1 → 0-filled
        Assert.Equal(0, got.Interfaces[1].InMbps[0]);
        Assert.True(got.Interfaces[1].InMbps[1] > 0);
        // 90e6 bytes/hour * 8 / 1e6 / 3600 = 0.2 Mbps
        Assert.Equal(0.2, got.Interfaces[0].InMbps[1]);
    }

    [Fact]
    public async Task GetHourlyAsync_NoWan_ShowsEverything()
    {
        var h1 = DateTime.UtcNow.AddHours(-1);
        var query = new Mock<IMetricsQueryService>();
        query.Setup(q => q.GetInterfaceTrafficHourlyAsync(It.IsAny<DateTime>(), It.IsAny<DateTime>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new[]
            {
                new InterfaceHourlyPoint(h1, "br0", "LAN", null, 1000, 1000)
            });

        var svc = new InterfaceTrafficService(query.Object);
        var got = await svc.GetHourlyAsync(24);
        Assert.True(Assert.Single(got.Interfaces).DefaultVisible);
    }

    [Fact]
    public async Task GetHourlyAsync_Empty_ReturnsEmpty()
    {
        var query = new Mock<IMetricsQueryService>();
        query.Setup(q => q.GetInterfaceTrafficHourlyAsync(It.IsAny<DateTime>(), It.IsAny<DateTime>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Array.Empty<InterfaceHourlyPoint>());

        var svc = new InterfaceTrafficService(query.Object);
        var got = await svc.GetHourlyAsync(24);
        Assert.Empty(got.Labels);
        Assert.Empty(got.Interfaces);
    }
}
