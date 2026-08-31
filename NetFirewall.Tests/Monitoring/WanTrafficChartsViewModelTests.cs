using NetFirewall.Web.Models.Monitoring;

namespace NetFirewall.Tests.Monitoring;

public class WanTrafficChartsViewModelTests
{
    [Fact]
    public void Dashboard_IsCompact_AndAppendsMinutes()
    {
        var vm = WanTrafficChartsViewModel.Dashboard();
        Assert.True(vm.Compact);
        Assert.Equal(60, vm.Minutes);
        Assert.Equal("/Monitoring/wan-traffic-series?minutes=60", vm.SeriesUrlWithMinutes);
    }

    [Fact]
    public void Monitoring_IsFull_AndSharesTheSameEndpoint()
    {
        var vm = WanTrafficChartsViewModel.Monitoring();
        Assert.False(vm.Compact);
        Assert.StartsWith("/Monitoring/wan-traffic-series", vm.SeriesUrlWithMinutes);
        Assert.Contains("minutes=60", vm.SeriesUrlWithMinutes);
    }
}
