using System.Net;
using System.Net.NetworkInformation;
using NetFirewall.Models.Dhcp;
using NetFirewall.Models.Firewall;
using NetFirewall.Web.Models;

namespace NetFirewall.Tests.Web;

public class DashboardPanelsTests
{
    [Fact]
    public void FromLeases_TakesNewestActive_SkipsExpired()
    {
        var now = DateTime.UtcNow;
        var leases = new[]
        {
            new DhcpLease { IpAddress = IPAddress.Parse("10.0.0.1"), MacAddress = PhysicalAddress.Parse("AABBCCDDEE01"), Hostname = "old", StartTime = now.AddHours(-2), EndTime = now.AddHours(1) },
            new DhcpLease { IpAddress = IPAddress.Parse("10.0.0.2"), MacAddress = PhysicalAddress.Parse("AABBCCDDEE02"), Hostname = "new", StartTime = now.AddMinutes(-5), EndTime = now.AddHours(1) },
            new DhcpLease { IpAddress = IPAddress.Parse("10.0.0.3"), MacAddress = PhysicalAddress.Parse("AABBCCDDEE03"), Hostname = "dead", StartTime = now.AddHours(-3), EndTime = now.AddMinutes(-1) },
        };

        var vm = DashboardPanels.FromLeases(leases, take: 8, manageUrl: "/leases");

        Assert.Equal(2, vm.TotalActive);
        Assert.Equal("new", vm.Rows[0].Hostname);
        Assert.Equal("aa:bb:cc:dd:ee:02", vm.Rows[0].Mac);
        Assert.Equal("/leases", vm.ManageUrl);
    }

    [Fact]
    public void FromFilters_OnlyEnabledDropAndReject()
    {
        var rules = new[]
        {
            new FwFilterRule { Action = "drop", Enabled = true, Chain = "forward", Description = "block", SourceAddresses = ["1.2.3.4"] },
            new FwFilterRule { Action = "drop", Enabled = false, Chain = "forward", Description = "off" },
            new FwFilterRule { Action = "accept", Enabled = true, Chain = "forward", Description = "ok" },
            new FwFilterRule { Action = "reject", Enabled = true, Chain = "input", Protocol = "tcp", DestinationPorts = ["22"] },
        };

        var vm = DashboardPanels.FromFilters(rules, take: 10, manageUrl: "/fw");

        Assert.Equal(2, vm.TotalLive);
        Assert.Contains(vm.Rows, r => r.Action == "drop" && r.Description == "block");
        Assert.Contains(vm.Rows, r => r.Action == "reject" && r.Match.Contains("tcp"));
    }

    [Fact]
    public void FromPending_HasPending_WhenAnyKindDirty()
    {
        var items = new[]
        {
            new PendingApplySummary { Kind = "nftables", LastAppliedAt = DateTime.UtcNow.AddMinutes(-10), PendingCount = 0 },
            new PendingApplySummary { Kind = "wireguard", LastAppliedAt = DateTime.UtcNow.AddHours(-1), PendingCount = 2 },
        };
        var vm = DashboardPanels.FromPending(items, "/apply");
        Assert.True(vm.HasPending);
        Assert.NotNull(vm.LastAppliedAt);
    }
}
