using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Vpn;
using Xunit;

namespace NetFirewall.Tests.Vpn;

/// <summary>
/// Mockable coverage for the WireGuard↔policy-routing bridge — the safety-critical
/// logic that must ADOPT existing rows (never clobber tekium's live wg0) and diff
/// egress sources without disturbing hand-authored mangle rules. Pure logic; the DB
/// is mocked via IFirewallService + IPolicyRoutingService.
/// </summary>
public sealed class VpnRoutingServiceTests
{
    private static readonly WgServer Wg0 = new()
    {
        Id = Guid.NewGuid(), Name = "wg0", Mode = "client",
        AddressCidr = "10.10.0.2/32", Enabled = true,
    };

    private static (VpnRoutingService svc, Mock<IFirewallService> fw, Mock<IPolicyRoutingService> routing) Make()
    {
        var fw = new Mock<IFirewallService>(MockBehavior.Strict);
        var routing = new Mock<IPolicyRoutingService>(MockBehavior.Strict);
        var svc = new VpnRoutingService(fw.Object, routing.Object, NullLogger<VpnRoutingService>.Instance);
        return (svc, fw, routing);
    }

    // ── Phase C: ADOPT existing scaffold (the anti-clobber proof) ──

    [Fact]
    public async Task EnsureScaffold_adopts_existing_mark_table_and_creates_nothing()
    {
        var (svc, fw, routing) = Make();
        var ifaceId = Guid.NewGuid();
        var tableId = Guid.NewGuid();
        var markId = Guid.NewGuid();

        // tekium's live state: wg0 interface, route table, policy rule fwmark 1280→wg0,
        // traffic mark 1280→wg0, and a default route already present.
        fw.Setup(x => x.GetInterfaceByNameAsync("wg0", It.IsAny<CancellationToken>()))
          .ReturnsAsync(new FwInterface { Id = ifaceId, Name = "wg0", Type = "VPN" });
        routing.Setup(x => x.GetRouteTableByNameAsync("wg0", It.IsAny<CancellationToken>()))
          .ReturnsAsync(new FwRouteTable { Id = tableId, TableId = 202, Name = "wg0" });
        routing.Setup(x => x.GetPolicyRuleByTableNameAsync("wg0", It.IsAny<CancellationToken>()))
          .ReturnsAsync(new FwPolicyRule { Fwmark = 1280, TableName = "wg0", Priority = 120 });
        fw.Setup(x => x.GetTrafficMarksAsync(It.IsAny<CancellationToken>()))
          .ReturnsAsync(new[] { new FwTrafficMark { Id = markId, MarkValue = 1280, RouteTable = "wg0" } });
        fw.Setup(x => x.GetStaticRoutesAsync(null, It.IsAny<CancellationToken>()))
          .ReturnsAsync(new[] { new FwStaticRoute { TableId = tableId, Destination = "0.0.0.0/0", InterfaceId = ifaceId } });

        var scaffold = await svc.EnsureRoutingScaffoldAsync(Wg0);

        Assert.Equal(1280, scaffold.Fwmark);
        Assert.Equal("wg0", scaffold.TableName);
        Assert.Equal(markId, scaffold.TrafficMarkId);

        // The critical assertion: NOTHING was created or mutated.
        fw.Verify(x => x.CreateInterfaceAsync(It.IsAny<FwInterface>(), It.IsAny<CancellationToken>()), Times.Never);
        fw.Verify(x => x.CreateTrafficMarkAsync(It.IsAny<FwTrafficMark>(), It.IsAny<CancellationToken>()), Times.Never);
        fw.Verify(x => x.UpdateTrafficMarkAsync(It.IsAny<FwTrafficMark>(), It.IsAny<CancellationToken>()), Times.Never);
        fw.Verify(x => x.CreateStaticRouteAsync(It.IsAny<FwStaticRoute>(), It.IsAny<CancellationToken>()), Times.Never);
        routing.Verify(x => x.EnsureRouteTableAsync(It.IsAny<int>(), It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Never);
        routing.Verify(x => x.EnsurePolicyRuleAsync(It.IsAny<long>(), It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task EnsureScaffold_clean_db_allocates_noncolliding_mark_and_creates_rows()
    {
        var (svc, fw, routing) = Make();
        var ifaceId = Guid.NewGuid();
        var tableId = Guid.NewGuid();
        var markId = Guid.NewGuid();

        // Nothing exists yet, but WAN marks 0x100/0x200 are in use → allocator must skip them.
        fw.Setup(x => x.GetInterfaceByNameAsync("wg0", It.IsAny<CancellationToken>())).ReturnsAsync((FwInterface?)null);
        fw.Setup(x => x.CreateInterfaceAsync(It.IsAny<FwInterface>(), It.IsAny<CancellationToken>()))
          .ReturnsAsync((FwInterface i, CancellationToken _) => { i.Id = ifaceId; return i; });
        routing.Setup(x => x.GetRouteTableByNameAsync("wg0", It.IsAny<CancellationToken>())).ReturnsAsync((FwRouteTable?)null);
        routing.Setup(x => x.AllocateTableIdAsync(It.IsAny<CancellationToken>())).ReturnsAsync(202);
        routing.Setup(x => x.EnsureRouteTableAsync(202, "wg0", It.IsAny<string?>(), It.IsAny<CancellationToken>()))
          .ReturnsAsync(new FwRouteTable { Id = tableId, TableId = 202, Name = "wg0" });
        routing.Setup(x => x.GetPolicyRuleByTableNameAsync("wg0", It.IsAny<CancellationToken>())).ReturnsAsync((FwPolicyRule?)null);
        // WAN marks already used; VPN allocator starts at 0x500.
        fw.Setup(x => x.GetTrafficMarksAsync(It.IsAny<CancellationToken>()))
          .ReturnsAsync(new[] {
              new FwTrafficMark { MarkValue = 0x100, RouteTable = "wan1" },
              new FwTrafficMark { MarkValue = 0x200, RouteTable = "wan2" },
          });
        routing.Setup(x => x.GetPolicyRulesAsync(It.IsAny<CancellationToken>()))
          .ReturnsAsync(new[] {
              new FwPolicyRule { Fwmark = 0x100, TableName = "wan1", Priority = 100 },
              new FwPolicyRule { Fwmark = 0x200, TableName = "wan2", Priority = 110 },
          });
        FwTrafficMark? createdMark = null;
        fw.Setup(x => x.CreateTrafficMarkAsync(It.IsAny<FwTrafficMark>(), It.IsAny<CancellationToken>()))
          .ReturnsAsync((FwTrafficMark m, CancellationToken _) => { m.Id = markId; createdMark = m; return m; });
        long ruleMark = 0;
        routing.Setup(x => x.EnsurePolicyRuleAsync(It.IsAny<long>(), "wg0", It.IsAny<int?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
          .ReturnsAsync((long fwmark, string tn, int? p, string? d, CancellationToken _) =>
              { ruleMark = fwmark; return new FwPolicyRule { Fwmark = fwmark, TableName = tn, Priority = p }; });
        fw.Setup(x => x.GetStaticRoutesAsync(null, It.IsAny<CancellationToken>())).ReturnsAsync(Array.Empty<FwStaticRoute>());
        fw.Setup(x => x.CreateStaticRouteAsync(It.IsAny<FwStaticRoute>(), It.IsAny<CancellationToken>()))
          .ReturnsAsync((FwStaticRoute r, CancellationToken _) => r);

        var scaffold = await svc.EnsureRoutingScaffoldAsync(Wg0);

        Assert.Equal(0x500, scaffold.Fwmark);        // first free in the VPN band
        Assert.Equal(0x500, createdMark!.MarkValue);
        Assert.Equal("wg0", createdMark.RouteTable);
        Assert.Equal(0x500, ruleMark);
        fw.Verify(x => x.CreateStaticRouteAsync(It.Is<FwStaticRoute>(r => r.Destination == "0.0.0.0/0" && r.Gateway == null), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ── Phase B: egress diff leaves hand-authored mangle rows alone ──

    [Fact]
    public async Task GetEgressSources_returns_union_of_mangle_sources_on_the_tunnel_mark()
    {
        var (svc, fw, routing) = Make();
        var markId = Guid.NewGuid();
        routing.Setup(x => x.GetPolicyRuleByTableNameAsync("wg0", It.IsAny<CancellationToken>()))
          .ReturnsAsync(new FwPolicyRule { Fwmark = 1280, TableName = "wg0" });
        fw.Setup(x => x.GetTrafficMarksAsync(It.IsAny<CancellationToken>()))
          .ReturnsAsync(new[] { new FwTrafficMark { Id = markId, MarkValue = 1280, RouteTable = "wg0" } });
        fw.Setup(x => x.GetMangleRulesAsync("prerouting", It.IsAny<CancellationToken>()))
          .ReturnsAsync(new[] {
              new FwMangleRule { Enabled = true, MarkId = markId, SourceAddresses = new[] { "192.168.99.25", "192.168.99.66" } },
              new FwMangleRule { Enabled = true, MarkId = markId, SourceAddresses = new[] { "192.168.99.73" } },
          });

        var sources = await svc.GetEgressSourcesAsync(Wg0);

        Assert.Equal(new[] { "192.168.99.25", "192.168.99.66", "192.168.99.73" }, sources);
    }
}
