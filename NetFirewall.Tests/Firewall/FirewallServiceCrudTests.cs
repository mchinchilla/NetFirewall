using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;
using NetFirewall.Tests.Infra;
using Xunit;

namespace NetFirewall.Tests.Firewall;

/// <summary>
/// Real-Postgres CRUD coverage for the slices of <see cref="FirewallService"/>
/// not exercised by <c>FirewallServiceGeneratorTests</c>: traffic marks, mangle
/// rules, QoS configs/classes, static routes, audit log search.
/// Resolvers are stubbed (passthrough) — they have their own coverage.
/// </summary>
[Collection("Postgres")]
public sealed class FirewallServiceCrudTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private FirewallService _svc = null!;

    public FirewallServiceCrudTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();

        var objectResolver = new Mock<INetworkObjectResolver>();
        objectResolver.Setup(r => r.ResolveAsync(It.IsAny<IEnumerable<string>>(), It.IsAny<CancellationToken>()))
            .Returns<IEnumerable<string>, CancellationToken>((i, _) =>
                Task.FromResult<IReadOnlyList<string>>(i.ToList()));

        var serviceResolver = new Mock<INetworkServiceResolver>();
        serviceResolver.Setup(r => r.ResolveAsync(It.IsAny<IEnumerable<string>>(), It.IsAny<CancellationToken>()))
            .Returns<IEnumerable<string>, CancellationToken>((i, _) =>
                Task.FromResult<IReadOnlyList<string>>(i.ToList()));

        _svc = new FirewallService(_pg.DataSource, objectResolver.Object, serviceResolver.Object,
            NullLogger<FirewallService>.Instance);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<FwInterface> CreateInterfaceAsync(string name = "eth0") =>
        await _svc.CreateInterfaceAsync(new FwInterface
        {
            Name = name, Type = "LAN", AddressingMode = "static", Enabled = true, AutoStart = true
        });

    // ── Traffic Marks ──────────────────────────────────────────────────

    [Fact]
    public async Task TrafficMark_CrudRoundTrip()
    {
        var created = await _svc.CreateTrafficMarkAsync(new FwTrafficMark
        {
            Name = "voip", MarkValue = 100, Description = "VoIP traffic", RouteTable = "voip"
        });
        Assert.NotEqual(Guid.Empty, created.Id);

        var fetched = await _svc.GetTrafficMarkByIdAsync(created.Id);
        Assert.NotNull(fetched);
        Assert.Equal("voip", fetched!.Name);
        Assert.Equal(100, fetched.MarkValue);

        fetched.Description = "renamed";
        await _svc.UpdateTrafficMarkAsync(fetched);
        Assert.Equal("renamed", (await _svc.GetTrafficMarkByIdAsync(created.Id))!.Description);

        Assert.True(await _svc.DeleteTrafficMarkAsync(created.Id));
        Assert.Null(await _svc.GetTrafficMarkByIdAsync(created.Id));
    }

    [Fact]
    public async Task TrafficMarks_GetAll_OrdersByMarkValue()
    {
        await _svc.CreateTrafficMarkAsync(new FwTrafficMark { Name = "high", MarkValue = 300 });
        await _svc.CreateTrafficMarkAsync(new FwTrafficMark { Name = "low",  MarkValue = 100 });
        await _svc.CreateTrafficMarkAsync(new FwTrafficMark { Name = "mid",  MarkValue = 200 });

        var all = await _svc.GetTrafficMarksAsync();

        Assert.Equal(new[] { 100, 200, 300 }, all.Select(m => m.MarkValue));
    }

    // ── Mangle rules ───────────────────────────────────────────────────

    [Fact]
    public async Task MangleRule_CrudRoundTrip()
    {
        var mark = await _svc.CreateTrafficMarkAsync(new FwTrafficMark { Name = "voip", MarkValue = 100 });
        var rule = await _svc.CreateMangleRuleAsync(new FwMangleRule
        {
            Chain = "prerouting", MarkId = mark.Id, Protocol = "udp",
            DestinationPorts = new[] { "5060" },
            Description = "SIP marking", Priority = 10
        });
        Assert.NotEqual(Guid.Empty, rule.Id);

        var fetched = await _svc.GetMangleRuleByIdAsync(rule.Id);
        Assert.Equal("prerouting", fetched!.Chain);
        Assert.Equal(mark.Id, fetched.MarkId);
        Assert.Equal(new[] { "5060" }, fetched.DestinationPorts);

        Assert.True(await _svc.DeleteMangleRuleAsync(rule.Id));
        Assert.Null(await _svc.GetMangleRuleByIdAsync(rule.Id));
    }

    [Fact]
    public async Task MangleRules_FilterByChain()
    {
        var mark = await _svc.CreateTrafficMarkAsync(new FwTrafficMark { Name = "m", MarkValue = 1 });
        await _svc.CreateMangleRuleAsync(new FwMangleRule { Chain = "prerouting",  MarkId = mark.Id });
        await _svc.CreateMangleRuleAsync(new FwMangleRule { Chain = "postrouting", MarkId = mark.Id });

        var pre  = await _svc.GetMangleRulesAsync(chain: "prerouting");
        var post = await _svc.GetMangleRulesAsync(chain: "postrouting");
        var all  = await _svc.GetMangleRulesAsync();

        Assert.Single(pre);
        Assert.Single(post);
        Assert.Equal(2, all.Count);
    }

    // ── QoS Config + Class ─────────────────────────────────────────────

    [Fact]
    public async Task QosConfig_CrudRoundTrip()
    {
        var iface = await CreateInterfaceAsync();
        var cfg = await _svc.CreateQosConfigAsync(new FwQosConfig
        {
            InterfaceId = iface.Id,
            Enabled = true,
            TotalBandwidthMbps = 100
        });
        Assert.NotEqual(Guid.Empty, cfg.Id);

        var fetched = await _svc.GetQosConfigByIdAsync(cfg.Id);
        Assert.Equal(100, fetched!.TotalBandwidthMbps);

        fetched.TotalBandwidthMbps = 500;
        await _svc.UpdateQosConfigAsync(fetched);
        Assert.Equal(500, (await _svc.GetQosConfigByIdAsync(cfg.Id))!.TotalBandwidthMbps);

        Assert.True(await _svc.DeleteQosConfigAsync(cfg.Id));
        Assert.Null(await _svc.GetQosConfigByIdAsync(cfg.Id));
    }

    [Fact]
    public async Task QosClass_CrudRoundTrip_ScopedToConfig()
    {
        var iface = await CreateInterfaceAsync();
        var cfg = await _svc.CreateQosConfigAsync(new FwQosConfig
        { InterfaceId = iface.Id, TotalBandwidthMbps = 100, Enabled = true });

        var c = await _svc.CreateQosClassAsync(new FwQosClass
        {
            QosConfigId = cfg.Id,
            Name = "browsing",
            GuaranteedMbps = 10,
            CeilingMbps = 50,
            Priority = 5
        });
        Assert.NotEqual(Guid.Empty, c.Id);

        var classes = await _svc.GetQosClassesAsync(cfg.Id);
        Assert.Single(classes);
        Assert.Equal("browsing", classes[0].Name);

        Assert.True(await _svc.DeleteQosClassAsync(c.Id));
        Assert.Empty(await _svc.GetQosClassesAsync(cfg.Id));
    }

    [Fact]
    public async Task DeleteQosConfig_CascadesQosClasses()
    {
        var iface = await CreateInterfaceAsync();
        var cfg = await _svc.CreateQosConfigAsync(new FwQosConfig
        { InterfaceId = iface.Id, TotalBandwidthMbps = 100 });
        var c = await _svc.CreateQosClassAsync(new FwQosClass
        { QosConfigId = cfg.Id, Name = "x", GuaranteedMbps = 10, CeilingMbps = 50, Priority = 1 });

        await _svc.DeleteQosConfigAsync(cfg.Id);

        // Schema FK is ON DELETE CASCADE — the class should be gone.
        var classes = await _svc.GetQosClassesAsync(cfg.Id);
        Assert.Empty(classes);
    }

    // ── Static routes ──────────────────────────────────────────────────

    [Fact]
    public async Task StaticRoute_CrudRoundTrip()
    {
        var iface = await CreateInterfaceAsync();
        var route = await _svc.CreateStaticRouteAsync(new FwStaticRoute
        {
            InterfaceId = iface.Id,
            Destination = "10.20.0.0/16",
            Gateway = IPAddress.Parse("192.168.1.254"),
            Metric = 100,
            Description = "remote office",
            Enabled = true
        });
        Assert.NotEqual(Guid.Empty, route.Id);

        var fetched = await _svc.GetStaticRouteByIdAsync(route.Id);
        Assert.NotNull(fetched);
        Assert.Equal("10.20.0.0/16", fetched!.Destination);
        Assert.Equal("192.168.1.254", fetched.Gateway?.ToString());

        Assert.True(await _svc.DeleteStaticRouteAsync(route.Id));
        Assert.Null(await _svc.GetStaticRouteByIdAsync(route.Id));
    }

    [Fact]
    public async Task StaticRoutes_FilterByInterface()
    {
        var i1 = await CreateInterfaceAsync("eth0");
        var i2 = await CreateInterfaceAsync("eth1");
        await _svc.CreateStaticRouteAsync(new FwStaticRoute
            { InterfaceId = i1.Id, Destination = "10.1.0.0/16", Gateway = IPAddress.Parse("10.0.0.1") });
        await _svc.CreateStaticRouteAsync(new FwStaticRoute
            { InterfaceId = i2.Id, Destination = "10.2.0.0/16", Gateway = IPAddress.Parse("10.0.0.1") });

        var i1Only = await _svc.GetStaticRoutesAsync(i1.Id);
        var allRoutes = await _svc.GetStaticRoutesAsync(interfaceId: null);

        Assert.Single(i1Only);
        Assert.Equal("10.1.0.0/16", i1Only[0].Destination);
        Assert.Equal(2, allRoutes.Count);
    }

    // ── Audit log ──────────────────────────────────────────────────────

    [Fact]
    public async Task LogAuditAsync_PersistsRow_GetAuditLogsAsyncReturnsIt()
    {
        var id = Guid.NewGuid();
        await _svc.LogAuditAsync(
            tableName: "fw_filter_rules",
            recordId: id,
            action: "INSERT",
            oldValues: null,
            newValues: new { name = "ssh-allow" });

        var logs = await _svc.GetAuditLogsAsync();

        Assert.Contains(logs, l => l.RecordId == id && l.Action == "INSERT" && l.TableName == "fw_filter_rules");
    }

    [Fact]
    public async Task SearchAuditLogsAsync_FiltersByActionAndTime()
    {
        await _svc.LogAuditAsync("fw_test", Guid.NewGuid(), "INSERT", null, null);
        await _svc.LogAuditAsync("fw_test", Guid.NewGuid(), "UPDATE", null, null);
        await _svc.LogAuditAsync("fw_other", Guid.NewGuid(), "DELETE", null, null);

        var inserts = await _svc.SearchAuditLogsAsync(action: "INSERT");
        Assert.Single(inserts);

        var fwTest = await _svc.SearchAuditLogsAsync(tableName: "fw_test");
        Assert.Equal(2, fwTest.Count);
    }
}
