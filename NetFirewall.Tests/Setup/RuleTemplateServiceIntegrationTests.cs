using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.Network;
using NetFirewall.Models.Setup;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;
using NetFirewall.Services.Setup;
using NetFirewall.Services.Settings;
using NetFirewall.Tests.Infra;
using Xunit;

namespace NetFirewall.Tests.Setup;

/// <summary>
/// Real-Postgres coverage for <see cref="RuleTemplateService"/>: it runs against
/// the actual schema + the real FirewallService / NetworkObjectService /
/// PolicyRoutingService, so it proves what the mock-only unit tests can't —
/// that network objects + group members actually persist, that the rules the
/// template writes reference object NAMES which the real resolver can EXPAND to
/// CIDRs, and that idempotency holds at the SQL level (UNIQUE name, tag-scoped
/// delete) rather than in a fake dictionary.
/// </summary>
[Collection("Postgres")]
public sealed class RuleTemplateServiceIntegrationTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private FirewallService _fw = null!;
    private NetworkObjectService _objects = null!;
    private NetworkObjectResolver _resolver = null!;
    private PolicyRoutingService _routing = null!;
    private RuleTemplateService _svc = null!;

    public RuleTemplateServiceIntegrationTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();

        _objects = new NetworkObjectService(_pg.DataSource, NullLogger<NetworkObjectService>.Instance);

        // Real resolver so we can assert the template's object references actually
        // expand. It needs IAppSettingsService for the FQDN cache TTL — stub it.
        var settings = new Mock<IAppSettingsService>();
        settings.Setup(s => s.GetIntAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(300); // fqdn TTL seconds — value irrelevant to these tests
        _resolver = new NetworkObjectResolver(_objects, settings.Object, NullLogger<NetworkObjectResolver>.Instance);

        var serviceResolver = new Mock<INetworkServiceResolver>();
        serviceResolver.Setup(r => r.ResolveAsync(It.IsAny<IEnumerable<string>>(), It.IsAny<CancellationToken>()))
            .Returns<IEnumerable<string>, CancellationToken>((i, _) => Task.FromResult<IReadOnlyList<string>>(i.ToList()));

        _fw = new FirewallService(_pg.DataSource, _resolver, serviceResolver.Object,
            NullLogger<FirewallService>.Instance);
        _routing = new PolicyRoutingService(_pg.DataSource, NullLogger<PolicyRoutingService>.Instance);
        _svc = new RuleTemplateService(_fw, _objects, _routing, NullLogger<RuleTemplateService>.Instance);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<FwInterface> Iface(string name, string type, string ip) =>
        await _fw.CreateInterfaceAsync(new FwInterface
        {
            Name = name, Type = type, AddressingMode = "static", Enabled = true, AutoStart = true,
            IpAddress = IPAddress.Parse(ip), SubnetMask = IPAddress.Parse("255.255.255.0"),
        });

    // ── network objects truly persist with members ──────────────────────

    [Fact]
    public async Task Gateway_persists_network_objects_with_members()
    {
        await Iface("wan0", "WAN", "203.0.113.2");
        await Iface("lan0", "LAN", "192.168.10.1");

        await _svc.ApplyTemplateAsync(new RuleTemplateSelection { Base = RuleTemplateBases.Gateway });

        var lanGroup = await _objects.GetByNameAsync(RuleTemplateObjects.LanNetworks, includeMembers: true);
        Assert.NotNull(lanGroup);
        Assert.Equal(NetworkObjectTypes.Group, lanGroup!.Type);
        Assert.NotNull(lanGroup.Members);
        // The LAN's /24 must be a member (derived from the interface).
        Assert.Contains(lanGroup.Members!, m => m.Value == "192.168.10.0/24");

        var bogons = await _objects.GetByNameAsync(RuleTemplateObjects.Bogons, includeMembers: true);
        Assert.NotNull(bogons);
        Assert.Contains(bogons!.Members!, m => m.Value == "10.0.0.0/8");
        Assert.Contains(bogons.Members!, m => m.Value == "224.0.0.0/4");
    }

    // ── the rules reference object names that the REAL resolver expands ──

    [Fact]
    public async Task Rule_object_references_expand_to_cidrs_via_resolver()
    {
        await Iface("wan0", "WAN", "203.0.113.2");
        await Iface("lan0", "LAN", "192.168.20.1");

        await _svc.ApplyTemplateAsync(new RuleTemplateSelection
        {
            Base = RuleTemplateBases.Gateway, AllowManagement = true
        });

        // Find the LAN-outbound forward rule (it references LAN_NETWORKS by name).
        var forwards = await _fw.GetFilterRulesAsync("forward");
        var lanOut = forwards.First(r => r.SourceAddresses is not null &&
                                          r.SourceAddresses.Contains(RuleTemplateObjects.LanNetworks));

        // The real resolver must expand the object name to the LAN CIDR.
        var expanded = await _resolver.ResolveAsync(lanOut.SourceAddresses!);
        Assert.Contains("192.168.20.0/24", expanded);
        // And it must NOT leave the literal object name unexpanded.
        Assert.DoesNotContain(RuleTemplateObjects.LanNetworks, expanded);
    }

    // ── idempotency at the SQL level (UNIQUE name + tag-scoped delete) ──

    [Fact]
    public async Task Reapply_is_idempotent_against_real_schema()
    {
        await Iface("wan0", "WAN", "203.0.113.2");
        await Iface("lan0", "LAN", "192.168.30.1");
        var sel = new RuleTemplateSelection { Base = RuleTemplateBases.Gateway };

        await _svc.ApplyTemplateAsync(sel);
        var filtersAfter1 = (await _fw.GetFilterRulesAsync(null)).Count;
        var natsAfter1 = (await _fw.GetNatRulesAsync()).Count;
        var objsAfter1 = (await _objects.GetAllAsync()).Count;

        await _svc.ApplyTemplateAsync(sel);
        var filtersAfter2 = (await _fw.GetFilterRulesAsync(null)).Count;
        var natsAfter2 = (await _fw.GetNatRulesAsync()).Count;
        var objsAfter2 = (await _objects.GetAllAsync()).Count;

        // No duplicate rules and no duplicate objects (UNIQUE name would have thrown).
        Assert.Equal(filtersAfter1, filtersAfter2);
        Assert.Equal(natsAfter1, natsAfter2);
        Assert.Equal(objsAfter1, objsAfter2);
    }

    // ── clear leaves the operator's own rules ───────────────────────────

    [Fact]
    public async Task Clear_removes_only_template_rules_in_real_db()
    {
        var lan = await Iface("lan0", "LAN", "192.168.40.1");
        await Iface("wan0", "WAN", "203.0.113.2");

        // Operator's own rule (no [tpl] tag).
        await _fw.CreateFilterRuleAsync(new FwFilterRule
        {
            Chain = "input", Action = "accept", Protocol = "tcp",
            DestinationPorts = ["8443"], Description = "My custom admin port", Enabled = true,
        });

        await _svc.ApplyTemplateAsync(new RuleTemplateSelection { Base = RuleTemplateBases.Gateway });
        var removed = await _svc.ClearTemplateRulesAsync();

        Assert.True(removed > 0);
        var remaining = await _fw.GetFilterRulesAsync(null);
        Assert.Contains(remaining, r => r.Description == "My custom admin port");
        Assert.DoesNotContain(remaining, r => RuleTemplateTags.IsTemplate(r.Description));
        Assert.Empty(await _fw.GetNatRulesAsync());
    }

    // ── multi-WAN writes real route tables + policy rules ───────────────

    [Fact]
    public async Task MultiWan_persists_route_tables_and_policy_rules()
    {
        await Iface("wan0", "WAN", "203.0.113.2");
        await Iface("wan1", "WAN", "198.51.100.2");
        await Iface("lan0", "LAN", "192.168.50.1");

        var result = await _svc.ApplyTemplateAsync(new RuleTemplateSelection
        {
            Base = RuleTemplateBases.Gateway, EnableMultiWan = true
        });

        Assert.True(result.PolicyRoutingRows >= 4);
        var tables = await _routing.GetRouteTablesAsync();
        var policies = await _routing.GetPolicyRulesAsync();
        Assert.True(tables.Count >= 2, "two WANs → two route tables");
        Assert.True(policies.Count >= 2, "two WANs → two policy rules");
    }

    // ── router base persists no NAT rows ────────────────────────────────

    [Fact]
    public async Task Router_base_writes_no_nat_rows()
    {
        await Iface("wan0", "WAN", "203.0.113.2");
        await Iface("lan0", "LAN", "192.168.60.1");

        await _svc.ApplyTemplateAsync(new RuleTemplateSelection
        {
            Base = RuleTemplateBases.Router, EnableNat = true
        });

        Assert.Empty(await _fw.GetNatRulesAsync());
        // But it still forwards (router routes between segments).
        Assert.NotEmpty(await _fw.GetFilterRulesAsync("forward"));
    }
}
