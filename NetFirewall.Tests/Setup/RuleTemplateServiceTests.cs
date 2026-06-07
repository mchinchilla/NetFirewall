using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.Network;
using NetFirewall.Models.Setup;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;
using NetFirewall.Services.Setup;
using Xunit;

namespace NetFirewall.Tests.Setup;

/// <summary>
/// Unit tests for the rule-template generator. All collaborators are mocked —
/// we assert on WHAT it generates (network objects by name, tagged rules,
/// idempotent clear, multi-WAN skip) rather than DB state.
/// </summary>
public sealed class RuleTemplateServiceTests
{
    private readonly Mock<IFirewallService> _fw = new();
    private readonly Mock<INetworkObjectService> _objs = new();
    private readonly Mock<IPolicyRoutingService> _routing = new();
    private readonly RuleTemplateService _svc;

    private readonly List<FwFilterRule> _filterRules = [];
    private readonly List<FwNatRule> _natRules = [];
    private readonly List<FwPortForward> _portForwards = [];
    private readonly Dictionary<string, NetworkObject> _objectsByName = new();

    public RuleTemplateServiceTests()
    {
        // Capture created rules into in-memory lists; echo back GetX queries.
        _fw.Setup(f => f.CreateFilterRuleAsync(It.IsAny<FwFilterRule>(), It.IsAny<CancellationToken>()))
           .ReturnsAsync((FwFilterRule r, CancellationToken _) => { r.Id = Guid.NewGuid(); _filterRules.Add(r); return r; });
        _fw.Setup(f => f.CreateNatRuleAsync(It.IsAny<FwNatRule>(), It.IsAny<CancellationToken>()))
           .ReturnsAsync((FwNatRule r, CancellationToken _) => { r.Id = Guid.NewGuid(); _natRules.Add(r); return r; });
        _fw.Setup(f => f.CreatePortForwardAsync(It.IsAny<FwPortForward>(), It.IsAny<CancellationToken>()))
           .ReturnsAsync((FwPortForward r, CancellationToken _) => { r.Id = Guid.NewGuid(); _portForwards.Add(r); return r; });

        _fw.Setup(f => f.GetFilterRulesAsync(It.IsAny<string?>(), It.IsAny<CancellationToken>()))
           .ReturnsAsync(() => _filterRules.ToList());
        _fw.Setup(f => f.GetNatRulesAsync(It.IsAny<CancellationToken>()))
           .ReturnsAsync(() => _natRules.ToList());
        _fw.Setup(f => f.GetPortForwardsAsync(It.IsAny<CancellationToken>()))
           .ReturnsAsync(() => _portForwards.ToList());

        _fw.Setup(f => f.DeleteFilterRuleAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
           .ReturnsAsync((Guid id, CancellationToken _) => _filterRules.RemoveAll(r => r.Id == id) > 0);
        _fw.Setup(f => f.DeleteNatRuleAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
           .ReturnsAsync((Guid id, CancellationToken _) => _natRules.RemoveAll(r => r.Id == id) > 0);
        _fw.Setup(f => f.DeletePortForwardAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
           .ReturnsAsync((Guid id, CancellationToken _) => _portForwards.RemoveAll(r => r.Id == id) > 0);

        // Network object catalog: create-by-name, get-by-name.
        _objs.Setup(o => o.GetByNameAsync(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
             .ReturnsAsync((string n, bool _, CancellationToken __) => _objectsByName.GetValueOrDefault(n));
        _objs.Setup(o => o.CreateAsync(It.IsAny<NetworkObject>(), It.IsAny<CancellationToken>()))
             .ReturnsAsync((NetworkObject o, CancellationToken _) => { o.Id = Guid.NewGuid(); _objectsByName[o.Name] = o; return o; });
        _objs.Setup(o => o.SetGroupMembersAsync(It.IsAny<Guid>(), It.IsAny<IEnumerable<Guid>>(), It.IsAny<CancellationToken>()))
             .Returns(Task.CompletedTask);

        _routing.Setup(r => r.EnsureRouteTableAsync(It.IsAny<int>(), It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync((int id, string name, string? d, CancellationToken _) => new FwRouteTable { TableId = id, Name = name });
        _routing.Setup(r => r.EnsurePolicyRuleAsync(It.IsAny<long>(), It.IsAny<string>(), It.IsAny<int?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync((long m, string t, int? p, string? d, CancellationToken _) => new FwPolicyRule { Fwmark = m, TableName = t });

        _svc = new RuleTemplateService(_fw.Object, _objs.Object, _routing.Object, NullLogger<RuleTemplateService>.Instance);
    }

    private void SetInterfaces(params FwInterface[] ifaces) =>
        _fw.Setup(f => f.GetInterfacesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(ifaces.ToList());

    private static FwInterface Wan(string name) => new()
        { Id = Guid.NewGuid(), Name = name, Type = "WAN", Enabled = true,
          IpAddress = IPAddress.Parse("203.0.113.2"), SubnetMask = IPAddress.Parse("255.255.255.0") };

    private static FwInterface Lan(string name, string ip = "192.168.1.1") => new()
        { Id = Guid.NewGuid(), Name = name, Type = "LAN", Enabled = true,
          IpAddress = IPAddress.Parse(ip), SubnetMask = IPAddress.Parse("255.255.255.0") };

    [Fact]
    public async Task Gateway_template_creates_nat_and_tagged_rules()
    {
        SetInterfaces(Wan("wan0"), Lan("lan0"));

        var result = await _svc.ApplyTemplateAsync(new RuleTemplateSelection { Base = RuleTemplateBases.Gateway });

        Assert.Equal(RuleTemplateBases.Gateway, result.Base);
        Assert.True(result.NatRules >= 1, "gateway should masquerade LAN via WAN");
        Assert.True(result.FilterRules > 0);
        // Every generated rule must carry the template tag (idempotency contract).
        Assert.All(_filterRules, r => Assert.True(RuleTemplateTags.IsTemplate(r.Description)));
        Assert.All(_natRules, r => Assert.True(RuleTemplateTags.IsTemplate(r.Description)));
    }

    [Fact]
    public async Task Rules_reference_network_objects_by_name_not_raw_cidrs()
    {
        SetInterfaces(Wan("wan0"), Lan("lan0"));

        await _svc.ApplyTemplateAsync(new RuleTemplateSelection
        {
            Base = RuleTemplateBases.Gateway, AllowManagement = true, AllowDns = true
        });

        // The LAN-outbound forward rule must use the LAN_NETWORKS object name.
        Assert.Contains(_filterRules, r =>
            r.Chain == "forward" && r.SourceAddresses is not null &&
            r.SourceAddresses.Contains(RuleTemplateObjects.LanNetworks));
        // Management rules use MGMT_SOURCES, not a literal CIDR.
        Assert.Contains(_filterRules, r =>
            r.SourceAddresses is not null && r.SourceAddresses.Contains(RuleTemplateObjects.MgmtSources));
        // NAT source_network is a Postgres `cidr` column, so it carries a literal
        // LAN CIDR (NOT the object name) — one rule per LAN network.
        Assert.Contains(_natRules, r => r.SourceNetwork == "192.168.1.0/24");
        Assert.DoesNotContain(_natRules, r => r.SourceNetwork == RuleTemplateObjects.LanNetworks);
        // The core objects were created.
        Assert.Contains(RuleTemplateObjects.LanNetworks, _objectsByName.Keys);
        Assert.Contains(RuleTemplateObjects.Bogons, _objectsByName.Keys);
        Assert.Contains(RuleTemplateObjects.MgmtSources, _objectsByName.Keys);
    }

    [Fact]
    public async Task Router_base_skips_nat_even_when_requested()
    {
        SetInterfaces(Wan("wan0"), Lan("lan0"));

        var result = await _svc.ApplyTemplateAsync(new RuleTemplateSelection
        {
            Base = RuleTemplateBases.Router, EnableNat = true
        });

        Assert.Equal(0, result.NatRules);
        Assert.Contains(result.Notes, n => n.Contains("router", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Bastion_base_creates_no_forward_rules()
    {
        SetInterfaces(Wan("wan0"), Lan("lan0"));

        await _svc.ApplyTemplateAsync(new RuleTemplateSelection { Base = RuleTemplateBases.Bastion });

        Assert.DoesNotContain(_filterRules, r => r.Chain == "forward");
    }

    [Fact]
    public async Task MultiWan_skipped_with_single_wan()
    {
        SetInterfaces(Wan("wan0"), Lan("lan0"));

        var result = await _svc.ApplyTemplateAsync(new RuleTemplateSelection
        {
            Base = RuleTemplateBases.Gateway, EnableMultiWan = true
        });

        Assert.Equal(0, result.PolicyRoutingRows);
        Assert.Contains(result.Notes, n => n.Contains("Multi-WAN", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task MultiWan_creates_policy_routing_with_two_wans()
    {
        SetInterfaces(Wan("wan0"), Wan("wan1"), Lan("lan0"));

        var result = await _svc.ApplyTemplateAsync(new RuleTemplateSelection
        {
            Base = RuleTemplateBases.Gateway, EnableMultiWan = true
        });

        Assert.True(result.PolicyRoutingRows >= 4, "two WANs → 2 route tables + 2 policy rules");
        _routing.Verify(r => r.EnsureRouteTableAsync(It.IsAny<int>(), It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Exactly(2));
    }

    [Fact]
    public async Task Reapplying_is_idempotent_no_duplicate_rules()
    {
        SetInterfaces(Wan("wan0"), Lan("lan0"));
        var sel = new RuleTemplateSelection { Base = RuleTemplateBases.Gateway };

        var first = await _svc.ApplyTemplateAsync(sel);
        var firstCount = _filterRules.Count + _natRules.Count;
        var second = await _svc.ApplyTemplateAsync(sel);
        var secondCount = _filterRules.Count + _natRules.Count;

        Assert.Equal(firstCount, secondCount); // re-apply replaced, didn't duplicate
        Assert.Equal(first.TotalRules, second.TotalRules);
    }

    [Fact]
    public async Task ClearTemplate_removes_only_tagged_rules()
    {
        SetInterfaces(Wan("wan0"), Lan("lan0"));
        // A hand-made rule the operator added (no template tag).
        _filterRules.Add(new FwFilterRule { Id = Guid.NewGuid(), Chain = "input", Action = "accept", Description = "My SSH from office" });

        await _svc.ApplyTemplateAsync(new RuleTemplateSelection { Base = RuleTemplateBases.Gateway });
        var removed = await _svc.ClearTemplateRulesAsync();

        Assert.True(removed > 0);
        // The hand-made rule survives; all template rules are gone.
        Assert.Contains(_filterRules, r => r.Description == "My SSH from office");
        Assert.DoesNotContain(_filterRules, r => RuleTemplateTags.IsTemplate(r.Description));
        Assert.Empty(_natRules);
    }

    [Fact]
    public async Task Invalid_selection_throws()
    {
        SetInterfaces(Lan("lan0"));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            _svc.ApplyTemplateAsync(new RuleTemplateSelection { Base = "bogus" }));
    }
}
