using NetFirewall.Models.Firewall;
using NetFirewall.Web.Models.Firewall;
using Xunit;

namespace NetFirewall.Tests.Firewall;

/// <summary>
/// Coverage for <see cref="FilterRuleGrouper"/>, which arranges the rule list
/// for the UI. The property worth defending: <b>rules never get reordered
/// inside a group by anything but priority</b>, and only the evaluation view
/// claims to reflect how the kernel runs the ruleset.
/// </summary>
public class FilterRuleGrouperTests
{
    private static readonly Guid Wan = Guid.NewGuid();
    private static readonly Guid Lan = Guid.NewGuid();

    private static readonly Dictionary<Guid, string> Ifaces = new()
    {
        [Wan] = "ens224",
        [Lan] = "ens256"
    };

    private static FwFilterRule Rule(
        string chain, int priority, string action = "accept",
        string? protocol = null, string[]? ports = null, Guid? ifIn = null,
        bool enabled = true, string? rate = null) => new()
    {
        Id = Guid.NewGuid(),
        Chain = chain,
        Priority = priority,
        Action = action,
        Protocol = protocol,
        DestinationPorts = ports,
        InterfaceInId = ifIn,
        Enabled = enabled,
        RateLimit = rate
    };

    [Fact]
    public void EvaluationView_KeepsChainOrderAndPriorityOrder()
    {
        var rules = new[]
        {
            Rule("forward", 20),
            Rule("input", 100),
            Rule("input", 1, "drop"),
            Rule("output", 10)
        };

        var vm = FilterRuleGrouper.Build(rules, Ifaces, FilterRuleView.Evaluation, null);

        Assert.Equal(["input", "forward", "output"], vm.Groups.Select(g => g.Title));
        Assert.Equal([1, 100], vm.Groups[0].Rows.Select(r => r.Rule.Priority));
        Assert.True(vm.PreservesEvaluationOrder);
    }

    [Fact]
    public void EvaluationView_FlagsUnreachableRules()
    {
        var blanket = Rule("input", 60, "accept", protocol: "tcp");
        var hidden = Rule("input", 70, "drop", protocol: "tcp", ports: ["445"]);

        var vm = FilterRuleGrouper.Build([blanket, hidden], Ifaces, FilterRuleView.Evaluation, null);
        var rows = vm.Groups.Single().Rows;

        Assert.Null(rows[0].ShadowedBy);
        Assert.Equal(blanket.Id, rows[1].ShadowedBy!.Id);
        Assert.Equal(1, vm.TotalShadowed);
    }

    [Fact]
    public void RegroupedViews_DoNotClaimShadowing()
    {
        // Shadowing is a statement about position inside a chain. Repeating it
        // in a regrouped list would attach the warning to rows whose visible
        // neighbours are no longer the ones hiding them.
        var blanket = Rule("input", 60, "accept", protocol: "tcp");
        var hidden = Rule("input", 70, "drop", protocol: "tcp", ports: ["445"]);

        foreach (var view in new[] { FilterRuleView.Interface, FilterRuleView.Action, FilterRuleView.Service })
        {
            var vm = FilterRuleGrouper.Build([blanket, hidden], Ifaces, view, null);

            Assert.False(vm.PreservesEvaluationOrder);
            Assert.Equal(0, vm.TotalShadowed);
            Assert.All(vm.Groups.SelectMany(g => g.Rows), r => Assert.Null(r.ShadowedBy));
        }
    }

    [Fact]
    public void InterfaceView_PutsConcreteInterfacesBeforeAny()
    {
        var rules = new[]
        {
            Rule("input", 10),                 // any
            Rule("input", 20, ifIn: Wan),
            Rule("input", 30, ifIn: Lan)
        };

        var vm = FilterRuleGrouper.Build(rules, Ifaces, FilterRuleView.Interface, null);

        Assert.Equal(["ens224", "ens256", "any interface"], vm.Groups.Select(g => g.Title));
    }

    [Fact]
    public void ServiceView_GroupsByProtocolAndPort()
    {
        var rules = new[]
        {
            Rule("input", 10, protocol: "tcp", ports: ["22"]),
            Rule("forward", 20, protocol: "tcp", ports: ["22"]),
            Rule("input", 30, protocol: "udp", ports: ["53"]),
            Rule("input", 40)
        };

        var vm = FilterRuleGrouper.Build(rules, Ifaces, FilterRuleView.Service, null);
        var titles = vm.Groups.Select(g => g.Title).ToList();

        Assert.Contains("tcp · 22", titles);
        Assert.Contains("udp · 53", titles);
        Assert.Equal("any protocol", titles[^1]);   // the catch-all sinks to the bottom
        Assert.Equal(2, vm.Groups.Single(g => g.Title == "tcp · 22").Rows.Count);
    }

    [Fact]
    public void ActionView_OrdersAcceptBeforeDrop()
    {
        var rules = new[]
        {
            Rule("input", 10, "drop"),
            Rule("input", 20, "accept"),
            Rule("input", 30, "log")
        };

        var vm = FilterRuleGrouper.Build(rules, Ifaces, FilterRuleView.Action, null);

        Assert.Equal(["accept", "drop", "log"], vm.Groups.Select(g => g.Title));
    }

    [Fact]
    public void DisabledRules_AreListedButNotCounted()
    {
        var rules = new[]
        {
            Rule("input", 10),
            Rule("input", 20, enabled: false)
        };

        var vm = FilterRuleGrouper.Build(rules, Ifaces, FilterRuleView.Evaluation, null);
        var group = vm.Groups.Single();

        Assert.Equal(2, group.Rows.Count);      // still visible — you must be able to re-enable it
        Assert.Equal(1, group.EnabledCount);
    }

    [Fact]
    public void UnknownChain_IsStillShown()
    {
        // An invisible rule is worse than an oddly grouped one.
        var vm = FilterRuleGrouper.Build([Rule("prerouting", 10)], Ifaces, FilterRuleView.Evaluation, null);

        Assert.Equal("prerouting", vm.Groups.Single().Title);
        Assert.Equal("unrecognised chain", vm.Groups.Single().Subtitle);
    }

    [Fact]
    public void Chips_SummariseLongAddressListsAndKeepNftOrder()
    {
        var rule = Rule("input", 10, protocol: "tcp", ports: ["22"]);
        rule.SourceAddresses = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"];
        rule.RateLimit = "10/second";

        var row = FilterRuleGrouper
            .Build([rule], Ifaces, FilterRuleView.Evaluation, null)
            .Groups.Single().Rows.Single();

        Assert.Equal(["proto", "port", "src", "rate"], row.Chips.Select(c => c.Label));
        Assert.Equal("4 addresses", row.Chips.Single(c => c.Label == "src").Value);
    }

    [Fact]
    public void RuleMatchingEverything_HasNoChips()
    {
        var row = FilterRuleGrouper
            .Build([Rule("input", 1000, "drop")], Ifaces, FilterRuleView.Evaluation, null)
            .Groups.Single().Rows.Single();

        Assert.Empty(row.Chips);
    }
}
