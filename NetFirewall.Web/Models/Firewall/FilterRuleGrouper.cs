using NetFirewall.Models.Firewall;

namespace NetFirewall.Web.Models.Firewall;

/// <summary>
/// Arranges filter rules into the titled groups the table renders, for one of
/// the <see cref="FilterRuleView"/> modes.
///
/// <para>Pure formatting over data the caller already loaded — no IO, no state
/// — so it stays a static utility rather than a DI service, and it is unit
/// tested directly.</para>
///
/// <para>The invariant every mode respects: <b>rows are never reordered inside
/// a group by anything other than priority</b>. Regrouping changes which rules
/// sit next to each other, but within any block the operator still reads them
/// in the order the kernel would. Only <see cref="FilterRuleView.Evaluation"/>
/// keeps the groups themselves meaningful as evaluation units, which is why
/// every other mode is flagged in the UI.</para>
/// </summary>
public static class FilterRuleGrouper
{
    /// <summary>Chain evaluation order, and the policy each one ends on.</summary>
    private static readonly (string Chain, string Policy)[] Chains =
    [
        ("input",   "drop"),
        ("forward", "drop"),
        ("output",  "accept")
    ];

    public static FilterRulesTableViewModel Build(
        IReadOnlyList<FwFilterRule> rules,
        IReadOnlyDictionary<Guid, string> interfaceNames,
        FilterRuleView view,
        string? chainFilter)
    {
        var groups = view switch
        {
            FilterRuleView.Interface => ByInterface(rules, interfaceNames),
            FilterRuleView.Action    => ByAction(rules, interfaceNames),
            FilterRuleView.Service   => ByService(rules, interfaceNames),
            _                        => ByChain(rules, interfaceNames)
        };

        return new FilterRulesTableViewModel
        {
            View = view,
            Groups = groups,
            ChainFilter = chainFilter
        };
    }

    /// <summary>
    /// The default. One block per chain in the order the kernel walks them,
    /// rules by priority, and the only mode that computes shadowing — which is
    /// a statement about position inside a chain and would be misleading
    /// attached to a row in any other arrangement.
    /// </summary>
    private static List<FilterRuleGroupViewModel> ByChain(
        IReadOnlyList<FwFilterRule> rules,
        IReadOnlyDictionary<Guid, string> ifaces)
    {
        var groups = new List<FilterRuleGroupViewModel>();

        foreach (var (chain, policy) in Chains)
        {
            var inChain = rules.Where(r => string.Equals(r.Chain, chain, StringComparison.OrdinalIgnoreCase)).ToList();
            if (inChain.Count == 0) continue;

            var shadowed = FwRuleShadowAnalyzer.FindShadowed(inChain);

            var rows = inChain
                .OrderBy(r => r.Priority)
                .Select(r => Row(r, ifaces, shadowed.GetValueOrDefault(r.Id)))
                .ToList();

            groups.Add(new FilterRuleGroupViewModel
            {
                Title = chain,
                Subtitle = $"policy {policy}",
                Rows = rows
            });
        }

        // Anything with an unrecognised chain value still has to be visible —
        // an invisible rule is worse than an oddly grouped one.
        AppendUnknownChains(rules, ifaces, groups);
        return groups;
    }

    private static List<FilterRuleGroupViewModel> ByInterface(
        IReadOnlyList<FwFilterRule> rules,
        IReadOnlyDictionary<Guid, string> ifaces)
    {
        return rules
            .GroupBy(r => r.InterfaceInId is { } id && ifaces.TryGetValue(id, out var n) ? n : "any interface")
            .OrderBy(g => g.Key == "any interface" ? 1 : 0) // concrete interfaces first
            .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .Select(g => new FilterRuleGroupViewModel
            {
                Title = g.Key,
                Subtitle = "inbound interface",
                Rows = g.OrderBy(r => r.Chain).ThenBy(r => r.Priority)
                        .Select(r => Row(r, ifaces, null)).ToList()
            })
            .ToList();
    }

    private static List<FilterRuleGroupViewModel> ByAction(
        IReadOnlyList<FwFilterRule> rules,
        IReadOnlyDictionary<Guid, string> ifaces)
    {
        string[] order = ["accept", "drop", "reject", "log"];

        return rules
            .GroupBy(r => r.Action?.Trim().ToLowerInvariant() ?? "")
            .OrderBy(g => Array.IndexOf(order, g.Key) is var i && i >= 0 ? i : order.Length)
            .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .Select(g => new FilterRuleGroupViewModel
            {
                Title = g.Key,
                Subtitle = "verdict",
                Rows = g.OrderBy(r => r.Chain).ThenBy(r => r.Priority)
                        .Select(r => Row(r, ifaces, null)).ToList()
            })
            .ToList();
    }

    /// <summary>
    /// By what the rule lets through, not where. Answers "who can reach 22?"
    /// — the question that sends you scrolling in the flat list.
    /// </summary>
    private static List<FilterRuleGroupViewModel> ByService(
        IReadOnlyList<FwFilterRule> rules,
        IReadOnlyDictionary<Guid, string> ifaces)
    {
        return rules
            .GroupBy(ServiceKey)
            .OrderBy(g => g.Key == "any protocol" ? 1 : 0)
            .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .Select(g => new FilterRuleGroupViewModel
            {
                Title = g.Key,
                Subtitle = "protocol and port",
                Rows = g.OrderBy(r => r.Chain).ThenBy(r => r.Priority)
                        .Select(r => Row(r, ifaces, null)).ToList()
            })
            .ToList();
    }

    private static string ServiceKey(FwFilterRule r)
    {
        var proto = string.IsNullOrWhiteSpace(r.Protocol) ? null : r.Protocol.Trim().ToLowerInvariant();
        var ports = r.DestinationPorts is { Length: > 0 } ? string.Join(", ", r.DestinationPorts) : null;

        return (proto, ports) switch
        {
            (null, null) => "any protocol",
            (not null, null) => $"{proto} · any port",
            (null, not null) => $"port {ports}",
            _ => $"{proto} · {ports}"
        };
    }

    private static void AppendUnknownChains(
        IReadOnlyList<FwFilterRule> rules,
        IReadOnlyDictionary<Guid, string> ifaces,
        List<FilterRuleGroupViewModel> groups)
    {
        var known = Chains.Select(c => c.Chain).ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var g in rules.Where(r => !known.Contains(r.Chain ?? ""))
                               .GroupBy(r => r.Chain ?? "(no chain)")
                               .OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase))
        {
            groups.Add(new FilterRuleGroupViewModel
            {
                Title = g.Key,
                Subtitle = "unrecognised chain",
                Rows = g.OrderBy(r => r.Priority).Select(r => Row(r, ifaces, null)).ToList()
            });
        }
    }

    private static FilterRuleRowViewModel Row(
        FwFilterRule r,
        IReadOnlyDictionary<Guid, string> ifaces,
        FwFilterRule? shadowedBy) => new()
    {
        Rule = r,
        InterfaceIn = r.InterfaceInId is { } i && ifaces.TryGetValue(i, out var n1) ? n1 : null,
        InterfaceOut = r.InterfaceOutId is { } o && ifaces.TryGetValue(o, out var n2) ? n2 : null,
        ShadowedBy = shadowedBy
    };
}
