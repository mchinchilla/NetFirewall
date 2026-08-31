using System.Text.RegularExpressions;
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
        string? chainFilter,
        IReadOnlyDictionary<Guid, string>? scheduleNames = null)
    {
        var groups = view switch
        {
            FilterRuleView.Interface => ByInterface(rules, interfaceNames, scheduleNames),
            FilterRuleView.Action    => ByAction(rules, interfaceNames, scheduleNames),
            FilterRuleView.Service   => ByService(rules, interfaceNames, scheduleNames),
            _                        => ByChain(rules, interfaceNames, scheduleNames)
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
        IReadOnlyDictionary<Guid, string> ifaces,
        IReadOnlyDictionary<Guid, string>? schedules)
    {
        var groups = new List<FilterRuleGroupViewModel>();

        foreach (var (chain, policy) in Chains)
        {
            var inChain = rules.Where(r => string.Equals(r.Chain, chain, StringComparison.OrdinalIgnoreCase)).ToList();
            if (inChain.Count == 0) continue;

            var shadowed = FwRuleShadowAnalyzer.FindShadowed(inChain);

            var rows = inChain
                .OrderBy(r => r.Priority)
                .Select(r => Row(r, ifaces, shadowed.GetValueOrDefault(r.Id), schedules))
                .ToList();

            groups.Add(new FilterRuleGroupViewModel
            {
                Title = chain,
                Subtitle = $"policy {policy}",
                Policy = policy,
                Summary = string.Equals(policy, "drop", StringComparison.OrdinalIgnoreCase)
                    ? "First match wins. Packets that miss every rule are dropped."
                    : "First match wins. Packets that miss every rule are allowed out.",
                Clusters = Cluster(rows, mergeInterfaceVariants: true)
            });
        }

        // Anything with an unrecognised chain value still has to be visible —
        // an invisible rule is worse than an oddly grouped one.
        AppendUnknownChains(rules, ifaces, schedules, groups);
        return groups;
    }

    private static List<FilterRuleGroupViewModel> ByInterface(
        IReadOnlyList<FwFilterRule> rules,
        IReadOnlyDictionary<Guid, string> ifaces,
        IReadOnlyDictionary<Guid, string>? schedules)
    {
        return rules
            .GroupBy(r => r.InterfaceInId is { } id && ifaces.TryGetValue(id, out var n) ? n : "any interface")
            .OrderBy(g => g.Key == "any interface" ? 1 : 0) // concrete interfaces first
            .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .Select(g => new FilterRuleGroupViewModel
            {
                Title = g.Key,
                Subtitle = "inbound interface",
                Clusters = Cluster(
                    g.OrderBy(r => r.Chain).ThenBy(r => r.Priority)
                     .Select(r => Row(r, ifaces, null, schedules)).ToList(),
                    mergeInterfaceVariants: false)
            })
            .ToList();
    }

    private static List<FilterRuleGroupViewModel> ByAction(
        IReadOnlyList<FwFilterRule> rules,
        IReadOnlyDictionary<Guid, string> ifaces,
        IReadOnlyDictionary<Guid, string>? schedules)
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
                Clusters = Cluster(
                    g.OrderBy(r => r.Chain).ThenBy(r => r.Priority)
                     .Select(r => Row(r, ifaces, null, schedules)).ToList(),
                    mergeInterfaceVariants: false)
            })
            .ToList();
    }

    /// <summary>
    /// By what the rule lets through, not where. Answers "who can reach 22?"
    /// — the question that sends you scrolling in the flat list.
    /// </summary>
    private static List<FilterRuleGroupViewModel> ByService(
        IReadOnlyList<FwFilterRule> rules,
        IReadOnlyDictionary<Guid, string> ifaces,
        IReadOnlyDictionary<Guid, string>? schedules)
    {
        return rules
            .GroupBy(ServiceKey)
            .OrderBy(g => g.Key == "any protocol" ? 1 : 0)
            .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .Select(g => new FilterRuleGroupViewModel
            {
                Title = g.Key,
                Subtitle = "protocol and port",
                Clusters = Cluster(
                    g.OrderBy(r => r.Chain).ThenBy(r => r.Priority)
                     .Select(r => Row(r, ifaces, null, schedules)).ToList(),
                    mergeInterfaceVariants: false)
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
        IReadOnlyDictionary<Guid, string>? schedules,
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
                Clusters = Cluster(
                    g.OrderBy(r => r.Priority).Select(r => Row(r, ifaces, null, schedules)).ToList(),
                    mergeInterfaceVariants: true)
            });
        }
    }

    /// <summary>
    /// Walks already-ordered rows and, in evaluation view, folds consecutive
    /// interface variants into one step. Never reorders. A variant is the
    /// same decision (action, match, schedule, enabled) on a different NIC.
    /// </summary>
    internal static List<FilterRuleClusterViewModel> Cluster(
        List<FilterRuleRowViewModel> rows,
        bool mergeInterfaceVariants)
    {
        var clusters = new List<FilterRuleClusterViewModel>();
        FilterRuleRowViewModel? prevLast = null;

        for (var i = 0; i < rows.Count; )
        {
            var j = i + 1;
            if (mergeInterfaceVariants)
            {
                while (j < rows.Count && IsInterfaceVariant(rows[i].Rule, rows[j].Rule))
                    j++;
            }

            var members = rows.GetRange(i, j - i);
            var firstPri = members[0].Rule.Priority;
            var gap = prevLast is null ? 0 : firstPri - prevLast.Rule.Priority;
            string? band = null;
            if (prevLast is not null && prevLast.Rule.Priority < 900 && firstPri >= 900)
                band = "Default policy";

            clusters.Add(new FilterRuleClusterViewModel
            {
                Members = members,
                Title = ClusterTitle(members),
                ShowGap = gap >= 10,
                BandLabel = band
            });

            prevLast = members[^1];
            i = j;
        }

        return clusters;
    }

    /// <summary>
    /// Same verdict and match, different in and/or out interface. Used to
    /// collapse the "SSH via ens192" / "SSH via ens224" twins into one step
    /// without lying about them being separate nft rules.
    /// </summary>
    internal static bool IsInterfaceVariant(FwFilterRule a, FwFilterRule b)
    {
        if (a.Priority != b.Priority) return false;
        if (a.Enabled != b.Enabled) return false;
        if (!Eq(a.Action, b.Action)) return false;
        if (!Eq(a.Protocol, b.Protocol)) return false;
        if (!Eq(a.RateLimit, b.RateLimit)) return false;
        if (a.ScheduleId != b.ScheduleId) return false;
        if (!SetEq(a.DestinationPorts, b.DestinationPorts)) return false;
        if (!SetEq(a.ConnectionState, b.ConnectionState)) return false;
        if (!SetEq(a.SourceAddresses, b.SourceAddresses)) return false;
        if (!SetEq(a.DestinationAddresses, b.DestinationAddresses)) return false;

        var sameIn = a.InterfaceInId == b.InterfaceInId;
        var sameOut = a.InterfaceOutId == b.InterfaceOutId;
        return !sameIn || !sameOut;
    }

    private static string ClusterTitle(IReadOnlyList<FilterRuleRowViewModel> members)
    {
        var stripped = members
            .Select(StripIfaceFromDescription)
            .Where(s => s.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (stripped.Count == 1) return stripped[0];

        var raw = members[0].Rule.Description;
        return string.IsNullOrWhiteSpace(raw) ? "(no description)" : raw;
    }

    private static string StripIfaceFromDescription(FilterRuleRowViewModel m)
    {
        var d = m.Rule.Description ?? "";
        foreach (var n in new[] { m.InterfaceIn, m.InterfaceOut }.OfType<string>())
        {
            d = Regex.Replace(d, $@"\s+via\s+{Regex.Escape(n)}\b", "", RegexOptions.IgnoreCase);
            d = Regex.Replace(d, $@"\s*\({Regex.Escape(n)}\)", "", RegexOptions.IgnoreCase);
        }
        d = Regex.Replace(d, @"\s+", " ").Trim();
        return d.TrimEnd('—', '-', ' ').Trim();
    }

    private static bool Eq(string? a, string? b) =>
        string.Equals(a?.Trim(), b?.Trim(), StringComparison.OrdinalIgnoreCase);

    private static bool SetEq(string[]? a, string[]? b)
    {
        var left = (a ?? []).Select(s => s.Trim()).OrderBy(s => s, StringComparer.OrdinalIgnoreCase);
        var right = (b ?? []).Select(s => s.Trim()).OrderBy(s => s, StringComparer.OrdinalIgnoreCase);
        return left.SequenceEqual(right, StringComparer.OrdinalIgnoreCase);
    }

    private static FilterRuleRowViewModel Row(
        FwFilterRule r,
        IReadOnlyDictionary<Guid, string> ifaces,
        FwFilterRule? shadowedBy,
        IReadOnlyDictionary<Guid, string>? schedules) => new()
    {
        Rule = r,
        InterfaceIn = r.InterfaceInId is { } i && ifaces.TryGetValue(i, out var n1) ? n1 : null,
        InterfaceOut = r.InterfaceOutId is { } o && ifaces.TryGetValue(o, out var n2) ? n2 : null,
        ShadowedBy = shadowedBy,
        ScheduleName = r.ScheduleId is { } sid && schedules is not null && schedules.TryGetValue(sid, out var sn)
            ? sn : null
    };
}
