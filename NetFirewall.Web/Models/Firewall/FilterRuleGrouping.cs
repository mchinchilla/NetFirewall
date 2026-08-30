using NetFirewall.Models.Firewall;

namespace NetFirewall.Web.Models.Firewall;

/// <summary>
/// How the filter-rule list is arranged. Only <see cref="Evaluation"/> shows
/// rules in the order the kernel actually applies them; the others regroup for
/// answering a question ("what do I expose on ens224?") and must say so, or an
/// operator will read a reordered list as if it were the ruleset.
/// </summary>
public enum FilterRuleView
{
    /// <summary>By chain, then priority — the real evaluation order.</summary>
    Evaluation,

    /// <summary>By inbound interface. Answers "what reaches me here?".</summary>
    Interface,

    /// <summary>By verdict: accept / drop / reject / log.</summary>
    Action,

    /// <summary>By protocol and port. Answers "who can reach 22?".</summary>
    Service
}

/// <summary>One rendered row: the rule plus everything the view needs resolved.</summary>
public sealed class FilterRuleRowViewModel
{
    public required FwFilterRule Rule { get; init; }
    public string? InterfaceIn { get; init; }
    public string? InterfaceOut { get; init; }

    /// <summary>
    /// The earlier rule that makes this one unreachable, when there is one.
    /// Only ever set in <see cref="FilterRuleView.Evaluation"/>: shadowing is a
    /// statement about position within a chain, and repeating it in a regrouped
    /// list would attach it to rows whose neighbours are no longer the ones
    /// that hide them.
    /// </summary>
    public FwFilterRule? ShadowedBy { get; init; }

    /// <summary>
    /// Match conditions as short labelled chips, in the order nft evaluates
    /// them. Empty means the rule matches everything.
    /// </summary>
    public IReadOnlyList<(string Label, string Value)> Chips
    {
        get
        {
            var chips = new List<(string, string)>();
            var r = Rule;

            if (!string.IsNullOrWhiteSpace(r.Protocol)) chips.Add(("proto", r.Protocol));
            if (r.DestinationPorts is { Length: > 0 }) chips.Add(("port", string.Join(", ", r.DestinationPorts)));
            if (r.ConnectionState is { Length: > 0 }) chips.Add(("state", string.Join(", ", r.ConnectionState)));
            if (r.SourceAddresses is { Length: > 0 }) chips.Add(("src", Summarise(r.SourceAddresses)));
            if (r.DestinationAddresses is { Length: > 0 }) chips.Add(("dst", Summarise(r.DestinationAddresses)));
            if (!string.IsNullOrWhiteSpace(r.RateLimit)) chips.Add(("rate", r.RateLimit));

            return chips;
        }
    }

    /// <summary>
    /// Long address lists become "5 addresses" — the anti-spoof rules carry
    /// seven bogon prefixes each and would otherwise swamp the row. The full
    /// list stays available as the cell's title attribute.
    /// </summary>
    private static string Summarise(string[] values) =>
        values.Length > 3 ? $"{values.Length} addresses" : string.Join(", ", values);
}

/// <summary>One titled block of rows.</summary>
public sealed class FilterRuleGroupViewModel
{
    public required string Title { get; init; }
    public string? Subtitle { get; init; }
    public required IReadOnlyList<FilterRuleRowViewModel> Rows { get; init; }

    public int EnabledCount => Rows.Count(r => r.Rule.Enabled);
    public int ShadowedCount => Rows.Count(r => r.ShadowedBy is not null);
}

/// <summary>The whole table.</summary>
public sealed class FilterRulesTableViewModel
{
    public required FilterRuleView View { get; init; }
    public required IReadOnlyList<FilterRuleGroupViewModel> Groups { get; init; }
    public string? ChainFilter { get; init; }

    /// <summary>
    /// False for every view but <see cref="FilterRuleView.Evaluation"/>. Drives
    /// the banner warning that the order on screen is not the order the kernel
    /// uses.
    /// </summary>
    public bool PreservesEvaluationOrder => View == FilterRuleView.Evaluation;

    public int TotalRows => Groups.Sum(g => g.Rows.Count);
    public int TotalShadowed => Groups.Sum(g => g.ShadowedCount);
}
