namespace NetFirewall.Models.Firewall;

/// <summary>
/// Finds filter rules that can never run because an earlier rule in the same
/// chain already matches everything they match.
///
/// <para>A chain is evaluated top to bottom and the first matching rule wins,
/// so a broad rule silently kills every narrower rule below it. That is not a
/// hypothetical: a single <c>accept</c> on all TCP sat at priority 60 of a
/// <c>policy drop</c> input chain and turned the port-scan drops, the
/// invalid-state drop and the catch-all below it into dead code — for months,
/// invisibly, while the UI listed them as Enabled.</para>
///
/// <para>Deliberately CONSERVATIVE: a rule is reported only when coverage is
/// certain from the stored fields alone. Address and port sets are compared as
/// literal strings, so <c>10.0.0.0/8</c> is NOT treated as covering
/// <c>10.1.0.0/16</c> and a port range is not expanded. A missed shadow costs
/// nothing; a false one would train the operator to ignore the warning.</para>
///
/// <para>Pure and deterministic — a static utility rather than a DI service,
/// the same pure-function exception as <see cref="FwFilterRuleGuard"/>.</para>
/// </summary>
public static class FwRuleShadowAnalyzer
{
    /// <summary>
    /// Maps the id of each unreachable rule to the earlier rule that hides it.
    /// Rules absent from the dictionary are reachable.
    ///
    /// <para>Pass the rules of ONE chain. Ordering matches the nft generator:
    /// by priority, stable, so rules sharing a priority keep the order they
    /// were given in.</para>
    /// </summary>
    public static IReadOnlyDictionary<Guid, FwFilterRule> FindShadowed(IEnumerable<FwFilterRule>? chainRules)
    {
        var shadowed = new Dictionary<Guid, FwFilterRule>();
        if (chainRules is null) return shadowed;

        // Disabled rules are not emitted at all: they neither shadow nor get
        // shadowed. OrderBy is a stable sort, matching the generator.
        var ordered = chainRules.Where(r => r.Enabled).OrderBy(r => r.Priority).ToList();

        for (var i = 0; i < ordered.Count; i++)
        {
            for (var j = 0; j < i; j++)
            {
                if (!Covers(ordered[j], ordered[i])) continue;
                shadowed[ordered[i].Id] = ordered[j];
                break; // report the FIRST rule that hides it — the one to fix
            }
        }

        return shadowed;
    }

    /// <summary>
    /// Whether every packet matching <paramref name="narrow"/> also matches
    /// <paramref name="broad"/>, so <paramref name="broad"/> always wins first.
    /// </summary>
    private static bool Covers(FwFilterRule broad, FwFilterRule narrow)
    {
        // Only a terminal verdict ends evaluation. `log` falls through, so it
        // hides nothing.
        if (!IsTerminal(broad.Action)) return false;

        // A rate limit means the rule STOPS matching above the limit — traffic
        // then falls through to the rules below, which are therefore reachable.
        if (!string.IsNullOrWhiteSpace(broad.RateLimit)) return false;

        // A scheduled rule is only live inside its window; outside it the rules
        // below run normally.
        if (broad.ScheduleId.HasValue) return false;

        // Each dimension: either the broad rule doesn't constrain it at all, or
        // it constrains it exactly the same way.
        if (broad.InterfaceInId.HasValue && broad.InterfaceInId != narrow.InterfaceInId) return false;
        if (broad.InterfaceOutId.HasValue && broad.InterfaceOutId != narrow.InterfaceOutId) return false;

        if (!string.IsNullOrWhiteSpace(broad.Protocol)
            && !string.Equals(broad.Protocol.Trim(), narrow.Protocol?.Trim(), StringComparison.OrdinalIgnoreCase))
            return false;

        return CoversSet(broad.SourceAddresses, narrow.SourceAddresses)
            && CoversSet(broad.DestinationAddresses, narrow.DestinationAddresses)
            && CoversSet(broad.DestinationPorts, narrow.DestinationPorts)
            && CoversSet(broad.ConnectionState, narrow.ConnectionState);
    }

    private static bool IsTerminal(string? action) =>
        action?.Trim().ToLowerInvariant() is "accept" or "drop" or "reject";

    /// <summary>
    /// An empty broad set means "any" and covers everything. Otherwise the
    /// narrow rule must list values and every one of them must appear in the
    /// broad set — compared literally, never interpreted as CIDR or ranges.
    /// </summary>
    private static bool CoversSet(string[]? broad, string[]? narrow)
    {
        var broadValues = Clean(broad);
        if (broadValues.Count == 0) return true;

        var narrowValues = Clean(narrow);
        if (narrowValues.Count == 0) return false; // narrow means "any" — wider

        return narrowValues.All(broadValues.Contains);
    }

    private static HashSet<string> Clean(string[]? values) =>
        values is null
            ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            : values.Where(v => !string.IsNullOrWhiteSpace(v))
                    .Select(v => v.Trim())
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);
}
