namespace NetFirewall.Models.Firewall;

/// <summary>
/// Pure (no-IO) guard that recognises a filter rule which would silently make
/// its chain's default-deny policy unreachable.
///
/// <para>This exists because of a real incident. A rule stored as
/// <c>action=accept, protocol=tcp</c> with no port, no source, no interface and
/// <c>rate_limit='10/second'</c> renders as:</para>
///
/// <code>ip protocol tcp limit rate 10/second burst 5 packets accept</code>
///
/// <para>which matches EVERY TCP packet reaching the chain. <c>limit rate</c>
/// reads like a throttle but restricts nothing — it only bounds *when the rule
/// matches*, so all ordinary traffic passes under the limit and is accepted.
/// The firewall carried <c>policy drop</c> on input and still answered on every
/// listening TCP port from the public Internet, including an admin UI on
/// TCP/10000, while every rule below it (port-scan drops, invalid-state drop,
/// the catch-all) was dead code that never ran.</para>
///
/// <para>Three callers share this one definition so they can never disagree:
/// <c>FirewallService</c> refuses to store such a rule, the nft generator skips
/// one that is already stored, and the rule form in the Web UI blocks the
/// submit with the same reason (mirrored in <c>site.js</c> —
/// <c>NetFw.filterRuleBypass</c>; keep the two in step).</para>
///
/// <para>Stateless and deterministic, so it stays a static utility rather than
/// a DI service — the pure-function exception to the
/// everything-is-a-service rule.</para>
/// </summary>
public static class FwFilterRuleGuard
{
    /// <summary>
    /// Returns a human-readable reason why this rule defeats its chain's
    /// default-deny policy, or <c>null</c> when the rule is legitimately
    /// narrowed. The string is surfaced verbatim to the operator, so it says
    /// what is wrong AND how to fix it.
    ///
    /// <para>A rule is a bypass when it accepts, in a default-deny chain,
    /// without a single narrowing condition: no interface, no source or
    /// destination address, no destination port, and a connection-state match
    /// that still admits NEW connections. Any one of those turns it into an
    /// operator's deliberate choice rather than a hole.</para>
    /// </summary>
    public static string? DescribeBypass(FwFilterRule? rule)
    {
        if (rule is null) return null;

        // A disabled rule is never emitted into the ruleset, so it cannot open
        // anything. Keeping it storable lets an operator retain a historical
        // row (and its audit trail) after disabling it — what the guard blocks
        // is turning one back on.
        if (!rule.Enabled) return null;

        // Only an accept can open a hole. drop / reject end the packet, and log
        // is non-terminal.
        if (!Is(rule.Action, "accept")) return null;

        // Only the default-deny chains. output is `policy accept` by design, so
        // a broad accept there changes nothing.
        if (!Is(rule.Chain, "input") && !Is(rule.Chain, "forward")) return null;

        // ICMP has no ports to narrow by, and a rate-limited "allow ping"
        // accept is a normal, deliberate shape rather than an oversight.
        if (Is(rule.Protocol, "icmp") || Is(rule.Protocol, "icmpv6")) return null;

        // Any single narrowing condition means the operator scoped it.
        if (rule.InterfaceInId.HasValue || rule.InterfaceOutId.HasValue) return null;
        if (HasEntries(rule.SourceAddresses)) return null;
        if (HasEntries(rule.DestinationAddresses)) return null;
        if (HasEntries(rule.DestinationPorts)) return null;

        // `ct state established,related accept` is the standard stateful rule:
        // it only readmits return traffic for connections this box already
        // allowed out, so it is not a way in. Anything that still admits NEW
        // connections (including an empty state match, which means every state)
        // is.
        if (!AdmitsNewConnections(rule.ConnectionState)) return null;

        var protocol = string.IsNullOrWhiteSpace(rule.Protocol)
            ? "IP"
            : rule.Protocol.Trim().ToUpperInvariant();

        var reason =
            $"This '{rule.Chain}' accept matches all {protocol} traffic — no interface, no address and no port " +
            $"narrow it — so it would shadow every rule below it and make the chain's default-deny policy " +
            $"unreachable. Add a destination port, a source address, or an interface.";

        // The trap that caused the incident: operators read `limit rate` as a
        // restriction. Say so explicitly when it is the only thing on the rule.
        if (!string.IsNullOrWhiteSpace(rule.RateLimit))
        {
            reason +=
                $" The rate limit does not narrow it: 'limit rate' only bounds when the rule matches, so all " +
                $"traffic under {rule.RateLimit} is still accepted.";
        }

        return reason;
    }

    /// <summary>
    /// Whether <paramref name="rule"/> would defeat its chain's default-deny
    /// policy. Convenience over <see cref="DescribeBypass"/> for callers that
    /// do not need the reason.
    /// </summary>
    public static bool IsDefaultDenyBypass(FwFilterRule? rule) => DescribeBypass(rule) is not null;

    private static bool Is(string? value, string expected) =>
        string.Equals(value?.Trim(), expected, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// True when the array carries at least one non-blank entry. An empty array
    /// and a null array both mean "any" to the nft generator, which is exactly
    /// the case the guard must catch.
    /// </summary>
    private static bool HasEntries(string[]? values) =>
        values is not null && values.Any(v => !string.IsNullOrWhiteSpace(v));

    /// <summary>
    /// True when this connection-state match still lets NEW connections in. No
    /// state match at all means every state, new included.
    /// </summary>
    private static bool AdmitsNewConnections(string[]? states) =>
        !HasEntries(states) || states!.Any(s => Is(s, "new"));
}
