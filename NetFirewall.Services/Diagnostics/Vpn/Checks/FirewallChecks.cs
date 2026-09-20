using System.Text.RegularExpressions;
using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics.Vpn.Checks;

// Firewall checks read the LIVE ruleset (what the kernel is enforcing right now),
// not the database — the two drift whenever an apply failed or was never run.

public sealed partial class MasqueradeCheck : VpnDoctorCheckBase
{
    public override string Id => "fw.masq";
    public override string Category => "Firewall";
    public override string Title => "Masquerade out the tunnel";

    protected override async Task<DiagCheck> CheckAsync(VpnDoctorContext ctx, CancellationToken ct)
    {
        var rs = await ctx.LiveRulesetAsync();
        if (string.IsNullOrWhiteSpace(rs)) return Skip("Live ruleset unavailable.");

        var lines = rs.Split('\n').Select(l => l.Trim())
            .Where(l => l.Contains("masquerade", StringComparison.Ordinal) && l.Contains($"\"{ctx.Iface}\"", StringComparison.Ordinal))
            .ToList();
        var evidence = VpnDoctorContext.Evidence("nft list ruleset | grep masquerade", string.Join('\n', lines));

        if (lines.Count == 0)
            return Fail($"No masquerade rule sends LAN traffic out {ctx.Iface}. Packets would enter the tunnel with a private source the far end cannot answer.",
                VpnRemedies.ApplyFirewall("Firewall → Apply. The rule is generated from the VPN egress panel."), evidence: evidence);

        // Index-based matches (oif 7) break the moment the tunnel is re-created with a new ifindex.
        return lines.Any(l => IndexMatchRx().IsMatch(l))
            ? Warn($"Masquerade for {ctx.Iface} exists but matches the interface by INDEX — it stops matching after the tunnel is restarted.",
                VpnRemedies.ApplyFirewall("Re-apply: the generator now emits oifname \"…\"."), evidence: evidence)
            : Pass($"{lines.Count} masquerade rule(s) for {ctx.Iface}.", evidence: evidence);
    }

    [GeneratedRegex(@"\b(iif|oif)\s+\d+")]
    internal static partial Regex IndexMatchRx();
}

public sealed class ForwardCheck : VpnDoctorCheckBase
{
    public override string Id => "fw.forward";
    public override string Category => "Firewall";
    public override string Title => "LAN ↔ tunnel forwarding";

    protected override async Task<DiagCheck> CheckAsync(VpnDoctorContext ctx, CancellationToken ct)
    {
        var rs = await ctx.LiveRulesetAsync();
        if (string.IsNullOrWhiteSpace(rs)) return Skip("Live ruleset unavailable.");

        var lans = (await ctx.InterfacesAsync())
            .Where(i => string.Equals(i.Type, "LAN", StringComparison.OrdinalIgnoreCase) && i.Enabled)
            .Select(i => i.Name).ToList();
        var forwardLines = rs.Split('\n').Select(l => l.Trim())
            .Where(l => l.Contains("accept", StringComparison.Ordinal) &&
                        (l.Contains($"oifname \"{ctx.Iface}\"", StringComparison.Ordinal) || l.Contains($"iifname \"{ctx.Iface}\"", StringComparison.Ordinal)))
            .ToList();
        var blanket = lans.Where(lan => rs.Contains($"iifname \"{lan}\" accept", StringComparison.Ordinal)).ToList();
        var evidence = VpnDoctorContext.Evidence($"nft list ruleset | grep '{ctx.Iface}'", await ctx.RulesetLinesMentioningTunnelAsync());

        if (forwardLines.Count > 0)
            return Pass($"{forwardLines.Count} forward rule(s) reference {ctx.Iface}" + (blanket.Count > 0 ? $"; LAN {string.Join(", ", blanket)} also has a blanket accept." : "."), evidence: evidence);

        if (blanket.Count > 0)
            return Pass($"No tunnel-specific forward rule, but LAN {string.Join(", ", blanket)} has a blanket accept that covers LAN → {ctx.Iface}.", evidence: evidence);

        return Fail($"Nothing in the forward chain lets traffic cross between the LAN and {ctx.Iface} — the default policy drops it.",
            VpnRemedies.ApplyFirewall(), evidence: evidence);
    }
}

public sealed class InputPortCheck : VpnDoctorCheckBase
{
    public override string Id => "fw.input_port";
    public override string Category => "Firewall";
    public override string Title => "Inbound listener accepted";

    protected override async Task<DiagCheck> CheckAsync(VpnDoctorContext ctx, CancellationToken ct)
    {
        var port = ctx.Server.ListenPort;
        if (port == 0) return Skip("Dial-only interface — no inbound port to accept.");

        var rs = await ctx.LiveRulesetAsync();
        if (string.IsNullOrWhiteSpace(rs)) return Skip("Live ruleset unavailable.");

        var needle = $"udp dport {port}";
        var line = rs.Split('\n').Select(l => l.Trim())
            .FirstOrDefault(l => l.Contains(needle, StringComparison.Ordinal) && l.Contains("accept", StringComparison.Ordinal));
        var evidence = VpnDoctorContext.Evidence($"nft list ruleset | grep 'dport {port}'", line ?? "(no match)");

        return line is not null
            ? Pass($"UDP {port} is accepted for inbound peers.", evidence: evidence)
            : Warn($"No input rule accepts UDP {port}; peers that dial this firewall cannot complete a handshake.",
                VpnRemedies.FilterRules($"Add an accept for udp/{port} on the WAN."), evidence: evidence);
    }
}

public sealed class StaleIndexMatchCheck : VpnDoctorCheckBase
{
    public override string Id => "fw.stale_iif";
    public override string Category => "Firewall";
    public override string Title => "Interface matches by name";

    protected override async Task<DiagCheck> CheckAsync(VpnDoctorContext ctx, CancellationToken ct)
    {
        var rs = await ctx.LiveRulesetAsync();
        if (string.IsNullOrWhiteSpace(rs)) return Skip("Live ruleset unavailable.");

        // `iif lo` is the only legitimate index match (lo never disappears).
        var offenders = rs.Split('\n').Select(l => l.Trim())
            .Where(l => MasqueradeCheck.IndexMatchRx().IsMatch(l))
            .ToList();
        var evidence = VpnDoctorContext.Evidence("nft list ruleset | grep -E '\\b(iif|oif) [0-9]+'", string.Join('\n', offenders));

        return offenders.Count == 0
            ? Pass("Every rule matches interfaces by name, so rules survive a tunnel restart and load while a link is down.")
            : Fail($"{offenders.Count} live rule(s) match an interface by index. Those stop matching as soon as the interface is re-created with a new index, and the whole ruleset refuses to load while the interface is absent.",
                VpnRemedies.ApplyFirewall("Re-apply: the generator emits iifname/oifname now."), evidence: evidence);
    }
}

public sealed partial class MangleCatchAllCheck : VpnDoctorCheckBase
{
    public override string Id => "fw.mangle_catchall";
    public override string Category => "Firewall";
    public override string Title => "Mark rules are constrained";

    protected override async Task<DiagCheck> CheckAsync(VpnDoctorContext ctx, CancellationToken ct)
    {
        var rs = await ctx.LiveRulesetAsync();
        if (string.IsNullOrWhiteSpace(rs)) return Skip("Live ruleset unavailable.");

        var markLines = rs.Split('\n').Select(l => l.Trim())
            .Where(l => l.Contains("meta mark set", StringComparison.Ordinal))
            .ToList();
        var unconstrained = markLines.Where(IsUnconstrained).ToList();

        var generated = await ctx.GeneratedConfigAsync();
        var skips = generated.Split('\n').Select(l => l.Trim())
            .Where(l => l.StartsWith("# SKIP", StringComparison.Ordinal))
            .ToList();

        var evidence = VpnDoctorContext.Evidence("nft list ruleset | grep 'meta mark set'", string.Join('\n', markLines));

        if (unconstrained.Count > 0)
            return Fail($"{unconstrained.Count} mark rule(s) have NO match criteria: they stamp every packet and, because the generator appends `return`, no mark rule below them ever runs. Steering for the other WANs is dead.",
                VpnRemedies.MangleRules("A rule whose addresses resolve to nothing renders like this; check it and re-apply."),
                string.Join('\n', unconstrained), evidence);

        if (skips.Count > 0)
            return Warn($"{skips.Count} rule(s) were skipped while generating the ruleset (their addresses or ports resolved to nothing).",
                VpnRemedies.MangleRules(), string.Join('\n', skips), evidence);

        var mark = await ctx.TunnelMarkAsync();
        var steering = mark > 0 ? markLines.Where(l => l.Contains($"0x{mark:x8}", StringComparison.OrdinalIgnoreCase) || l.Contains($"0x{mark:x}", StringComparison.OrdinalIgnoreCase)).ToList() : [];
        var sources = await ctx.EgressSourcesAsync();

        return Pass(mark > 0
            ? $"{markLines.Count} mark rule(s), all constrained; {steering.Count} steer into the tunnel mark 0x{mark:x} ({(sources.Count == 0 ? "no sources configured" : string.Join(", ", sources))})."
            : $"{markLines.Count} mark rule(s), all constrained.",
            string.Join('\n', steering), evidence);
    }

    /// <summary>A mark rule with no L3/L4 or interface match applies to everything.</summary>
    internal static bool IsUnconstrained(string line)
    {
        var head = line[..line.IndexOf("meta mark set", StringComparison.Ordinal)];
        return !head.Contains("saddr", StringComparison.Ordinal)
            && !head.Contains("daddr", StringComparison.Ordinal)
            && !head.Contains("iifname", StringComparison.Ordinal)
            && !head.Contains("oifname", StringComparison.Ordinal)
            && !head.Contains("iif ", StringComparison.Ordinal)
            && !head.Contains("oif ", StringComparison.Ordinal)
            && !head.Contains("ct mark", StringComparison.Ordinal)
            && !head.Contains("ct direction", StringComparison.Ordinal)
            && !head.Contains("dport", StringComparison.Ordinal)
            && !head.Contains("sport", StringComparison.Ordinal)
            && !head.Contains("ip protocol", StringComparison.Ordinal)
            && !head.Contains("meta l4proto", StringComparison.Ordinal);
    }
}

public sealed class VpnAutoRowsCheck : VpnDoctorCheckBase
{
    public override string Id => "fw.vpn_auto";
    public override string Category => "Firewall";
    public override string Title => "[vpn-auto] rows match the peers";

    protected override async Task<DiagCheck> CheckAsync(VpnDoctorContext ctx, CancellationToken ct)
    {
        const string tag = "[vpn-auto] peer ";
        var forwards = await ctx.ForwardRulesAsync();
        var nats = await ctx.NatRulesAsync();

        var rows = forwards.Select(f => f.Description).Concat(nats.Select(n => n.Description))
            .Where(d => d is not null && d.StartsWith(tag, StringComparison.Ordinal))
            .Select(d => d!).ToList();
        if (rows.Count == 0 && !ctx.EnabledPeers.Any()) return Skip("No peers and no generated rows.");

        var live = ctx.Peers.Select(p => p.Id.ToString()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var orphans = rows.Where(d =>
        {
            var rest = d[tag.Length..];
            var id = rest.Split(' ', 2)[0];
            return !live.Contains(id);
        }).Distinct().ToList();

        // An upstream peer is dialled by us; it legitimately has no generated rows.
        var missing = ctx.EnabledPeers
            .Where(p => !VpnDoctorContext.IsRole(p, "upstream"))
            .Where(p => !rows.Any(d => d.Contains(p.Id.ToString(), StringComparison.OrdinalIgnoreCase)))
            .Select(p => p.Name).ToList();

        if (orphans.Count > 0)
            return Warn($"{orphans.Count} auto-generated row(s) belong to peers that no longer exist.",
                VpnRemedies.ApplyFirewall("Re-saving any peer reconciles the tagged rows."), string.Join('\n', orphans));

        if (missing.Count > 0)
            return Warn($"No auto-generated rows for peer(s): {string.Join(", ", missing)}.",
                VpnRemedies.PeerForm(ctx.EnabledPeers.First(p => missing.Contains(p.Name)).Id, "Re-save the peer to regenerate its rules, then Apply."));

        return Pass(rows.Count == 0 ? "No auto-generated rows needed." : $"{rows.Count} auto-generated row(s), all belonging to current peers.");
    }
}
