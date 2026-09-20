using System.Net;
using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics.Doctors.Dns;

public sealed class DnsResolverUnitCheck : DnsDoctorCheckBase
{
    public override string Id => "dns.unit";
    public override string Category => "Service";
    public override string Title => "Resolver unit";

    protected override async Task<DiagCheck> CheckAsync(DnsDoctorContext ctx, CancellationToken ct)
    {
        var unit = await ctx.ResolverUnitAsync();
        if (unit is null || string.Equals(unit.ActiveState, "not-found", StringComparison.OrdinalIgnoreCase))
            return Skip("No local resolver unit is deployed (the firewall may be handing clients an upstream DNS directly).");

        var detail = $"{unit.UnitName} · {unit.ActiveState}/{unit.SubState} · {(unit.Enabled ? "enabled" : "not enabled at boot")}";
        if (!string.Equals(unit.ActiveState, "active", StringComparison.OrdinalIgnoreCase))
            return Fail($"{unit.UnitName} is {unit.ActiveState} — LAN clients pointed at this firewall cannot resolve anything.", DnsRemedies.Service(), detail);

        return unit.Enabled
            ? Pass($"{unit.UnitName} active.", detail)
            : Warn($"{unit.UnitName} runs but is not enabled — it will not survive a reboot.", DnsRemedies.Service($"systemctl enable {unit.UnitName}"), detail);
    }
}

public sealed class DnsListenerCheck : DnsDoctorCheckBase
{
    public override string Id => "dns.listen";
    public override string Category => "Service";
    public override string Title => "Listening on port 53";

    protected override async Task<DiagCheck> CheckAsync(DnsDoctorContext ctx, CancellationToken ct)
    {
        var listeners = await ctx.ListenersAsync();
        if (string.IsNullOrWhiteSpace(listeners)) return Skip("Could not read the listener table (ss).");

        var lines = listeners.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Where(l => l.Contains(":53 ", StringComparison.Ordinal) || l.TrimEnd().EndsWith(":53", StringComparison.Ordinal))
            .Select(l => l.Trim()).ToList();
        var evidence = new[] { new DiagEvidence("ss -lntup | grep :53", string.Join('\n', lines)) };

        if (lines.Count == 0)
            return Fail("Nothing is listening on port 53 — clients using this firewall as their resolver get no answer at all.", DnsRemedies.Forwarder(), evidence: evidence);

        var udp = lines.Any(l => l.StartsWith("udp", StringComparison.OrdinalIgnoreCase));
        var tcp = lines.Any(l => l.StartsWith("tcp", StringComparison.OrdinalIgnoreCase));

        // LAN clients cannot use a resolver bound only to loopback.
        var loopbackOnly = lines.All(l => l.Contains("127.0.0.1:53", StringComparison.Ordinal) || l.Contains("[::1]:53", StringComparison.Ordinal));
        if (loopbackOnly)
            return Fail("Port 53 is bound to loopback only — the firewall resolves for itself, but no LAN client can reach it.",
                DnsRemedies.Forwarder("Bind the forwarder to the LAN address (or 0.0.0.0)."), evidence: evidence);

        if (!udp) return Fail("Port 53 has no UDP listener — almost every client asks over UDP first.", DnsRemedies.Forwarder(), evidence: evidence);
        if (!tcp) return Warn("Port 53 listens on UDP but not TCP — large answers and zone transfers will fail.", DnsRemedies.Forwarder(), evidence: evidence);

        return Pass($"{lines.Count} listener(s) on port 53 (UDP and TCP).", evidence: evidence);
    }
}

public sealed class DnsLocalResolutionCheck : DnsDoctorCheckBase
{
    public override string Id => "dns.resolve_local";
    public override string Category => "Resolution";
    public override string Title => "Local resolver answers";

    protected override async Task<DiagCheck> CheckAsync(DnsDoctorContext ctx, CancellationToken ct)
    {
        var probe = await DnsDoctorContext.QueryAsync(IPAddress.Loopback, ctx.ProbeName, 2000, ct);
        var evidence = new[] { new DiagEvidence($"DNS A? {ctx.ProbeName} @127.0.0.1", Describe(probe)) };

        if (!probe.Answered)
            return Fail($"The local resolver did not answer for {ctx.ProbeName}: {probe.Error}", DnsRemedies.Forwarder(), evidence: evidence);

        if (probe.Rcode == "SERVFAIL")
            return Fail($"The local resolver returned SERVFAIL for {ctx.ProbeName} — it is running but cannot reach its upstreams (or DNSSEC validation is failing).",
                DnsRemedies.Forwarder("Check the upstream servers and the WAN."), evidence: evidence);
        if (probe.Rcode == "REFUSED")
            return Fail($"The local resolver REFUSED the query — the client asking (this firewall) is outside its access list.",
                DnsRemedies.Forwarder("Add the firewall's own address / the LAN to the allowed clients."), evidence: evidence);
        if (probe.Rcode != "NOERROR" || probe.Answers == 0)
            return Warn($"{ctx.ProbeName} resolved to {probe.Rcode} with {probe.Answers} answer(s).", DnsRemedies.Forwarder(), evidence: evidence);

        var slow = probe.ElapsedMs > 500;
        return slow
            ? Warn($"Resolved {ctx.ProbeName} in {probe.ElapsedMs:0} ms — slow enough for clients to notice.", DnsRemedies.Forwarder(), evidence: evidence)
            : Pass($"Resolved {ctx.ProbeName} in {probe.ElapsedMs:0} ms ({probe.Answers} answer(s)).", evidence: evidence);
    }

    internal static string Describe(DnsProbe p) =>
        p.Answered ? $"rcode {p.Rcode} · {p.Answers} answer(s) · {p.ElapsedMs:0} ms" : $"no answer · {p.Error} · waited {p.ElapsedMs:0} ms";
}

public sealed class DnsLanResolutionCheck : IDnsDoctorCheck
{
    public string Id => "dns.resolve_lan";
    public string Category => "Resolution";

    public async Task<IReadOnlyList<DiagCheck>> RunAsync(DnsDoctorContext ctx, CancellationToken ct)
    {
        var lans = (await ctx.InterfacesAsync())
            .Where(i => string.Equals(i.Type, "LAN", StringComparison.OrdinalIgnoreCase) && i.Enabled).ToList();
        if (lans.Count == 0) return [DiagCheck.Skip(Id, Category, "LAN-facing resolution", "No enabled LAN interface.")];

        var links = await ctx.LinksAsync();
        var rows = new List<DiagCheck>();

        foreach (var lan in lans)
        {
            var addr = links.FirstOrDefault(l => l.Name == lan.Name)?.Addresses
                .Select(a => a.Split('/')[0])
                .FirstOrDefault(a => IPAddress.TryParse(a, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            var id = $"{Id}.{lan.Name}";
            if (addr is null)
            {
                rows.Add(DiagCheck.Skip(id, Category, $"Resolution on {lan.Name}", $"{lan.Name} has no IPv4 address."));
                continue;
            }

            // Query the LAN address exactly as a client would — this catches a
            // resolver bound to loopback and a firewall rule that blocks 53.
            var probe = await DnsDoctorContext.QueryAsync(IPAddress.Parse(addr), ctx.ProbeName, 2000, ct);
            var ev = new[] { new DiagEvidence($"DNS A? {ctx.ProbeName} @{addr}", DnsLocalResolutionCheck.Describe(probe)) };

            rows.Add(probe.Answered && probe.Rcode == "NOERROR"
                ? DiagCheck.Pass(id, Category, $"Resolution on {lan.Name}", $"{addr} answers in {probe.ElapsedMs:0} ms — clients on {lan.Name} can resolve.", evidence: ev)
                : DiagCheck.Fail(id, Category, $"Resolution on {lan.Name}",
                    $"{addr} did not answer properly ({(probe.Answered ? probe.Rcode : probe.Error)}). Clients on {lan.Name} pointed at this firewall cannot resolve.",
                    DnsRemedies.Forwarder("Check the listen address and that the input chain accepts 53 from this LAN."), evidence: ev));
        }
        return rows;
    }
}

public sealed class DnsFirewallCheck : DnsDoctorCheckBase
{
    public override string Id => "dns.firewall";
    public override string Category => "Firewall";
    public override string Title => "Port 53 accepted from the LAN";

    protected override async Task<DiagCheck> CheckAsync(DnsDoctorContext ctx, CancellationToken ct)
    {
        var ruleset = await ctx.LiveRulesetAsync();
        if (string.IsNullOrWhiteSpace(ruleset)) return Skip("Live ruleset unavailable.");

        var lines = ruleset.Split('\n').Select(l => l.Trim())
            .Where(l => l.Contains("dport 53", StringComparison.Ordinal) || l.Contains("dport { 53", StringComparison.Ordinal))
            .ToList();
        var evidence = new[] { new DiagEvidence("nft list ruleset | grep 'dport 53'", string.Join('\n', lines)) };

        var accepts = lines.Where(l => l.Contains("accept", StringComparison.Ordinal)).ToList();
        var dnats = lines.Where(l => l.Contains("dnat", StringComparison.Ordinal)).ToList();

        if (accepts.Count == 0 && dnats.Count == 0)
            return Warn("No rule mentions port 53. If clients use this firewall as their resolver, the input chain's default policy is dropping their queries.",
                DnsRemedies.FilterRules("Add an accept for udp/tcp 53 from the LAN."), evidence: evidence);

        if (accepts.Count == 0 && dnats.Count > 0)
            return Pass($"{dnats.Count} DNAT rule(s) redirect port 53 — queries are forwarded to another resolver rather than served locally.", evidence: evidence);

        return Pass($"{accepts.Count} rule(s) accept port 53.", evidence: evidence);
    }
}

public sealed class DnsUpstreamCheck : DnsDoctorCheckBase
{
    public override string Id => "dns.upstream";
    public override string Category => "Resolution";
    public override string Title => "Upstream reachability";

    private static readonly IPAddress[] Wellknown = [IPAddress.Parse("1.1.1.1"), IPAddress.Parse("8.8.8.8")];

    protected override async Task<DiagCheck> CheckAsync(DnsDoctorContext ctx, CancellationToken ct)
    {
        // If the local resolver is sick, this tells you whether the box itself can
        // reach the outside world's DNS at all — a WAN problem, not a DNS problem.
        var results = new List<string>();
        var ok = 0;
        foreach (var server in Wellknown)
        {
            var probe = await DnsDoctorContext.QueryAsync(server, ctx.ProbeName, 2000, ct);
            results.Add($"{server}: {DnsLocalResolutionCheck.Describe(probe)}");
            if (probe.Answered && probe.Rcode == "NOERROR") ok++;
        }
        var detail = string.Join('\n', results);

        return ok switch
        {
            0 => Fail("No public resolver answered — this is an uplink problem, not a DNS-server problem.",
                    new DiagRemedy("WAN doctor", "/Diagnostics/Wan", "Run the WAN doctor next."), detail),
            var n when n < Wellknown.Length => Warn($"{ok}/{Wellknown.Length} public resolvers answered.", null, detail),
            _ => Pass($"All {Wellknown.Length} public resolvers answered — outbound DNS works.", detail),
        };
    }
}
