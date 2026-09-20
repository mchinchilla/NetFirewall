using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics.Vpn.Checks;

// Routing checks: does a marked packet actually reach the tunnel, and does the
// tunnel's own traffic leave through a WAN? These cover the Stop/Start failure
// (the kernel purges every `dev wg0` route when the link disappears).

public sealed class EndpointPathCheck : VpnDoctorCheckBase
{
    public override string Id => "path.endpoint";
    public override string Category => "Path";
    public override string Title => "Route to the remote endpoint";

    protected override async Task<DiagCheck> CheckAsync(VpnDoctorContext ctx, CancellationToken ct)
    {
        var endpoints = ctx.UpstreamPeers.Concat(ctx.EnabledPeers.Where(p => VpnDoctorContext.IsRole(p, "site")))
            .Select(p => p.Endpoint).Where(e => !string.IsNullOrWhiteSpace(e)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (endpoints.Count == 0) return Skip("No dialled peer — nothing to route to.");

        var endpoint = endpoints[0]!;
        var host = endpoint.Contains(':') ? endpoint[..endpoint.LastIndexOf(':')] : endpoint;
        var ip = await ctx.Probes.ResolveAsync(host.Trim('[', ']'), ct);
        if (ip is null) return Fail($"Cannot resolve the endpoint host '{host}' — the tunnel can never come up.", VpnRemedies.PeerForm(ctx.UpstreamPeers.FirstOrDefault()?.Id ?? Guid.Empty));

        var r = await ctx.Routes.GetAsync(ip, 0, null, null, ct);
        var evidence = VpnDoctorContext.Evidence($"ip -j route get {ip}", r.Raw);
        if (r.Error is not null || r.Dev is null) return Fail($"No route to the endpoint {ip}: {r.Error ?? "no device"}", VpnRemedies.PolicyRouting(), evidence: evidence);

        if (string.Equals(r.Dev, ctx.Iface, StringComparison.Ordinal))
            return Fail($"The endpoint {ip} routes back into {ctx.Iface} — a routing loop: the encrypted packets would be sent through the tunnel they belong to.",
                VpnRemedies.PolicyRouting("Add a host route to the endpoint via the WAN, or make sure Table=off is set so wg-quick's 0.0.0.0/0 route is not installed."), evidence: evidence);

        var wans = (await ctx.InterfacesAsync()).Where(i => string.Equals(i.Type, "WAN", StringComparison.OrdinalIgnoreCase)).Select(i => i.Name).ToList();
        return wans.Contains(r.Dev, StringComparer.Ordinal)
            ? Pass($"Endpoint {ip} leaves via {r.Dev}" + (r.Gateway is null ? "" : $" → {r.Gateway}") + ".", evidence: evidence)
            : Warn($"Endpoint {ip} leaves via {r.Dev}, which is not a configured WAN.", VpnRemedies.PolicyRouting(), evidence: evidence);
    }
}

public sealed class PolicyRuleCheck : VpnDoctorCheckBase
{
    public override string Id => "pr.rule";
    public override string Category => "Policy routing";
    public override string Title => "ip rule for the tunnel mark";

    protected override async Task<DiagCheck> CheckAsync(VpnDoctorContext ctx, CancellationToken ct)
    {
        var mark = await ctx.TunnelMarkAsync();
        if (mark == 0) return Skip("No fwmark is scaffolded for this tunnel (nothing is steered into it by mark).");

        var wanted = await ctx.PolicyRuleAsync();
        var live = await ctx.IpRulesAsync();
        var evidence = VpnDoctorContext.Evidence("ip -j rule list", string.Join('\n', live.Select(r => r.Raw)));
        var hit = live.FirstOrDefault(r => r.Fwmark == mark);

        if (hit is null)
            return Fail($"No live ip rule for fwmark 0x{mark:x} — marked packets fall through to the main table and leave via the default WAN.",
                VpnRemedies.PolicyRouting(), evidence: evidence);

        if (!string.Equals(hit.Table, ctx.Iface, StringComparison.OrdinalIgnoreCase))
            return Fail($"fwmark 0x{mark:x} looks up table '{hit.Table}', not '{ctx.Iface}'.", VpnRemedies.PolicyRouting(), evidence: evidence);

        if (wanted?.Priority is { } prio && hit.Priority != prio)
            return Warn($"Rule present (fwmark 0x{mark:x} → {hit.Table}) but at priority {hit.Priority}, while the database says {prio}.",
                VpnRemedies.PolicyRouting(), evidence: evidence);

        return Pass($"fwmark 0x{mark:x} → table {hit.Table} at priority {hit.Priority}.", evidence: evidence);
    }
}

public sealed class TunnelTableCheck : VpnDoctorCheckBase
{
    public override string Id => "pr.table";
    public override string Category => "Policy routing";
    public override string Title => "Routes in the tunnel table";

    protected override async Task<DiagCheck> CheckAsync(VpnDoctorContext ctx, CancellationToken ct)
    {
        if (await ctx.RouteTableAsync() is null && await ctx.TunnelMarkAsync() == 0)
            return Skip("No routing table is scaffolded for this tunnel.");

        var routes = await ctx.TunnelTableAsync();
        var evidence = VpnDoctorContext.Evidence($"ip -j route show table {ctx.Iface}", string.Join('\n', routes.Select(r => r.Raw)));

        if (routes.Count == 0)
            return Fail($"Table '{ctx.Iface}' is EMPTY. Deleting the interface purges its routes from every table and wg-quick with Table=off puts none back, so the fwmark lookup finds nothing and traffic silently leaves via the default WAN — the classic Stop/Start symptom.",
                VpnRemedies.PolicyRouting("Apply VPN also re-installs these routes now; this table is rebuilt from fw_static_routes."), evidence: evidence);

        var def = routes.FirstOrDefault(r => r.Destination is "default" or "0.0.0.0/0");
        if (def is null)
            return Fail($"Table '{ctx.Iface}' has {routes.Count} route(s) but no default — marked traffic for other destinations is not carried.",
                VpnRemedies.PolicyRouting(), evidence: evidence);

        return string.Equals(def.Dev, ctx.Iface, StringComparison.Ordinal)
            ? Pass($"default dev {def.Dev} present ({routes.Count} route(s) in the table).", evidence: evidence)
            : Fail($"The default route in table '{ctx.Iface}' points at {def.Dev}, not the tunnel.", VpnRemedies.PolicyRouting(), evidence: evidence);
    }
}

public sealed class MarkLookupCheck : VpnDoctorCheckBase
{
    public override string Id => "pr.mark_lookup";
    public override string Category => "Policy routing";
    public override string Title => "Marked packet reaches the tunnel";

    protected override async Task<DiagCheck> CheckAsync(VpnDoctorContext ctx, CancellationToken ct)
    {
        var mark = await ctx.TunnelMarkAsync();
        if (mark == 0) return Skip("No tunnel mark to test.");

        var ip = await ctx.Probes.ResolveAsync(ctx.ProbeTarget, ct);
        if (ip is null) return Skip($"Could not resolve the probe target '{ctx.ProbeTarget}'.");

        var r = await ctx.Routes.GetAsync(ip, mark, null, null, ct);
        var evidence = VpnDoctorContext.Evidence($"ip -j route get {ip} mark 0x{mark:x}", r.Raw);
        if (r.Error is not null) return Skip($"Lookup failed: {r.Error}");

        return string.Equals(r.Dev, ctx.Iface, StringComparison.Ordinal)
            ? Pass($"A packet to {ip} with mark 0x{mark:x} is routed out {r.Dev}.", evidence: evidence)
            : Fail($"A packet to {ip} with mark 0x{mark:x} would leave via {r.Dev ?? "(nothing)"}, not {ctx.Iface}. Whatever you steer into this mark is not using the tunnel.",
                VpnRemedies.PolicyRouting(), evidence: evidence);
    }
}

public sealed class JournalCheck : VpnDoctorCheckBase
{
    public override string Id => "log.recent";
    public override string Category => "Journal";
    public override string Title => "Recent kernel messages";

    protected override async Task<DiagCheck> CheckAsync(VpnDoctorContext ctx, CancellationToken ct)
    {
        var all = await ctx.DropLog.QueryAsync(null, 30, 800, "all", ct);
        if (all.Error is not null) return Skip($"Journal unavailable: {all.Error}");

        var mine = all.Entries.Where(e =>
            e.In == ctx.Iface || e.Out == ctx.Iface ||
            e.Raw.Contains(ctx.Iface, StringComparison.OrdinalIgnoreCase)).ToList();
        if (mine.Count == 0) return Pass($"Nothing about {ctx.Iface} in the last 30 minutes.");

        var drops = mine.Count(e => e.Prefix.Contains("DROP", StringComparison.Ordinal));
        var martians = mine.Count(e => e.Prefix == "martian");
        var detail = string.Join('\n', mine.TakeLast(20).Select(e => e.Raw));

        if (drops == 0 && martians == 0)
            return Pass($"{mine.Count} message(s) mentioning {ctx.Iface}, none of them drops.", detail);

        return Warn($"{drops} firewall drop(s) and {martians} martian report(s) involving {ctx.Iface} in the last 30 minutes.",
            VpnRemedies.DropLog($"Filter the drop log by interface {ctx.Iface}."), detail);
    }
}
