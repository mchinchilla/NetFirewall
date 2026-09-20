using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics.Doctors.Wan;

// The dual-WAN failures this box has actually had: a health config table that was
// empty so failover never fired, marks that route nowhere, and a default route
// that disagrees with the WAN the monitor thinks is active.

public sealed class WanInventoryCheck : WanDoctorCheckBase
{
    public override string Id => "wan.inventory";
    public override string Category => "Inventory";
    public override string Title => "WAN interfaces";

    protected override async Task<DiagCheck> CheckAsync(WanDoctorContext ctx, CancellationToken ct)
    {
        var wans = await ctx.WansAsync();
        if (wans.Count == 0)
            return Fail("No enabled interface is typed WAN — nothing to monitor or fail over.", WanRemedies.Interfaces());

        var detail = string.Join('\n', wans.Select(w => $"• {w.Name} · role {(string.IsNullOrEmpty(w.Role) ? "(unset)" : w.Role)} · {w.AddressingMode}"));
        var roleless = wans.Where(w => string.IsNullOrWhiteSpace(w.Role)).Select(w => w.Name).ToList();

        return wans.Count == 1
            ? Pass($"Single WAN: {wans[0].Name}. Failover checks below are informational.", detail)
            : roleless.Count > 0
                ? Warn($"{wans.Count} WANs, but {string.Join(", ", roleless)} has no role — failover priority is undefined.", WanRemedies.Interfaces(), detail)
                : Pass($"{wans.Count} WANs: {string.Join(", ", wans.Select(w => w.Name))}.", detail);
    }
}

public sealed class WanLinkCheck : IWanDoctorCheck
{
    public string Id => "wan.link";
    public string Category => "Link";

    public async Task<IReadOnlyList<DiagCheck>> RunAsync(WanDoctorContext ctx, CancellationToken ct)
    {
        var wans = await ctx.WansAsync();
        if (wans.Count == 0) return [DiagCheck.Skip(Id, Category, "Link state", "No WAN interfaces.")];

        var links = await ctx.LinksAsync();
        var rows = new List<DiagCheck>();
        foreach (var wan in wans)
        {
            var id = $"{Id}.{wan.Name}";
            var link = links.FirstOrDefault(l => l.Name == wan.Name);
            if (link is null || !link.Exists)
            {
                rows.Add(DiagCheck.Fail(id, Category, $"{wan.Name} link", $"{wan.Name} is configured but not present in the kernel.", WanRemedies.Interfaces()));
                continue;
            }

            var addrs = link.Addresses.Where(a => !a.StartsWith("fe80:", StringComparison.OrdinalIgnoreCase)).ToList();
            var detail = $"state {link.OperState} · mtu {link.Mtu} · addresses {(addrs.Count == 0 ? "none" : string.Join(", ", addrs))} · rx/tx errors {link.RxErrors}/{link.TxErrors}";

            if (link.OperState == "down" || link.Carrier == false)
                rows.Add(DiagCheck.Fail(id, Category, $"{wan.Name} link", $"{wan.Name} has no carrier — the cable or the upstream device is down.", WanRemedies.Interfaces(), detail));
            else if (addrs.Count == 0)
                rows.Add(DiagCheck.Fail(id, Category, $"{wan.Name} link", $"{wan.Name} is up but has no address (DHCP/PPPoE not up?).", WanRemedies.Interfaces(), detail));
            else if (link.RxErrors + link.TxErrors > 0)
                rows.Add(DiagCheck.Warn(id, Category, $"{wan.Name} link", $"{wan.Name} is up with {link.RxErrors + link.TxErrors} interface error(s).", WanRemedies.Interfaces(), detail));
            else
                rows.Add(DiagCheck.Pass(id, Category, $"{wan.Name} link", $"{wan.Name} up · {string.Join(", ", addrs)}", detail));
        }
        return rows;
    }
}

public sealed class WanHealthConfigCheck : WanDoctorCheckBase
{
    public override string Id => "wan.health_config";
    public override string Category => "Failover";
    public override string Title => "Health monitor configuration";

    protected override async Task<DiagCheck> CheckAsync(WanDoctorContext ctx, CancellationToken ct)
    {
        var wans = await ctx.WansAsync();
        var configs = await ctx.ConfigsAsync();

        // This box has been bitten by exactly this: the table existed but was empty,
        // so the monitor had nothing to probe and failover never fired.
        if (configs.Count == 0)
            return Fail("wan_health_config is empty — the monitor probes nothing, so failover can never fire no matter how dead a WAN is.",
                WanRemedies.Failover("Add a monitor entry per WAN (targets + probe mark)."));

        var missing = wans.Where(w => !configs.Any(c => c.InterfaceId == w.Id)).Select(w => w.Name).ToList();
        var disabled = configs.Where(c => !c.Enabled).Select(c => c.InterfaceName).ToList();
        var noTargets = configs.Where(c => c.Enabled && c.MonitorTargets.Length == 0).Select(c => c.InterfaceName).ToList();
        var noMark = configs.Where(c => c.Enabled && c.ProbeFwmark is null or 0).Select(c => c.InterfaceName).ToList();

        var detail = string.Join('\n', configs.Select(c =>
            $"• {c.InterfaceName} · priority {c.Priority} · mark {(c.ProbeFwmark is { } m ? $"0x{m:x}" : "none")} · targets {(c.MonitorTargets.Length == 0 ? "none" : string.Join(", ", c.MonitorTargets))} · {(c.Enabled ? "enabled" : "disabled")}"));

        if (missing.Count > 0)
            return Fail($"No health config for {string.Join(", ", missing)} — those WANs are never probed.", WanRemedies.Failover(), detail);
        if (noTargets.Count > 0)
            return Fail($"{string.Join(", ", noTargets)} has no monitor target — its probe always succeeds vacuously.", WanRemedies.Failover(), detail);
        if (noMark.Count > 0)
            return Warn($"{string.Join(", ", noMark)} has no probe fwmark — the probe follows the default route instead of its own uplink, so it cannot tell that WAN apart.",
                WanRemedies.Failover("Set probe_fwmark to the mark whose table points at that WAN."), detail);
        if (disabled.Count > 0)
            return Warn($"Monitoring disabled for {string.Join(", ", disabled)}.", WanRemedies.Failover(), detail);

        return Pass($"{configs.Count} WAN(s) monitored.", detail);
    }
}

public sealed class WanHealthStateCheck : WanDoctorCheckBase
{
    public override string Id => "wan.health_state";
    public override string Category => "Failover";
    public override string Title => "Monitor verdict";

    protected override async Task<DiagCheck> CheckAsync(WanDoctorContext ctx, CancellationToken ct)
    {
        var state = await ctx.StateAsync();
        if (state.Count == 0) return Skip("The monitor has not recorded any state yet.");

        var stale = state.Where(s => DateTime.UtcNow - s.LastCheckAt > TimeSpan.FromMinutes(5)).ToList();
        var down = state.Where(s => !s.IsUp).ToList();
        var detail = string.Join('\n', state.Select(s =>
            $"• {s.InterfaceName} · {(s.IsUp ? "up" : "DOWN")} · last check {s.LastCheckAt:HH:mm:ss} UTC · rtt {(s.LastRttMs is { } r ? $"{r:0.#} ms" : "—")} · target {s.LastTarget ?? "—"}{(s.LastError is null ? "" : $" · {s.LastError}")}"));

        if (stale.Count == state.Count)
            return Fail($"No WAN has been probed in the last 5 minutes — the health monitor is not running.",
                new DiagRemedy("Check the daemon", "/Monitoring", "systemctl status netfirewall-daemon"), detail);
        if (down.Count > 0)
            return Fail($"The monitor considers {string.Join(", ", down.Select(d => d.InterfaceName))} DOWN.", WanRemedies.Failover(), detail);
        if (stale.Count > 0)
            return Warn($"Stale state for {string.Join(", ", stale.Select(s => s.InterfaceName))}.", WanRemedies.Failover(), detail);

        return Pass($"All {state.Count} monitored WAN(s) up.", detail);
    }
}

public sealed class WanPolicyRoutingCheck : IWanDoctorCheck
{
    public string Id => "wan.policy";
    public string Category => "Policy routing";

    public async Task<IReadOnlyList<DiagCheck>> RunAsync(WanDoctorContext ctx, CancellationToken ct)
    {
        var configs = (await ctx.ConfigsAsync()).Where(c => c.Enabled && c.ProbeFwmark is > 0).ToList();
        if (configs.Count == 0) return [DiagCheck.Skip(Id, Category, "Per-WAN routing", "No WAN has a probe mark to verify.")];

        var rules = await ctx.IpRulesAsync();
        var evidence = new[] { new DiagEvidence("ip -j rule list", string.Join('\n', rules.Select(r => r.Raw))) };
        var rows = new List<DiagCheck>();

        foreach (var cfg in configs)
        {
            var id = $"{Id}.{cfg.InterfaceName}";
            var mark = cfg.ProbeFwmark!.Value;
            var rule = rules.FirstOrDefault(r => r.Fwmark == mark);
            if (rule is null)
            {
                rows.Add(DiagCheck.Fail(id, Category, $"{cfg.InterfaceName} mark 0x{mark:x}",
                    $"No ip rule for fwmark 0x{mark:x} — traffic marked for {cfg.InterfaceName} falls through to the main table and leaves via whichever WAN holds the default route.",
                    WanRemedies.PolicyRouting(), evidence: evidence));
                continue;
            }

            // The decisive test: would a marked packet actually leave via that WAN?
            var ip = await ctx.Probes.ResolveAsync(ctx.ProbeTarget, ct);
            if (ip is null)
            {
                rows.Add(DiagCheck.Skip(id, Category, $"{cfg.InterfaceName} mark 0x{mark:x}", $"Could not resolve the probe target '{ctx.ProbeTarget}'."));
                continue;
            }
            var got = await ctx.Routes.GetAsync(ip, mark, null, null, ct);
            var ev = new[] { new DiagEvidence($"ip -j route get {ip} mark 0x{mark:x}", got.Raw) };

            rows.Add(string.Equals(got.Dev, cfg.InterfaceName, StringComparison.Ordinal)
                ? DiagCheck.Pass(id, Category, $"{cfg.InterfaceName} mark 0x{mark:x}", $"fwmark 0x{mark:x} → table {rule.Table} → dev {got.Dev}.", evidence: ev)
                : DiagCheck.Fail(id, Category, $"{cfg.InterfaceName} mark 0x{mark:x}",
                    $"A packet marked 0x{mark:x} leaves via {got.Dev ?? "(nothing)"}, not {cfg.InterfaceName}. Its probe is measuring the wrong uplink, and anything steered into this mark is on the wrong WAN.",
                    WanRemedies.PolicyRouting(), evidence: ev));
        }
        return rows;
    }
}

public sealed class WanDefaultRouteCheck : WanDoctorCheckBase
{
    public override string Id => "wan.default_route";
    public override string Category => "Policy routing";
    public override string Title => "Default route owner";

    protected override async Task<DiagCheck> CheckAsync(WanDoctorContext ctx, CancellationToken ct)
    {
        var def = await ctx.DefaultRouteAsync();
        if (def is null) return Fail("The main table has no default route — unmarked traffic has nowhere to go.", WanRemedies.PolicyRouting());

        var control = await ctx.ControlAsync();
        var evidence = new[] { new DiagEvidence("ip -j route show table main", def.Raw) };
        var expected = control.OverrideInterfaceName ?? control.ActiveInterfaceName;
        var summary = $"default via {def.Gateway ?? "(on-link)"} dev {def.Dev}";

        if (expected is null) return Pass($"{summary}. The failover controller has not claimed an active WAN yet.", evidence: evidence);

        if (!string.Equals(def.Dev, expected, StringComparison.Ordinal))
            return Fail($"{summary}, but the failover controller believes {expected} is active{(control.OverrideInterfaceName is null ? "" : " (manual override)")}. Kernel and controller disagree.",
                WanRemedies.Failover("Re-apply failover, or clear the override."), evidence: evidence);

        return control.OverrideInterfaceName is not null
            ? Warn($"{summary} — pinned by a manual override set by {control.OverrideSetBy ?? "?"}. Automatic failover will not move it.",
                WanRemedies.Failover("Clear the override to restore automatic failover."), evidence: evidence)
            : Pass($"{summary}, matching the active WAN.", evidence: evidence);
    }
}

public sealed class WanReachabilityCheck : IWanDoctorCheck
{
    public string Id => "wan.reach";
    public string Category => "Reachability";

    public async Task<IReadOnlyList<DiagCheck>> RunAsync(WanDoctorContext ctx, CancellationToken ct)
    {
        var configs = (await ctx.ConfigsAsync()).Where(c => c.Enabled).ToList();
        if (configs.Count == 0) return [DiagCheck.Skip(Id, Category, "Live probe", "No monitored WAN to probe.")];

        var ip = await ctx.Probes.ResolveAsync(ctx.ProbeTarget, ct);
        if (ip is null) return [DiagCheck.Skip(Id, Category, "Live probe", $"Could not resolve '{ctx.ProbeTarget}'.")];

        var rows = new List<DiagCheck>();
        foreach (var cfg in configs)
        {
            var id = $"{Id}.{cfg.InterfaceName}";
            var mark = cfg.ProbeFwmark ?? 0;
            // Mark, not -I: policy routing ignores a bind, so a -I failure would prove nothing.
            var ping = await ctx.Probes.PingAsync(ip, mark > 0 ? null : cfg.InterfaceName, mark, 2, 2, ct);
            var ev = new[] { new DiagEvidence($"ping -c 2 {(mark > 0 ? $"-m {mark}" : $"-I {cfg.InterfaceName}")} {ip}", ping.Raw) };

            rows.Add(ping.Received > 0
                ? DiagCheck.Pass(id, Category, $"{cfg.InterfaceName} → {ip}", $"{ping.Received}/{ping.Sent} replies via {ping.Via}" + (ping.RttAvgMs is { } a ? $", avg {a:0.#} ms" : ""), evidence: ev)
                : DiagCheck.Fail(id, Category, $"{cfg.InterfaceName} → {ip}",
                    $"No reply via {ping.Via}. {(mark > 0 ? "That uplink cannot reach the internet." : "No probe mark is set, so this test may have used another WAN.")}",
                    WanRemedies.Failover(), evidence: ev));
        }
        return rows;
    }
}
