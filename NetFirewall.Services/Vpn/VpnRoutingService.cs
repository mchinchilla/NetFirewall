using System.Net;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Firewall;

namespace NetFirewall.Services.Vpn;

/// <summary>
/// Maps WireGuard tunnels onto policy-routing + firewall rows. See
/// <see cref="IVpnRoutingService"/> for the safety contract (discover-then-create,
/// never clobber seeded prod rows).
/// </summary>
public sealed class VpnRoutingService : IVpnRoutingService
{
    // Description tags that mark rows THIS service owns, so we can round-trip /
    // remove them without disturbing hand-authored or seeded rules.
    internal const string EgressTag = "[vpn-egress]";
    internal const string AutoTag = "[vpn-auto]";

    private readonly IFirewallService _fw;
    private readonly IPolicyRoutingService _routing;
    private readonly ILogger<VpnRoutingService> _logger;

    public VpnRoutingService(IFirewallService fw, IPolicyRoutingService routing, ILogger<VpnRoutingService> logger)
    {
        _fw = fw;
        _routing = routing;
        _logger = logger;
    }

    // ───────────────────────── Phase C: scaffold ─────────────────────────

    public async Task<VpnScaffold> EnsureRoutingScaffoldAsync(WgServer server, CancellationToken ct = default)
    {
        var name = server.Name; // "wg0"

        // 1) Interface (type VPN). Reuse if present (tekium already has wg0).
        var iface = await _fw.GetInterfaceByNameAsync(name, ct)
                    ?? await _fw.CreateInterfaceAsync(new FwInterface
                    {
                        Name = name,
                        Type = "VPN",
                        Role = "wireguard_tunnel",
                        IpAddress = TryIp(server.AddressCidr),
                        Gateway = null, // point-to-point
                        AddressingMode = "static",
                        Description = $"{AutoTag} WireGuard tunnel",
                        Enabled = true,
                    }, ct);

        // 2) Route table — reuse by name, else allocate a free id in [200,252].
        var table = await _routing.GetRouteTableByNameAsync(name, ct);
        if (table is null)
        {
            var tid = await _routing.AllocateTableIdAsync(ct);
            table = await _routing.EnsureRouteTableAsync(tid, name, $"{AutoTag} WireGuard tunnel — {name}", ct);
        }

        // 3) Mark — ADOPT, never assume. If a policy rule already routes to this
        //    table (tekium: fwmark 1280→wg0), reuse its mark. Else allocate one that
        //    collides with nothing in BOTH fw_traffic_marks AND fw_policy_rules.
        var existingRule = await _routing.GetPolicyRuleByTableNameAsync(name, ct);
        long fwmark;
        if (existingRule is not null)
        {
            fwmark = existingRule.Fwmark;
        }
        else
        {
            fwmark = await AllocateMarkAsync(ct);
        }

        // 4) Traffic mark row (so the mangle UI + generator can reference it).
        //    Match by mark_value; route_table soft-FK must point at this table name.
        var marks = await _fw.GetTrafficMarksAsync(ct);
        var mark = marks.FirstOrDefault(m => m.MarkValue == (int)fwmark);
        if (mark is null)
        {
            mark = await _fw.CreateTrafficMarkAsync(new FwTrafficMark
            {
                Name = $"VPN_{name}",
                MarkValue = (int)fwmark,
                RouteTable = name,
                Description = $"{AutoTag} egress via {name}",
            }, ct);
        }
        else if (!string.Equals(mark.RouteTable, name, StringComparison.OrdinalIgnoreCase)
                 && string.IsNullOrEmpty(mark.RouteTable))
        {
            // Existing mark with no route table → point it at ours (don't override a
            // mark that already routes elsewhere — that would be someone else's mark).
            mark.RouteTable = name;
            await _fw.UpdateTrafficMarkAsync(mark, ct);
        }

        // 5) Policy rule fwmark→table (priority above the WANs). Idempotent.
        if (existingRule is null)
        {
            var prio = await NextPolicyPriorityAsync(ct);
            await _routing.EnsurePolicyRuleAsync(fwmark, name, prio, $"{AutoTag} marked 0x{fwmark:x} → {name}", ct);
        }

        // 6) Default route dev <name> in the table. Match-before-insert.
        await EnsureDefaultRouteAsync(iface.Id, table.Id, name, ct);

        return new VpnScaffold(iface.Id, table.Name, table.TableId, fwmark, mark.Id);
    }

    private async Task EnsureDefaultRouteAsync(Guid ifaceId, Guid tableId, string name, CancellationToken ct)
    {
        var routes = await _fw.GetStaticRoutesAsync(null, ct);
        var has = routes.Any(r =>
            r.TableId == tableId &&
            r.Destination is "0.0.0.0/0" or "default" &&
            r.InterfaceId == ifaceId);
        if (has) return;

        await _fw.CreateStaticRouteAsync(new FwStaticRoute
        {
            InterfaceId = ifaceId,
            Destination = "0.0.0.0/0",
            Gateway = null,            // point-to-point — PolicyRoutingApplyService emits `dev <name>`
            Metric = 100,
            TableId = tableId,
            Description = $"{AutoTag} default via {name}",
            Enabled = true,
        }, ct);
    }

    /// <summary>Lowest free mark in the VPN band, colliding with nothing in either
    /// fw_traffic_marks.mark_value or fw_policy_rules.fwmark. Steps by 0x100 from
    /// 0x500 (WAN1=0x100, WAN2=0x200 are reserved; 0x300/0x400 left for other use).</summary>
    private async Task<long> AllocateMarkAsync(CancellationToken ct)
    {
        var used = new HashSet<long>();
        foreach (var m in await _fw.GetTrafficMarksAsync(ct)) used.Add(m.MarkValue);
        foreach (var p in await _routing.GetPolicyRulesAsync(ct)) used.Add(p.Fwmark);
        for (long v = 0x500; v <= 0xFF00; v += 0x100)
            if (!used.Contains(v)) return v;
        throw new InvalidOperationException("No free fwmark in the VPN band.");
    }

    private async Task<int> NextPolicyPriorityAsync(CancellationToken ct)
    {
        var rules = await _routing.GetPolicyRulesAsync(ct);
        var max = rules.Where(r => r.Priority.HasValue).Select(r => r.Priority!.Value).DefaultIfEmpty(100).Max();
        return max + 10;
    }

    // ───────────────────────── Phase B: egress sources ─────────────────────────

    public async Task<IReadOnlyList<string>> GetEgressSourcesAsync(WgServer server, CancellationToken ct = default)
    {
        var markValue = await ResolveTunnelMarkValueAsync(server, ct);
        if (markValue is null) return Array.Empty<string>();

        // Find the FwTrafficMark id for that value, then the mangle rules using it.
        var marks = await _fw.GetTrafficMarksAsync(ct);
        var markIds = marks.Where(m => m.MarkValue == markValue.Value).Select(m => m.Id).ToHashSet();
        if (markIds.Count == 0) return Array.Empty<string>();

        var mangle = await _fw.GetMangleRulesAsync("prerouting", ct);
        return mangle
            .Where(r => r.Enabled && r.MarkId.HasValue && markIds.Contains(r.MarkId.Value))
            .SelectMany(r => r.SourceAddresses ?? Array.Empty<string>())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public async Task SetEgressSourcesAsync(WgServer server, IReadOnlyList<string> sourceCidrs, CancellationToken ct = default)
    {
        var scaffold = await EnsureRoutingScaffoldAsync(server, ct);
        var clean = sourceCidrs
            .Select(s => s.Trim())
            .Where(s => s.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        // We own exactly one [vpn-egress] mangle rule on this mark — find or create it,
        // and set its SourceAddresses to the desired set. Hand-authored mangle rules on
        // the same mark (tekium's existing 4 lines) are LEFT ALONE; the panel shows
        // their union via GetEgressSources but only mutates the [vpn-egress] row.
        var mangle = await _fw.GetMangleRulesAsync("prerouting", ct);
        var managed = mangle.FirstOrDefault(r =>
            r.MarkId == scaffold.TrafficMarkId &&
            (r.Description?.StartsWith(EgressTag, StringComparison.Ordinal) ?? false));

        // Sources already covered by NON-managed rules on this mark — don't duplicate them.
        var coveredByOthers = mangle
            .Where(r => r.Enabled && r.MarkId == scaffold.TrafficMarkId && r != managed
                        && !(r.Description?.StartsWith(EgressTag, StringComparison.Ordinal) ?? false))
            .SelectMany(r => r.SourceAddresses ?? Array.Empty<string>())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var managedSources = clean.Where(s => !coveredByOthers.Contains(s)).ToArray();

        if (managed is null)
        {
            if (managedSources.Length == 0) return; // nothing for us to own
            await _fw.CreateMangleRuleAsync(new FwMangleRule
            {
                Chain = "prerouting",
                MarkId = scaffold.TrafficMarkId,
                SourceAddresses = managedSources,
                Priority = 50, // before the broad LAN-default mark so these win
                Enabled = true,
                Description = $"{EgressTag} devices routed via {server.Name}",
            }, ct);
        }
        else
        {
            managed.SourceAddresses = managedSources;
            managed.Enabled = managedSources.Length > 0;
            await _fw.UpdateMangleRuleAsync(managed, ct);
        }
    }

    private async Task<int?> ResolveTunnelMarkValueAsync(WgServer server, CancellationToken ct)
    {
        var rule = await _routing.GetPolicyRuleByTableNameAsync(server.Name, ct);
        if (rule is not null) return (int)rule.Fwmark;
        // No policy rule yet → fall back to a traffic mark whose route_table is the tunnel.
        var mark = (await _fw.GetTrafficMarksAsync(ct))
            .FirstOrDefault(m => string.Equals(m.RouteTable, server.Name, StringComparison.OrdinalIgnoreCase));
        return mark?.MarkValue;
    }

    // ───────────────────────── Phase D: per-peer NAT/forward ─────────────────────────

    public async Task EnsurePeerForwardingAsync(WgServer server, WgPeer peer, CancellationToken ct = default)
    {
        // Upstream tunnels are peers WE dial — they get no inbound NAT/forward.
        // Clients and site links need it regardless of the legacy server mode
        // (a dual-role interface dials an upstream AND hosts inbound peers).
        if (string.Equals(peer.Role, "upstream", StringComparison.OrdinalIgnoreCase)) return;

        var wg = await _fw.GetInterfaceByNameAsync(server.Name, ct);
        if (wg is null) return; // scaffold not built yet

        var lanIfaces = (await _fw.GetInterfacesAsync(ct)).Where(i => i.Type == "LAN" && i.Enabled).ToList();
        var wanIfaces = (await _fw.GetInterfacesAsync(ct)).Where(i => i.Type == "WAN" && i.Enabled).ToList();
        var mode = (peer.RouteMode ?? "full").ToLowerInvariant();
        var tag = $"{AutoTag} peer {peer.Id}";

        var existingNat = await _fw.GetNatRulesAsync(ct);
        var existingFilter = await _fw.GetFilterRulesAsync("forward", ct);

        // FORWARD: wg0 → LAN (+ return), scoped by intent.
        foreach (var lan in lanIfaces)
        {
            var dest = mode switch
            {
                "restricted" or "split" or "site" when peer.AllowedSubnets is { Length: > 0 } => peer.AllowedSubnets,
                _ => null, // full → no dest restriction (whole LAN)
            };
            await EnsureForwardRuleAsync(existingFilter, wg.Id, lan.Id, dest, tag + $" wg→{lan.Name}", ct);
        }

        // FULL tunnel: peer also reaches the internet → masquerade out the WAN + FORWARD wg→WAN.
        if (mode == "full")
        {
            var wan = wanIfaces.FirstOrDefault(w => w.Role == "primary_wan") ?? wanIfaces.FirstOrDefault();
            if (wan is not null)
            {
                await EnsureMasqueradeAsync(existingNat, server.AddressCidr, wan.Id, tag + $" → {wan.Name}", ct);
                await EnsureForwardRuleAsync(existingFilter, wg.Id, wan.Id, null, tag + $" wg→{wan.Name}", ct);
            }
        }
    }

    public async Task RemovePeerForwardingAsync(WgServer server, WgPeer peer, CancellationToken ct = default)
    {
        var tag = $"{AutoTag} peer {peer.Id}";
        foreach (var n in (await _fw.GetNatRulesAsync(ct)).Where(n => n.Description?.StartsWith(tag, StringComparison.Ordinal) ?? false))
            await _fw.DeleteNatRuleAsync(n.Id, ct);
        foreach (var f in (await _fw.GetFilterRulesAsync("forward", ct)).Where(f => f.Description?.StartsWith(tag, StringComparison.Ordinal) ?? false))
            await _fw.DeleteFilterRuleAsync(f.Id, ct);
    }

    private async Task EnsureMasqueradeAsync(
        IReadOnlyList<FwNatRule> existing, string sourceCidr, Guid wanId, string desc, CancellationToken ct)
    {
        // Dedup: skip if ANY masquerade row already covers (source, oif) — protects
        // tekium's existing `192.168.99.0/24 oif wg0 masquerade` and avoids double-NAT.
        if (existing.Any(n => n.Type == "masquerade"
                              && string.Equals(n.SourceNetwork, sourceCidr, StringComparison.OrdinalIgnoreCase)
                              && n.OutputInterfaceId == wanId))
            return;
        await _fw.CreateNatRuleAsync(new FwNatRule
        {
            Type = "masquerade",
            SourceNetwork = sourceCidr,
            OutputInterfaceId = wanId,
            Enabled = true,
            Priority = 100,
            Description = desc,
        }, ct);
    }

    private async Task EnsureForwardRuleAsync(
        IReadOnlyList<FwFilterRule> existing, Guid iifId, Guid oifId, string[]? destAddrs, string desc, CancellationToken ct)
    {
        if (existing.Any(f => f.InterfaceInId == iifId && f.InterfaceOutId == oifId
                              && f.Action == "accept"
                              && SameSet(f.DestinationAddresses, destAddrs)))
            return;
        await _fw.CreateFilterRuleAsync(new FwFilterRule
        {
            Chain = "forward",
            Action = "accept",
            InterfaceInId = iifId,
            InterfaceOutId = oifId,
            DestinationAddresses = destAddrs,
            Enabled = true,
            Priority = 90,
            Description = desc,
        }, ct);
    }

    private static bool SameSet(string[]? a, string[]? b)
    {
        var sa = a is null ? new HashSet<string>() : new HashSet<string>(a, StringComparer.OrdinalIgnoreCase);
        var sb = b is null ? new HashSet<string>() : new HashSet<string>(b, StringComparer.OrdinalIgnoreCase);
        return sa.SetEquals(sb);
    }

    private static IPAddress? TryIp(string cidr)
    {
        var slash = cidr.IndexOf('/');
        var ipPart = slash > 0 ? cidr[..slash] : cidr;
        return IPAddress.TryParse(ipPart, out var ip) ? ip : null;
    }
}
