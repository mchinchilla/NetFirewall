using Microsoft.Extensions.Logging;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Firewall;

namespace NetFirewall.Services.Vpn;

/// <summary>
/// See <see cref="IWireGuardTeardownService"/>. The safety contract mirrors
/// VpnRoutingService's: rows tagged [vpn-auto]/[vpn-egress] are ours and get
/// deleted; anything hand-authored is never deleted — at most disabled, with a
/// breadcrumb appended to its description so the operator can find and triage
/// it later.
/// </summary>
public sealed class WireGuardTeardownService : IWireGuardTeardownService
{
    private readonly IWireGuardService _wg;
    private readonly IFirewallService _fw;
    private readonly IPolicyRoutingService _routing;
    private readonly IVpnRoutingService _vpnRouting;
    private readonly IVpnHealthService _health;
    private readonly ILogger<WireGuardTeardownService> _logger;

    public WireGuardTeardownService(
        IWireGuardService wg,
        IFirewallService fw,
        IPolicyRoutingService routing,
        IVpnRoutingService vpnRouting,
        IVpnHealthService health,
        ILogger<WireGuardTeardownService> logger)
    {
        _wg = wg;
        _fw = fw;
        _routing = routing;
        _vpnRouting = vpnRouting;
        _health = health;
        _logger = logger;
    }

    private static bool IsVpnManaged(string? description) =>
        description is not null
        && (description.StartsWith(VpnRoutingService.AutoTag, StringComparison.Ordinal)
            || description.StartsWith(VpnRoutingService.EgressTag, StringComparison.Ordinal));

    private static bool IsTunnelRole(string role) =>
        role.Equals("upstream", StringComparison.OrdinalIgnoreCase)
        || role.Equals("site", StringComparison.OrdinalIgnoreCase);

    public async Task<WgTeardownImpact> ComputeImpactAsync(WgServer server, CancellationToken ct = default)
    {
        var peers = await _wg.GetPeersAsync(server.Id, ct);
        var iface = await _fw.GetInterfaceByNameAsync(server.Name, ct);
        var table = await _routing.GetRouteTableByNameAsync(server.Name, ct);
        var policyRule = await _routing.GetPolicyRuleByTableNameAsync(server.Name, ct);
        var marks = (await _fw.GetTrafficMarksAsync(ct))
            .Where(m => string.Equals(m.RouteTable, server.Name, StringComparison.OrdinalIgnoreCase))
            .ToArray();

        var natRules = await _fw.GetNatRulesAsync(ct);
        var filterRules = await _fw.GetFilterRulesAsync(null, ct);
        var mangleRules = await _fw.GetMangleRulesAsync(null, ct);
        var portForwards = await _fw.GetPortForwardsAsync(ct);
        var staticRoutes = (await _fw.GetStaticRoutesAsync(null, ct))
            .Where(r => (iface is not null && r.InterfaceId == iface.Id)
                        || (table is not null && r.TableId == table.Id))
            .ToArray();

        // Hand-authored rules that reference the interface: FK is SET NULL, so a
        // plain delete would leave them enabled but interface-less — silently
        // matching MORE traffic than intended. They get disabled instead.
        var orphans = new List<WgOrphanRule>();
        if (iface is not null)
        {
            orphans.AddRange(filterRules
                .Where(f => !IsVpnManaged(f.Description)
                            && (f.InterfaceInId == iface.Id || f.InterfaceOutId == iface.Id))
                .Select(f => new WgOrphanRule("filter", f.Description ?? f.Id.ToString())));
            orphans.AddRange(natRules
                .Where(n => !IsVpnManaged(n.Description) && n.OutputInterfaceId == iface.Id)
                .Select(n => new WgOrphanRule("nat", n.Description ?? n.Id.ToString())));
            orphans.AddRange(portForwards
                .Where(p => p.InterfaceId == iface.Id)
                .Select(p => new WgOrphanRule("port-forward", p.Description ?? p.Id.ToString())));
        }

        var activeVpnAlerts = (await _health.ActiveAlertsAsync(ct)).Count(a => a.Source == "vpn");

        return new WgTeardownImpact
        {
            InterfaceName = server.Name,
            TunnelNames = peers.Where(p => IsTunnelRole(p.Role)).Select(p => p.Name).ToArray(),
            ClientNames = peers.Where(p => !IsTunnelRole(p.Role)).Select(p => p.Name).ToArray(),
            AutoNatRuleCount = natRules.Count(n => IsVpnManaged(n.Description)),
            AutoForwardRuleCount = filterRules.Count(f => IsVpnManaged(f.Description)),
            EgressMangleRuleCount = mangleRules.Count(m => IsVpnManaged(m.Description)),
            EgressSources = (await _vpnRouting.GetEgressSourcesAsync(server, ct)).ToArray(),
            HasInterfaceRow = iface is not null,
            HasRouteTable = table is not null,
            HasPolicyRule = policyRule is not null,
            TrafficMarkCount = marks.Length,
            StaticRouteCount = staticRoutes.Length,
            OrphanedRules = orphans.ToArray(),
            ActiveAlertCount = activeVpnAlerts,
        };
    }

    public async Task<WgTeardownImpact> TeardownAsync(WgServer server, CancellationToken ct = default)
    {
        var impact = await ComputeImpactAsync(server, ct);
        var iface = await _fw.GetInterfaceByNameAsync(server.Name, ct);
        var table = await _routing.GetRouteTableByNameAsync(server.Name, ct);
        var orphanBreadcrumb = $" [orphaned: interface '{server.Name}' deleted]";

        // 1) Our own NAT/forward/mangle rows go first ([vpn-auto]/[vpn-egress]).
        foreach (var n in (await _fw.GetNatRulesAsync(ct)).Where(n => IsVpnManaged(n.Description)))
            await _fw.DeleteNatRuleAsync(n.Id, ct);
        foreach (var f in (await _fw.GetFilterRulesAsync(null, ct)).Where(f => IsVpnManaged(f.Description)))
            await _fw.DeleteFilterRuleAsync(f.Id, ct);
        foreach (var m in (await _fw.GetMangleRulesAsync(null, ct)).Where(m => IsVpnManaged(m.Description)))
            await _fw.DeleteMangleRuleAsync(m.Id, ct);

        // 2) Disable (never delete) hand-authored rules referencing the interface.
        if (iface is not null)
        {
            foreach (var f in (await _fw.GetFilterRulesAsync(null, ct))
                     .Where(f => !IsVpnManaged(f.Description)
                                 && (f.InterfaceInId == iface.Id || f.InterfaceOutId == iface.Id)))
            {
                f.Enabled = false;
                f.Description = (f.Description ?? "") + orphanBreadcrumb;
                await _fw.UpdateFilterRuleAsync(f, ct);
            }
            foreach (var n in (await _fw.GetNatRulesAsync(ct))
                     .Where(n => !IsVpnManaged(n.Description) && n.OutputInterfaceId == iface.Id))
            {
                n.Enabled = false;
                n.Description = (n.Description ?? "") + orphanBreadcrumb;
                await _fw.UpdateNatRuleAsync(n, ct);
            }
            foreach (var p in (await _fw.GetPortForwardsAsync(ct)).Where(p => p.InterfaceId == iface.Id))
            {
                p.Enabled = false;
                p.Description = (p.Description ?? "") + orphanBreadcrumb;
                await _fw.UpdatePortForwardAsync(p, ct);
            }
        }

        // 3) Policy-routing scaffold: routes → policy rule → marks → table → iface.
        foreach (var r in (await _fw.GetStaticRoutesAsync(null, ct))
                 .Where(r => (iface is not null && r.InterfaceId == iface.Id)
                             || (table is not null && r.TableId == table.Id)))
            await _fw.DeleteStaticRouteAsync(r.Id, ct);

        var policyRule = await _routing.GetPolicyRuleByTableNameAsync(server.Name, ct);
        if (policyRule is not null)
            await _routing.DeletePolicyRuleAsync(policyRule.Id, ct);

        foreach (var m in (await _fw.GetTrafficMarksAsync(ct))
                 .Where(m => string.Equals(m.RouteTable, server.Name, StringComparison.OrdinalIgnoreCase)))
            await _fw.DeleteTrafficMarkAsync(m.Id, ct);

        if (table is not null)
            await _routing.DeleteRouteTableAsync(table.Id, ct);

        if (iface is not null)
            await _fw.DeleteInterfaceAsync(iface.Id, ct);

        // 4) Health: resolve banners + drop state NOW (synchronously) — the
        // daemon's retire sweep would also get there, but the operator deleting
        // the VPN shouldn't stare at a stale "tunnel down" banner for 30s.
        foreach (var s in (await _health.GetStateAsync(ct)).Where(s => s.ServerId == server.Id))
        {
            await _health.ResolveAlertAsync($"vpn:{server.Id}:{s.PublicKey}", ct);
            await _health.DeleteStateAsync(server.Id, s.PublicKey, ct);
        }

        // 5) The server row last — peers + health history cascade with it.
        await _wg.DeleteServerAsync(server.Id, ct);

        _logger.LogWarning(
            "WireGuard interface {Name} torn down: {Tunnels} tunnel(s), {Clients} client(s), " +
            "{Nat}+{Fwd}+{Mangle} auto rules deleted, {Orphans} hand rules disabled, scaffold removed",
            server.Name, impact.TunnelNames.Length, impact.ClientNames.Length,
            impact.AutoNatRuleCount, impact.AutoForwardRuleCount, impact.EgressMangleRuleCount,
            impact.OrphanedRules.Length);

        return impact;
    }
}
