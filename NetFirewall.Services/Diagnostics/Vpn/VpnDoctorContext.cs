using NetFirewall.Models.Diagnostics;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Vpn;

namespace NetFirewall.Services.Diagnostics.Vpn;

/// <summary>
/// Everything the checks may ask about one tunnel, fetched at most once per run.
/// Every accessor is a memoised task: twenty checks reading the live ruleset or
/// <c>wg show</c> cost one command, and a DB/tool failure surfaces in each check
/// as a Skip with the message rather than aborting the report.
/// </summary>
public sealed class VpnDoctorContext
{
    public WgServer Server { get; }
    public IReadOnlyList<WgPeer> Peers { get; }
    public DateTime NowUtc { get; }
    public string Iface => Server.Name;
    public string ProbeTarget { get; }

    private readonly Lazy<Task<FwPolicyRule?>> _rule;
    private readonly Lazy<Task<FwRouteTable?>> _table;
    private readonly Lazy<Task<long>> _mark;
    private readonly Lazy<Task<WgDump?>> _dump;
    private readonly Lazy<Task<InterfaceHealth?>> _link;
    private readonly Lazy<Task<string>> _ruleset;
    private readonly Lazy<Task<string>> _generated;
    private readonly Lazy<Task<IReadOnlyList<IpRuleEntry>>> _ipRules;
    private readonly Lazy<Task<IReadOnlyList<IpRouteEntry>>> _tunnelTable;
    private readonly Lazy<Task<IReadOnlyList<FwMangleRule>>> _mangle;
    private readonly Lazy<Task<IReadOnlyList<FwTrafficMark>>> _marks;
    private readonly Lazy<Task<IReadOnlyList<FwNatRule>>> _nat;
    private readonly Lazy<Task<IReadOnlyList<FwFilterRule>>> _forward;
    private readonly Lazy<Task<IReadOnlyList<FwInterface>>> _interfaces;
    private readonly Lazy<Task<IReadOnlyList<string>>> _egress;

    public IRouteOracleService Routes { get; }
    public IPingProbeService Probes { get; }
    public IDropLogService DropLog { get; }

    internal VpnDoctorContext(
        WgServer server,
        IReadOnlyList<WgPeer> peers,
        string probeTarget,
        IPolicyRoutingService routing,
        IWgLiveReader wg,
        IInterfaceHealthService links,
        INftApplyService nft,
        IFirewallService fw,
        IRouteOracleService routes,
        IVpnRoutingService vpnRouting,
        IPingProbeService probes,
        IDropLogService dropLog,
        CancellationToken ct)
    {
        Server = server;
        Peers = peers;
        ProbeTarget = probeTarget;
        NowUtc = DateTime.UtcNow;
        Routes = routes;
        Probes = probes;
        DropLog = dropLog;

        _rule        = new(() => routing.GetPolicyRuleByTableNameAsync(server.Name, ct));
        _table       = new(() => routing.GetRouteTableByNameAsync(server.Name, ct));
        _dump        = new(() => wg.DumpAsync(server.Name, ct));
        _link        = new(() => links.GetAsync(server.Name, ct));
        _ruleset     = new(() => nft.GetCurrentRulesetAsync(ct));
        _generated   = new(() => fw.GenerateNftablesConfigAsync(ct));
        _ipRules     = new(() => routes.ListRulesAsync(ct));
        _tunnelTable = new(() => routes.ShowTableAsync(server.Name, ct));
        _mangle      = new(() => fw.GetMangleRulesAsync("prerouting", ct));
        _marks       = new(() => fw.GetTrafficMarksAsync(ct));
        _nat         = new(() => fw.GetNatRulesAsync(ct));
        _forward     = new(() => fw.GetFilterRulesAsync("forward", ct));
        _interfaces  = new(() => fw.GetInterfacesAsync(ct));
        _egress      = new(() => vpnRouting.GetEgressSourcesAsync(server, ct));
        _mark        = new(async () =>
        {
            // The scaffold names the policy rule's table after the interface; fall back
            // to a traffic mark whose route_table is the tunnel (tekium: 0x500 = 1280).
            var rule = await _rule!.Value;
            if (rule is not null) return rule.Fwmark;
            var marks = await _marks!.Value;
            return marks.FirstOrDefault(m => string.Equals(m.RouteTable, server.Name, StringComparison.OrdinalIgnoreCase))?.MarkValue ?? 0;
        });
    }

    public Task<FwPolicyRule?> PolicyRuleAsync() => _rule.Value;
    public Task<FwRouteTable?> RouteTableAsync() => _table.Value;
    public Task<long> TunnelMarkAsync() => _mark.Value;
    public Task<WgDump?> DumpAsync() => _dump.Value;
    public Task<InterfaceHealth?> LinkAsync() => _link.Value;
    public Task<string> LiveRulesetAsync() => _ruleset.Value;
    public Task<string> GeneratedConfigAsync() => _generated.Value;
    public Task<IReadOnlyList<IpRuleEntry>> IpRulesAsync() => _ipRules.Value;
    public Task<IReadOnlyList<IpRouteEntry>> TunnelTableAsync() => _tunnelTable.Value;
    public Task<IReadOnlyList<FwMangleRule>> MangleRulesAsync() => _mangle.Value;
    public Task<IReadOnlyList<FwTrafficMark>> MarksAsync() => _marks.Value;
    public Task<IReadOnlyList<FwNatRule>> NatRulesAsync() => _nat.Value;
    public Task<IReadOnlyList<FwFilterRule>> ForwardRulesAsync() => _forward.Value;
    public Task<IReadOnlyList<FwInterface>> InterfacesAsync() => _interfaces.Value;
    public Task<IReadOnlyList<string>> EgressSourcesAsync() => _egress.Value;

    public IEnumerable<WgPeer> EnabledPeers => Peers.Where(p => p.Enabled);
    public IEnumerable<WgPeer> UpstreamPeers => EnabledPeers.Where(p => IsRole(p, "upstream"));
    public static bool IsRole(WgPeer p, string role) => string.Equals(p.Role, role, StringComparison.OrdinalIgnoreCase);

    /// <summary>Evidence helper: caps output so a ruleset dump does not bloat the stored report.</summary>
    public static IReadOnlyList<DiagEvidence> Evidence(string command, string? output, int max = 16 * 1024)
    {
        output ??= string.Empty;
        return output.Length <= max
            ? [new DiagEvidence(command, output)]
            : [new DiagEvidence(command, output[..max] + "\n… (truncated)", true)];
    }

    /// <summary>Lines of the live ruleset that mention the tunnel — small, relevant evidence.</summary>
    public async Task<string> RulesetLinesMentioningTunnelAsync()
    {
        var rs = await LiveRulesetAsync();
        var hits = rs.Split('\n').Where(l => l.Contains($"\"{Iface}\"", StringComparison.Ordinal)).Select(l => l.Trim());
        return string.Join('\n', hits);
    }
}

public interface IVpnDoctorContextFactory
{
    VpnDoctorContext Create(WgServer server, IReadOnlyList<WgPeer> peers, string probeTarget, CancellationToken ct);
}

public sealed class VpnDoctorContextFactory : IVpnDoctorContextFactory
{
    private readonly IPolicyRoutingService _routing;
    private readonly IWgLiveReader _wg;
    private readonly IInterfaceHealthService _links;
    private readonly INftApplyService _nft;
    private readonly IFirewallService _fw;
    private readonly IRouteOracleService _routes;
    private readonly IVpnRoutingService _vpnRouting;
    private readonly IPingProbeService _probes;
    private readonly IDropLogService _dropLog;

    public VpnDoctorContextFactory(
        IPolicyRoutingService routing, IWgLiveReader wg, IInterfaceHealthService links, INftApplyService nft,
        IFirewallService fw, IRouteOracleService routes, IVpnRoutingService vpnRouting, IPingProbeService probes, IDropLogService dropLog)
    {
        _routing = routing; _wg = wg; _links = links; _nft = nft; _fw = fw;
        _routes = routes; _vpnRouting = vpnRouting; _probes = probes; _dropLog = dropLog;
    }

    public VpnDoctorContext Create(WgServer server, IReadOnlyList<WgPeer> peers, string probeTarget, CancellationToken ct) =>
        new(server, peers, probeTarget, _routing, _wg, _links, _nft, _fw, _routes, _vpnRouting, _probes, _dropLog, ct);
}
