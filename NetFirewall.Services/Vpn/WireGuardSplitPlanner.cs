using NetFirewall.Models.Firewall;
using NetFirewall.Models.Vpn;

namespace NetFirewall.Services.Vpn;

/// <summary>What splitting a dual-role interface will do — shown as a dry run, then executed.</summary>
public sealed record WgSplitPlan(
    string SourceName,
    string ServerName,
    int ListenPort,
    IReadOnlyList<string> AddressesToServer,
    IReadOnlyList<string> AddressesKept,
    IReadOnlyList<WgPeer> PeersToServer,
    IReadOnlyList<WgPeer> PeersKept,
    IReadOnlyList<string> HandRulesToReview,
    IReadOnlyList<string> Blockers)
{
    public bool CanExecute => Blockers.Count == 0;
}

/// <summary>
/// Plans the split of a legacy dual-role interface (it listens for road warriors AND dials a
/// provider/site). Direction, proven on a real kernel: the interface KEEPS its name as the
/// OUTBOUND link — everything egress (route table, fwmark, policy rule, hand mangle/NAT rows) is
/// keyed to that name — and the SERVER role moves to a new interface with the SAME private key and
/// listen port, so issued client configs stay valid (active clients re-handshake in ~15 s).
/// Addresses can't be inferred safely: those holding a client's tunnel address go to the server
/// by default; the operator confirms. Pure.
/// </summary>
public static class WireGuardSplitPlanner
{
    public static WgSplitPlan Plan(
        WgServer source,
        IReadOnlyList<WgPeer> peers,
        IReadOnlyCollection<string> takenNames,
        Guid? sourceIfaceId,
        IReadOnlyList<FwFilterRule> filterRules,
        IReadOnlyList<FwNatRule> natRules,
        IReadOnlyCollection<string>? chosenServerAddresses = null)
    {
        var blockers = new List<string>();
        if (WgInterfaceRole.Classify(source, peers) != WgRole.DualRole)
            blockers.Add($"{source.Name} isn't doing both jobs — there is nothing to split.");

        var inbound = peers.Where(IsInbound).ToList();
        var kept = peers.Where(p => !IsInbound(p)).ToList();
        var addresses = (source.AddressCidr ?? string.Empty)
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

        var toServer = chosenServerAddresses is { Count: > 0 }
            ? addresses.Where(a => chosenServerAddresses.Contains(a)).ToList()
            : addresses.Where(a => inbound.Any(p => p.AllowedIps.Any(ip => Covers(a, ip)))).ToList();
        var keptAddresses = addresses.Except(toServer).ToList();
        if (toServer.Count == 0) blockers.Add("Pick the address the VPN server keeps (its clients' subnet).");
        if (keptAddresses.Count == 0) blockers.Add($"{source.Name} needs an address for its outbound tunnel — leave the provider-assigned one there.");
        if (source.ListenPort <= 0 && inbound.Count == 0) blockers.Add("No listener and no inbound peers: nothing to move.");

        // Hand-written rows that point at the interface: after the split they still mean the
        // OUTBOUND link. The ones meant for road warriors must be repointed by the operator.
        var hand = new List<string>();
        if (sourceIfaceId is { } iid)
        {
            hand.AddRange(filterRules
                .Where(f => !IsManaged(f.Description) && (f.InterfaceInId == iid || f.InterfaceOutId == iid))
                .Select(f => $"Filter rule ({f.Chain}) “{f.Description ?? f.Id.ToString()[..8]}”"));
            hand.AddRange(natRules
                .Where(n => !IsManaged(n.Description) && n.OutputInterfaceId == iid)
                .Select(n => $"NAT rule ({n.Type}) “{n.Description ?? n.SourceNetwork ?? n.Id.ToString()[..8]}”"));
        }

        return new WgSplitPlan(source.Name, WgInterfaceRole.NextServerName(takenNames), source.ListenPort,
            toServer, keptAddresses, inbound, kept, hand, blockers);
    }

    /// <summary>Peers the SERVER keeps: road warriors and sites that dial in (no endpoint).</summary>
    internal static bool IsInbound(WgPeer p) =>
        p.Role == "client" || (p.Role == "site" && string.IsNullOrWhiteSpace(p.Endpoint));

    private static bool IsManaged(string? d) =>
        d is not null && (d.StartsWith(VpnRoutingService.AutoTag, StringComparison.Ordinal)
                          || d.StartsWith(VpnRoutingService.EgressTag, StringComparison.Ordinal));

    /// <summary>Does interface address "10.10.0.1/24" cover a client's "10.10.0.5/32"?</summary>
    internal static bool Covers(string interfaceCidr, string clientCidr)
    {
        if (!TryParse(interfaceCidr, out var net, out var len) || !TryParse(clientCidr, out var ip, out _)) return false;
        var mask = len == 0 ? 0u : uint.MaxValue << (32 - len);
        return (net & mask) == (ip & mask);
    }

    private static bool TryParse(string cidr, out uint addr, out int len)
    {
        addr = 0; len = 32;
        var slash = cidr.IndexOf('/');
        var host = slash < 0 ? cidr : cidr[..slash];
        if (slash >= 0 && !int.TryParse(cidr[(slash + 1)..], out len)) return false;
        if (!System.Net.IPAddress.TryParse(host, out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;
        Span<byte> b = stackalloc byte[4];
        ip.TryWriteBytes(b, out _);
        addr = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(b);
        return len is >= 0 and <= 32;
    }
}
