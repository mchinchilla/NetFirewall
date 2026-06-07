using NetFirewall.Models.Vpn;

namespace NetFirewall.Services.Vpn;

/// <summary>
/// Bridges the WireGuard subsystem (wg_servers/wg_peers) to the policy-routing +
/// firewall subsystems (route tables, policy rules, traffic marks, mangle rules,
/// NAT/forward rules). This is the ONLY place that knows how a tunnel maps onto
/// those rows, so the WireGuard UI can stay self-contained.
///
/// SAFETY: every write is discover-then-create / idempotent. It must NEVER clobber
/// hand-seeded production rows (tekium's live wg0 routing). Rows it creates itself
/// are tagged (description prefixes) so they can be round-tripped and removed
/// without touching operator-authored rules.
/// </summary>
public interface IVpnRoutingService
{
    // ── Phase C: routing scaffold ──

    /// <summary>
    /// Idempotently ensure the policy-routing scaffold for <paramref name="server"/>
    /// exists: an FwInterface(VPN, name), an FwRouteTable(name), a wg0 FwTrafficMark,
    /// an FwPolicyRule(fwmark→table), and a default FwStaticRoute(dev name, table).
    /// ADOPTS an existing mark/table/policy-rule if present (never assumes a value),
    /// so re-running on a configured box is a no-op. Returns the resolved scaffold.
    /// </summary>
    Task<VpnScaffold> EnsureRoutingScaffoldAsync(WgServer server, CancellationToken ct = default);

    // ── Phase B: which LAN devices egress via the tunnel ──

    /// <summary>The LAN source CIDRs currently routed into the tunnel (read back from
    /// the mangle rules whose mark routes to the tunnel's table). Empty if no scaffold.</summary>
    Task<IReadOnlyList<string>> GetEgressSourcesAsync(WgServer server, CancellationToken ct = default);

    /// <summary>Replace the set of LAN sources that egress via the tunnel. Diffs against
    /// the VPN-managed mangle rule(s) only — hand-authored mangle rules are untouched.
    /// Ensures the scaffold first.</summary>
    Task SetEgressSourcesAsync(WgServer server, IReadOnlyList<string> sourceCidrs, CancellationToken ct = default);

    // ── Phase D: per-peer NAT/forward (server mode) ──

    /// <summary>
    /// Ensure the NAT (masquerade) + FORWARD rules a connected peer needs to reach
    /// the LAN / internet per its RouteMode (full/split/restricted/site). Generates
    /// FwNatRule/FwFilterRule rows tagged [vpn-auto], deduped against existing rows.
    /// </summary>
    Task EnsurePeerForwardingAsync(WgServer server, WgPeer peer, CancellationToken ct = default);

    /// <summary>Remove the [vpn-auto] NAT/forward rows created for a peer (on delete).</summary>
    Task RemovePeerForwardingAsync(WgServer server, WgPeer peer, CancellationToken ct = default);
}

/// <summary>The resolved policy-routing scaffold for a tunnel — what the egress
/// panel and per-peer rules hang off of.</summary>
public sealed record VpnScaffold(
    Guid InterfaceId,
    string TableName,
    int TableId,
    long Fwmark,
    Guid TrafficMarkId);
