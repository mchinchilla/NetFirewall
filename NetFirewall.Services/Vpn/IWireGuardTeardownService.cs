using NetFirewall.Models.Vpn;

namespace NetFirewall.Services.Vpn;

/// <summary>
/// Impact analysis + orderly removal of a WireGuard interface and everything
/// hanging off it. DB-side only — the caller (controller) is responsible for
/// stopping the live interface via the daemon FIRST and re-applying nftables
/// afterwards so the deleted rows leave the live ruleset too.
/// </summary>
public interface IWireGuardTeardownService
{
    /// <summary>What deleting <paramref name="server"/> would touch — powers the
    /// confirmation dialog. Read-only.</summary>
    Task<WgTeardownImpact> ComputeImpactAsync(WgServer server, CancellationToken ct = default);

    /// <summary>
    /// Remove the interface and its dependents, in dependency order:
    /// auto-generated ([vpn-auto]/[vpn-egress]) NAT/forward/mangle rules are
    /// deleted; hand-authored rules referencing the interface are DISABLED (not
    /// deleted — their FK is SET NULL, so left enabled they would silently widen
    /// their match); the policy-routing scaffold (static routes, policy rule,
    /// traffic marks, route table, interface row) is removed; VPN alerts are
    /// resolved and health state dropped; finally the wg_servers row goes
    /// (peers + health history cascade). Returns the impact that was acted on.
    /// </summary>
    Task<WgTeardownImpact> TeardownAsync(WgServer server, CancellationToken ct = default);
}
