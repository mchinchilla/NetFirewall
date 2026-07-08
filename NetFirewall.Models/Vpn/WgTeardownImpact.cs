namespace NetFirewall.Models.Vpn;

/// <summary>
/// Everything deleting a WireGuard interface will touch — computed BEFORE the
/// teardown so the confirmation dialog can show the operator exactly what they
/// are about to lose, and returned by the teardown itself as the record of what
/// was acted on.
/// </summary>
public sealed class WgTeardownImpact
{
    public required string InterfaceName { get; init; }

    /// <summary>Upstream / site-to-site peers that will be deleted (cascade).</summary>
    public string[] TunnelNames { get; init; } = Array.Empty<string>();

    /// <summary>Road-warrior client peers that will be deleted (cascade). Their
    /// configs stop working permanently — private keys are not recoverable.</summary>
    public string[] ClientNames { get; init; } = Array.Empty<string>();

    /// <summary>Auto-generated rows this teardown deletes outright ([vpn-auto] /
    /// [vpn-egress] tagged NAT, forward and mangle rules).</summary>
    public int AutoNatRuleCount { get; init; }
    public int AutoForwardRuleCount { get; init; }
    public int EgressMangleRuleCount { get; init; }

    /// <summary>LAN sources currently routed out through the tunnel — they fall
    /// back to the normal WAN(s) after teardown.</summary>
    public string[] EgressSources { get; init; } = Array.Empty<string>();

    /// <summary>Policy-routing scaffold pieces found (and removed on teardown).</summary>
    public bool HasInterfaceRow { get; init; }
    public bool HasRouteTable { get; init; }
    public bool HasPolicyRule { get; init; }
    public int TrafficMarkCount { get; init; }
    public int StaticRouteCount { get; init; }

    /// <summary>Hand-authored rules that reference the interface. NOT deleted —
    /// they are DISABLED, because their FK is ON DELETE SET NULL: left enabled
    /// they would silently lose their interface scope and start matching more
    /// traffic than the operator intended.</summary>
    public WgOrphanRule[] OrphanedRules { get; init; } = Array.Empty<WgOrphanRule>();

    /// <summary>Active VPN alerts that will be resolved as part of the teardown.</summary>
    public int ActiveAlertCount { get; init; }
}

/// <summary>A hand-authored rule that references the interface being deleted.</summary>
/// <param name="Kind">"filter" | "nat" | "port-forward"</param>
/// <param name="Name">Best available display name (description or id).</param>
public sealed record WgOrphanRule(string Kind, string Name);
