namespace NetFirewall.Web.Models.Vpn;

/// <summary>
/// Backs the "which devices egress via the tunnel" panel on the VPN page. Shows the
/// currently-routed sources, the available DHCP leases (for a host picker) and LAN
/// subnets, so the operator can assign egress with clicks instead of editing mangle
/// rules by hand.
/// </summary>
public sealed class VpnEgressViewModel
{
    public required string TunnelName { get; init; }              // "wg0"
    public required bool ScaffoldReady { get; init; }             // false → show enable CTA

    /// <summary>Source CIDRs currently egressing via the tunnel (union of all mangle
    /// rules on the tunnel's mark — includes hand-authored ones).</summary>
    public required IReadOnlyList<string> CurrentSources { get; init; }

    /// <summary>Active DHCP leases for the host picker.</summary>
    public required IReadOnlyList<EgressHost> Leases { get; init; }

    /// <summary>LAN subnets (CIDR) the operator can route wholesale.</summary>
    public required IReadOnlyList<string> LanSubnets { get; init; }
}

public sealed record EgressHost(string Ip, string? Hostname, string Mac);
