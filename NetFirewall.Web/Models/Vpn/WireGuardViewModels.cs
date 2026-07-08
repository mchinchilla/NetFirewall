using System.ComponentModel.DataAnnotations;

namespace NetFirewall.Web.Models.Vpn;

public sealed class WgServerFormViewModel
{
    public Guid? Id { get; set; }

    /// <summary>Linux interface name (e.g. wg0). IMMUTABLE after creation — the
    /// controller ignores this field on update (a rename would orphan the on-disk
    /// config, the policy-routing table, and the live interface). 15 chars is the
    /// kernel's IFNAMSIZ limit.</summary>
    [RegularExpression(@"^[A-Za-z0-9_.\-]{1,15}$", ErrorMessage = "1-15 chars: letters, digits, dot, dash, underscore.")]
    public string Name { get; set; } = "wg0";

    /// <summary>UDP port the interface listens on for inbound peers (clients /
    /// site links that dial us). 0 = don't listen — a dial-only interface whose
    /// kernel picks an ephemeral source port. Independent of whether the
    /// interface also dials upstream tunnels (it can do both at once).</summary>
    [Range(0, 65535, ErrorMessage = "Port must be 0-65535 (0 = don't accept inbound).")]
    public int ListenPort { get; set; } = 51820;

    [Required, RegularExpression(@"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$", ErrorMessage = "Address must be CIDR (e.g. 10.10.0.1/24).")]
    public string AddressCidr { get; set; } = "10.10.0.1/24";

    /// <summary>DNS for the tunnel [Interface]. Comma-separated. Optional.</summary>
    [StringLength(200)]
    public string? Dns { get; set; }

    [Range(1280, 9000, ErrorMessage = "MTU must be 1280-9000.")]
    public int? Mtu { get; set; }

    /// <summary>Emit "Table = off" so wg-quick does NOT install its own routes —
    /// required when policy routing (fwmark→table) owns the default route to wg0.
    /// The controller forces it ON whenever an enabled upstream tunnel exists.</summary>
    public bool TableOff { get; set; }

    [StringLength(500)]
    public string? PostUp { get; set; }

    [StringLength(500)]
    public string? PostDown { get; set; }

    public bool Enabled { get; set; } = true;

    /// <summary>Pre-existing keys (re-displayed on edit). Empty on first save → server generates.</summary>
    public string? PrivateKey { get; set; }
    public string? PublicKey  { get; set; }
}

public sealed class WgPeerFormViewModel
{
    public Guid? Id { get; set; }
    public Guid ServerId { get; set; }

    /// <summary>What the peer IS: 'client' (inbound road-warrior — keys generated
    /// on-device, no endpoint), 'upstream' (remote server we dial — endpoint +
    /// pasted public key required) or 'site' (site-to-site link). Decides which
    /// form variant renders and how Save shapes the entity.</summary>
    [Required, RegularExpression("client|upstream|site", ErrorMessage = "Role must be client, upstream or site.")]
    public string Role { get; set; } = "client";

    [Required, StringLength(80)]
    public string Name { get; set; } = string.Empty;

    [Required]
    public string AllowedIpsRaw { get; set; } = string.Empty;  // comma-separated CIDRs

    [Range(0, 65535)]
    public int? PersistentKeepalive { get; set; }

    /// <summary>"host:port" of the remote side. Required for upstream tunnels
    /// (we dial them); optional for site links; unused for clients.</summary>
    [RegularExpression(@"^[^\s:]+:\d{1,5}$", ErrorMessage = "Endpoint must be host:port.")]
    public string? Endpoint { get; set; }

    /// <summary>Remote side's PUBLIC key — tunnels only (upstream/site), pasted by
    /// the operator. Client peers get a daemon-generated keypair instead.</summary>
    [RegularExpression(@"^[A-Za-z0-9+/]{42,44}={0,2}$", ErrorMessage = "Public key must be a 44-char base64 WireGuard key.")]
    public string? PublicKey { get; set; }

    /// <summary>Client LAN-access intent: split (whole LAN) | restricted (only
    /// AllowedSubnets) | none. 'full' is accepted as a legacy synonym of split;
    /// 'site' is set by the controller for site-role tunnels.</summary>
    [RegularExpression("full|split|restricted|site|none")]
    public string RouteMode { get; set; } = "split";

    /// <summary>Internet axis, independent of LAN access: masquerade + forward to
    /// the WAN scoped to this client's tunnel IP. Clients only.</summary>
    public bool AllowInternet { get; set; }

    /// <summary>Comma/newline-separated LAN subnets for split/restricted/site modes.</summary>
    public string? AllowedSubnetsRaw { get; set; }

    [StringLength(500)]
    public string? Description { get; set; }

    public bool Enabled { get; set; } = true;

    /// <summary>Optional — when supplied the server pins this; when empty the daemon generates one.</summary>
    public string? PresharedKey { get; set; }
}

/// <summary>
/// Returned by the Save action on peer create — bundles the keys + rendered
/// client config so the view can render the QR + a download button. The
/// client private key is shown ONCE; we never persist it.
/// </summary>
public sealed class WgPeerCreatedViewModel
{
    public required Guid PeerId { get; init; }
    public required string PeerName { get; init; }
    public required string ClientConfig { get; init; }
}

/// <summary>
/// Typed model for the peers-table partial. Family decides the columns and
/// labels: "clients" (road-warriors: access intent, QR/export) vs "tunnels"
/// (upstream/site: role badge + endpoint).
/// </summary>
public sealed class WgPeerTableViewModel
{
    public required string Family { get; init; }   // "clients" | "tunnels"
    public required IReadOnlyList<NetFirewall.Models.Vpn.WgPeer> Peers { get; init; }
}

/// <summary>
/// Bundle for the live-status partial (server + per-peer wg-show stats +
/// catalog of peers so we can map pubkey → name).
/// </summary>
public sealed class WgStatusViewModel
{
    public required NetFirewall.Models.Vpn.WgServer? Server { get; init; }
    public required IReadOnlyList<NetFirewall.Models.Vpn.WgPeerLiveStatus> Status { get; init; }
    public required IReadOnlyList<NetFirewall.Models.Vpn.WgPeer> Peers { get; init; }
}

// WgPeerHealth + WgPeerHealthEvaluator moved to NetFirewall.Models/Vpn/WgPeerHealth.cs
// so the daemon's VpnHealthMonitorService and this project's status dot share ONE
// health rule instead of two copies kept in sync by hand.
