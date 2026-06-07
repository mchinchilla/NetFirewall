using System.ComponentModel.DataAnnotations;

namespace NetFirewall.Web.Models.Vpn;

public sealed class WgServerFormViewModel
{
    public Guid? Id { get; set; }

    /// <summary>"server" (accepts inbound peers) or "client" (this firewall dials
    /// out to a remote wg server — e.g. egress through a friend's US VPN).</summary>
    [Required, RegularExpression("server|client", ErrorMessage = "Mode must be 'server' or 'client'.")]
    public string Mode { get; set; } = "server";

    [Required, StringLength(64)]
    public string Name { get; set; } = "wg0";

    // ListenPort only matters in server mode; in client mode the kernel picks an
    // ephemeral source port. Not [Required] because client mode ignores it; the
    // controller validates it server-side only when Mode == "server".
    [Range(1, 65535, ErrorMessage = "Port must be 1-65535.")]
    public int ListenPort { get; set; } = 51820;

    [Required, RegularExpression(@"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$", ErrorMessage = "Address must be CIDR (e.g. 10.10.0.1/24).")]
    public string AddressCidr { get; set; } = "10.10.0.1/24";

    // ── client-mode extras (the firewall as a client to a remote server) ──
    /// <summary>Remote server "host:port" — REQUIRED in client mode. Stored on the
    /// single peer that represents the upstream server.</summary>
    [RegularExpression(@"^[^\s:]+:\d{1,5}$", ErrorMessage = "Endpoint must be host:port (e.g. vpn.example.com:51820).")]
    public string? RemoteEndpoint { get; set; }

    /// <summary>Client-side AllowedIPs (what to route INTO the tunnel). Default
    /// 0.0.0.0/0 = everything (so marked LAN devices can egress via the tunnel).</summary>
    public string? ClientAllowedIpsRaw { get; set; } = "0.0.0.0/0";

    [Range(0, 65535)]
    public int? ClientKeepalive { get; set; } = 25;

    /// <summary>DNS pushed via the tunnel [Interface] (client mode) / advertised to
    /// clients (server mode). Comma-separated. Optional.</summary>
    [StringLength(200)]
    public string? Dns { get; set; }

    [Range(1280, 9000, ErrorMessage = "MTU must be 1280-9000.")]
    public int? Mtu { get; set; }

    /// <summary>Emit "Table = off" so wg-quick does NOT install its own routes —
    /// required when policy routing (fwmark→table) owns the default route to wg0.
    /// Forced ON in client mode when a routing scaffold is active.</summary>
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

    [Required, StringLength(80)]
    public string Name { get; set; } = string.Empty;

    [Required]
    public string AllowedIpsRaw { get; set; } = string.Empty;  // comma-separated CIDRs

    [Range(0, 65535)]
    public int? PersistentKeepalive { get; set; }

    /// <summary>"host:port" of the remote side. Required when the parent server is
    /// in client mode (the peer IS the upstream server); optional otherwise.</summary>
    [RegularExpression(@"^[^\s:]+:\d{1,5}$", ErrorMessage = "Endpoint must be host:port.")]
    public string? Endpoint { get; set; }

    /// <summary>Per-peer routing intent (server mode): full | split | restricted | site.</summary>
    [RegularExpression("full|split|restricted|site")]
    public string RouteMode { get; set; } = "full";

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
/// Bundle for the live-status partial (server + per-peer wg-show stats +
/// catalog of peers so we can map pubkey → name).
/// </summary>
public sealed class WgStatusViewModel
{
    public required NetFirewall.Models.Vpn.WgServer? Server { get; init; }
    public required IReadOnlyList<NetFirewall.Models.Vpn.WgPeerLiveStatus> Status { get; init; }
    public required IReadOnlyList<NetFirewall.Models.Vpn.WgPeer> Peers { get; init; }
}
