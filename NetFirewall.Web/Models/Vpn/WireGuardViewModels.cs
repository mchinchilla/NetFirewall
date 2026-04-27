using System.ComponentModel.DataAnnotations;

namespace NetFirewall.Web.Models.Vpn;

public sealed class WgServerFormViewModel
{
    public Guid? Id { get; set; }

    [Required, StringLength(64)]
    public string Name { get; set; } = "wg0";

    [Required, Range(1, 65535, ErrorMessage = "Port must be 1-65535.")]
    public int ListenPort { get; set; } = 51820;

    [Required, RegularExpression(@"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$", ErrorMessage = "Address must be CIDR (e.g. 10.10.0.1/24).")]
    public string AddressCidr { get; set; } = "10.10.0.1/24";

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
