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

/// <summary>
/// Cooked connectivity verdict for a single peer, used to colour the status
/// dot. Mirrors the server-side health logic in the daemon's
/// VpnHealthMonitorService — keep the two in sync so the live dot and the
/// background "VPN down" alerting agree on what "down" means.
/// </summary>
public enum WgPeerHealth
{
    /// <summary>Fresh handshake — the tunnel is carrying traffic. Green.</summary>
    Connected,

    /// <summary>The peer is enabled and *should* be live (client-mode tunnel, or
    /// a peer with persistent keepalive) but its handshake is stale or it never
    /// handshook. This is a real outage — e.g. the remote endpoint's IP changed.
    /// Red.</summary>
    Down,

    /// <summary>State we can't call an outage: the peer is disabled, or it's an
    /// idle inbound peer with no keepalive (a laptop that's simply switched off).
    /// A stale handshake here is expected, not a failure. Grey.</summary>
    Idle,
}

/// <summary>
/// Pure (no-IO) helper that classifies a peer's live status into a
/// <see cref="WgPeerHealth"/>. Lives here so the typed verdict is computed in C#,
/// not inline in the Razor view (project rule #7 — views compose, they don't
/// decide). Stateless + deterministic, so it stays a static utility rather than
/// a DI service per rule #8's pure-function exception.
/// </summary>
public static class WgPeerHealthEvaluator
{
    /// <summary>
    /// A handshake older than this (or never) means the peer is not actively
    /// connected. WireGuard renews the handshake roughly every 2 min while
    /// traffic flows (and keepalive keeps it alive when idle), so 3 min is a
    /// comfortable "definitely not talking" threshold with no false negatives.
    /// </summary>
    public static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(3);

    /// <param name="server">Owning server (its Mode decides whether the tunnel
    /// is expected to stay up on its own).</param>
    /// <param name="peer">The catalog row (Enabled + PersistentKeepalive), or null
    /// when wg reports a pubkey we have no DB row for.</param>
    /// <param name="live">The live wg-show stats for this peer.</param>
    /// <param name="nowUtc">Current time (passed in to keep this pure/testable).</param>
    public static WgPeerHealth Evaluate(
        NetFirewall.Models.Vpn.WgServer server,
        NetFirewall.Models.Vpn.WgPeer? peer,
        NetFirewall.Models.Vpn.WgPeerLiveStatus live,
        DateTime nowUtc)
    {
        var fresh = live.LastHandshakeAt is { } h && (nowUtc - h) < StaleAfter;
        if (fresh) return WgPeerHealth.Connected;

        // Disabled peers are never an outage — the operator turned them off.
        if (peer is { Enabled: false }) return WgPeerHealth.Idle;

        // "Should be live" = either this firewall dials OUT (client mode keeps a
        // single always-on tunnel to the upstream), or the peer pins a keepalive
        // (so it's expected to handshake continuously even when idle). Anything
        // else is a quiet inbound peer where a stale handshake is normal.
        var clientMode = server.Mode.Equals("client", StringComparison.OrdinalIgnoreCase);
        var hasKeepalive = peer is { PersistentKeepalive: > 0 };

        return clientMode || hasKeepalive ? WgPeerHealth.Down : WgPeerHealth.Idle;
    }
}
