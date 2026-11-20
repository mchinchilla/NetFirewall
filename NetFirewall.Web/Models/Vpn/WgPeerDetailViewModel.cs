namespace NetFirewall.Web.Models.Vpn;

/// <summary>
/// Expanded row of the WireGuard peer grids. A copy of the peer's config WITHOUT secrets:
/// the preshared key is reduced to <see cref="HasPresharedKey"/>, and there is no private
/// key on the server to begin with (client keys are handed out once at creation).
/// </summary>
public sealed record WgPeerDetailViewModel
{
    public required Guid Id { get; init; }
    public required string Name { get; init; }
    public required string Role { get; init; }
    public string? Description { get; init; }
    public bool Enabled { get; init; }
    public required string PublicKey { get; init; }
    public bool HasPresharedKey { get; init; }
    public string? Endpoint { get; init; }
    public IReadOnlyList<string> AllowedIps { get; init; } = [];
    public int? PersistentKeepalive { get; init; }
    public string? RouteMode { get; init; }
    public bool AllowInternet { get; init; }
    public IReadOnlyList<string> AllowedSubnets { get; init; } = [];
    public DateTime CreatedAt { get; init; }

    /// <summary>The peer as <c>wg show</c> sees it right now; null when the daemon did not list it.</summary>
    public NetFirewall.Models.Vpn.WgPeerLiveStatus? Live { get; init; }

    /// <summary>Why live status is missing (daemon down / disabled); null when the daemon answered.</summary>
    public string? LiveError { get; init; }

    public DateTime NowUtc { get; init; } = DateTime.UtcNow;
}
