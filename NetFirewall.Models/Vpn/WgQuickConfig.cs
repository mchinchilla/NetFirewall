namespace NetFirewall.Models.Vpn;

/// <summary>
/// The key-free view of a wg-quick <c>.conf</c> — what the operator may paste into
/// the VPN doctor's "compare with issued config" box. PrivateKey and PresharedKey
/// are deliberately absent from the shape so they can never be persisted or logged.
/// </summary>
public sealed record WgQuickConfig(
    string? Address,
    string? Dns,
    int? Mtu,
    int? ListenPort,
    string? Table,
    IReadOnlyList<WgQuickPeer> Peers);

public sealed record WgQuickPeer(
    string? PublicKey,
    string? Endpoint,
    IReadOnlyList<string> AllowedIps,
    int? PersistentKeepalive);
