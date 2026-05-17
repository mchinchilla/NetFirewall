using NetFirewall.Models.Vpn;
using NetFirewall.Services.Firewall;

namespace NetFirewall.Services.Vpn;

/// <summary>
/// Privileged wrapper around <c>wg</c> + <c>wg-quick</c>. Lives in the daemon
/// because bringing the WireGuard interface up requires CAP_NET_ADMIN.
/// </summary>
public interface IWireGuardApplyService
{
    /// <summary>Generates a fresh X25519 keypair via <c>wg genkey | wg pubkey</c>.</summary>
    Task<(string Private, string Public)> GenerateKeyPairAsync(CancellationToken ct = default);

    /// <summary>Generates a 32-byte preshared key via <c>wg genpsk</c>.</summary>
    Task<string> GeneratePresharedKeyAsync(CancellationToken ct = default);

    /// <summary>
    /// Derives the public key for a given private key by piping it through
    /// <c>wg pubkey</c>. Used by the importer when reading an existing
    /// <c>[Interface]</c> block that only stores the private key.
    /// </summary>
    Task<string> DerivePublicKeyAsync(string privateKey, CancellationToken ct = default);

    /// <summary>
    /// Writes the rendered server config to <c>/etc/wireguard/{name}.conf</c>
    /// (mode 0600) then either brings the interface up (first apply) or
    /// hot-reloads peers via <c>wg syncconf</c> (preserves existing handshakes).
    /// </summary>
    Task<NftApplyResult> ApplyAsync(WgServer server, IReadOnlyList<WgPeer> peers, CancellationToken ct = default);

    /// <summary>Parses <c>wg show {name} dump</c> output into per-peer live status.</summary>
    Task<IReadOnlyList<WgPeerLiveStatus>> GetStatusAsync(string interfaceName, CancellationToken ct = default);

    /// <summary>Brings the WireGuard interface down (<c>wg-quick down</c>). Idempotent.</summary>
    Task<NftApplyResult> StopAsync(string interfaceName, CancellationToken ct = default);
}
