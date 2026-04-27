using NetFirewall.Models.Vpn;

namespace NetFirewall.Services.Vpn;

/// <summary>
/// Pure-text config generators for both sides of a WireGuard tunnel.
/// No IO, no process spawning — what gets written to <c>/etc/wireguard/wg0.conf</c>
/// vs what's handed to the user as a client config is the same shape, only the
/// roles flip.
/// </summary>
public interface IWireGuardConfigService
{
    /// <summary>
    /// Generates the server's <c>wg-quick</c> config (Interface block + one
    /// Peer block per enabled peer). The server's private key is included
    /// because this file lives in <c>/etc/wireguard/</c> with mode 0600.
    /// </summary>
    string GenerateServerConfig(WgServer server, IReadOnlyList<WgPeer> peers);

    /// <summary>
    /// Generates a peer's client config. The peer's PRIVATE key has to be
    /// supplied by the caller — we never persist it server-side, so it must
    /// be passed through in-memory once at peer-creation time.
    /// </summary>
    /// <param name="endpoint">Public host/IP of the WireGuard server (e.g. "vpn.example.com").</param>
    /// <param name="clientAddressCidr">The address assigned to this peer inside the tunnel (e.g. "10.10.0.2/32").</param>
    /// <param name="clientAllowedIps">What the client routes through the tunnel (e.g. ["0.0.0.0/0"] for full tunnel).</param>
    string GenerateClientConfig(
        WgServer server,
        WgPeer peer,
        string clientPrivateKey,
        string endpoint,
        string clientAddressCidr,
        IReadOnlyList<string> clientAllowedIps,
        string? clientDns = null);
}
