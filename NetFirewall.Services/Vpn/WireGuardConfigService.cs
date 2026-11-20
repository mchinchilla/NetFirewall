using System.Text;
using NetFirewall.Models.Vpn;

namespace NetFirewall.Services.Vpn;

public sealed class WireGuardConfigService : IWireGuardConfigService
{
    public string GenerateServerConfig(WgServer server, IReadOnlyList<WgPeer> peers)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# NetFirewall WireGuard config");
        sb.AppendLine($"# Generated: {DateTime.UtcNow:O}");
        sb.AppendLine();
        sb.AppendLine("[Interface]");
        sb.AppendLine($"PrivateKey = {server.PrivateKey}");
        sb.AppendLine($"Address    = {server.AddressCidr}");
        // ListenPort whenever configured — one interface can dial an upstream
        // AND accept inbound clients at once, so this must not depend on the
        // legacy server-level mode. 0 = dial-only, kernel picks an ephemeral port.
        if (server.ListenPort > 0)
            sb.AppendLine($"ListenPort = {server.ListenPort}");
        if (!string.IsNullOrWhiteSpace(server.Dns))
            sb.AppendLine($"DNS        = {server.Dns}");
        if (server.Mtu is { } mtu && mtu > 0)
            sb.AppendLine($"MTU        = {mtu}");
        // An outbound CLIENT interface never lets wg-quick touch routing: its peer's
        // AllowedIPs is typically 0.0.0.0/0, which would hijack the firewall's own
        // outbound. Traffic reaches it through policy routing (mark → its table) only.
        if (RendersTableOff(server))
            sb.AppendLine("Table      = off");
        if (!string.IsNullOrWhiteSpace(server.PostUp))
            sb.AppendLine($"PostUp     = {server.PostUp}");
        if (!string.IsNullOrWhiteSpace(server.PostDown))
            sb.AppendLine($"PostDown   = {server.PostDown}");

        foreach (var p in peers.Where(p => p.Enabled))
        {
            sb.AppendLine();
            if (!string.IsNullOrEmpty(p.Description))
                sb.AppendLine($"# {p.Name} — {p.Description}");
            else
                sb.AppendLine($"# {p.Name}");
            sb.AppendLine("[Peer]");
            sb.AppendLine($"PublicKey  = {p.PublicKey}");
            if (!string.IsNullOrEmpty(p.PresharedKey))
                sb.AppendLine($"PresharedKey = {p.PresharedKey}");
            sb.AppendLine($"AllowedIPs = {string.Join(", ", PeerAllowedIps(p))}");
            // Endpoint matters most in client mode (we need to know where to
            // send packets). In server mode it's optional but valid for
            // site-to-site keepalive.
            if (!string.IsNullOrWhiteSpace(p.Endpoint))
                sb.AppendLine($"Endpoint   = {p.Endpoint}");
            if (p.PersistentKeepalive is { } ka && ka > 0)
                sb.AppendLine($"PersistentKeepalive = {ka}");
        }

        return sb.ToString();
    }

    /// <summary>Whether wg-quick leaves routing alone for this interface (then NetFirewall owns its routes).</summary>
    public static bool RendersTableOff(WgServer s) => s.TableOff || IsClientKind(s);

    internal static bool IsClientKind(WgServer s) =>
        string.Equals(s.Mode, "client", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// A site link's remote LAN subnets must be in its AllowedIPs too: cryptokey routing drops
    /// every packet whose source (inbound) or destination (outbound) is outside them. They are
    /// appended after the stored list, de-duplicated, so a hand-config that already lists them
    /// renders unchanged.
    /// </summary>
    internal static IEnumerable<string> PeerAllowedIps(WgPeer p)
    {
        var isSite = string.Equals(p.Role, "site", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(p.RouteMode, "site", StringComparison.OrdinalIgnoreCase);
        if (!isSite || p.AllowedSubnets.Length == 0) return p.AllowedIps;
        var seen = new HashSet<string>(p.AllowedIps, StringComparer.OrdinalIgnoreCase);
        return p.AllowedIps.Concat(p.AllowedSubnets.Where(s => !string.IsNullOrWhiteSpace(s) && seen.Add(s.Trim())).Select(s => s.Trim()));
    }

    public string GenerateClientConfig(
        WgServer server,
        WgPeer peer,
        string clientPrivateKey,
        string endpoint,
        string clientAddressCidr,
        IReadOnlyList<string> clientAllowedIps,
        string? clientDns = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"# {peer.Name} — generated {DateTime.UtcNow:O}");
        sb.AppendLine("# Save this on the client and import via the WireGuard app.");
        sb.AppendLine();
        sb.AppendLine("[Interface]");
        sb.AppendLine($"PrivateKey = {clientPrivateKey}");
        sb.AppendLine($"Address    = {clientAddressCidr}");
        if (!string.IsNullOrWhiteSpace(clientDns))
            sb.AppendLine($"DNS        = {clientDns}");

        sb.AppendLine();
        sb.AppendLine("[Peer]");
        sb.AppendLine($"PublicKey  = {server.PublicKey}");
        if (!string.IsNullOrEmpty(peer.PresharedKey))
            sb.AppendLine($"PresharedKey = {peer.PresharedKey}");
        sb.AppendLine($"Endpoint   = {endpoint}:{server.ListenPort}");
        sb.AppendLine($"AllowedIPs = {string.Join(", ", clientAllowedIps)}");
        if (peer.PersistentKeepalive is { } ka && ka > 0)
            sb.AppendLine($"PersistentKeepalive = {ka}");

        return sb.ToString();
    }
}
