using System.Text;
using NetFirewall.Models.Vpn;

namespace NetFirewall.Services.Vpn;

public sealed class WireGuardConfigService : IWireGuardConfigService
{
    public string GenerateServerConfig(WgServer server, IReadOnlyList<WgPeer> peers)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# NetFirewall WireGuard server config");
        sb.AppendLine($"# Generated: {DateTime.UtcNow:O}");
        sb.AppendLine();
        sb.AppendLine("[Interface]");
        sb.AppendLine($"PrivateKey = {server.PrivateKey}");
        sb.AppendLine($"Address    = {server.AddressCidr}");
        sb.AppendLine($"ListenPort = {server.ListenPort}");
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
            sb.AppendLine($"AllowedIPs = {string.Join(", ", p.AllowedIps)}");
            if (p.PersistentKeepalive is { } ka && ka > 0)
                sb.AppendLine($"PersistentKeepalive = {ka}");
        }

        return sb.ToString();
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
