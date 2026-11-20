using NetFirewall.Services.Daemon;
using NetFirewall.Services.Vpn;
using NetFirewall.Web.Models.Vpn;

namespace NetFirewall.Web.Services;

/// <summary>
/// The peer from <see cref="IWireGuardService"/> joined by public key with the daemon's live
/// <c>wg show</c> status. Fail-soft: a daemon that is down blanks the live card, never the config.
/// Secrets are dropped here, so no view can render them.
/// </summary>
public sealed class WgPeerDetailService(IWireGuardService wg, IDaemonClient daemon) : IWgPeerDetailService
{
    public async Task<WgPeerDetailViewModel?> GetAsync(Guid peerId, CancellationToken ct = default)
    {
        var p = await wg.GetPeerByIdAsync(peerId, ct);
        if (p is null) return null;

        // Live status of the peer's OWN interface (keys are only unique per interface).
        var server = await wg.GetServerByIdAsync(p.ServerId, ct);
        var status = server is null
            ? NetFirewall.Models.ServiceResponse<IReadOnlyList<NetFirewall.Models.Vpn.WgPeerLiveStatus>>.Ok([], "No interface.")
            : await daemon.GetWireGuardStatusAsync(server.Name, ct);
        var live = status.Success
            ? status.Data?.FirstOrDefault(s => string.Equals(s.PublicKey, p.PublicKey, StringComparison.Ordinal))
            : null;

        return new WgPeerDetailViewModel
        {
            Id = p.Id,
            Name = p.Name,
            Role = string.IsNullOrEmpty(p.Role) ? "client" : p.Role.ToLowerInvariant(),
            Description = p.Description,
            Enabled = p.Enabled,
            PublicKey = p.PublicKey,
            HasPresharedKey = !string.IsNullOrEmpty(p.PresharedKey),
            Endpoint = p.Endpoint,
            AllowedIps = p.AllowedIps,
            PersistentKeepalive = p.PersistentKeepalive,
            RouteMode = p.RouteMode,
            AllowInternet = p.AllowInternet,
            AllowedSubnets = p.AllowedSubnets,
            CreatedAt = p.CreatedAt,
            Live = live,
            LiveError = status.Success ? null : status.Message,
        };
    }
}
