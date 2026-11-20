using NetFirewall.Web.Models.Vpn;

namespace NetFirewall.Web.Services;

/// <summary>Builds the on-demand detail panel of a WireGuard peer row (Tunnels / VPN clients grids).</summary>
public interface IWgPeerDetailService
{
    Task<WgPeerDetailViewModel?> GetAsync(Guid peerId, CancellationToken ct = default);
}
