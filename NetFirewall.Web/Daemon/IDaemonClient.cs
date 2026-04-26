using NetFirewall.Models;
using NetFirewall.Models.System;

namespace NetFirewall.Web.Daemon;

/// <summary>
/// Tiny client-side surface over the daemon's HTTP-on-Unix-socket API.
/// All calls forward the current user's session token via the configured header
/// so the daemon can authenticate the request against <c>user_sessions</c>.
/// </summary>
public interface IDaemonClient
{
    /// <summary><c>POST /v1/network/{id}/apply</c></summary>
    Task<ServiceResponse<NetworkApplyResult>> ApplyInterfaceAsync(Guid interfaceId, CancellationToken ct = default);

    /// <summary><c>POST /v1/network/restart</c></summary>
    Task<ServiceResponse<NetworkApplyResult>> RestartNetworkingAsync(CancellationToken ct = default);

    /// <summary><c>POST /v1/routes/{id}/apply</c></summary>
    Task<ServiceResponse<NetworkApplyResult>> ApplyRouteAsync(Guid routeId, CancellationToken ct = default);

    /// <summary><c>POST /v1/routes/{id}/remove</c></summary>
    Task<ServiceResponse<NetworkApplyResult>> RemoveRouteAsync(Guid routeId, CancellationToken ct = default);

    /// <summary>Lightweight health probe (no auth on the daemon side).</summary>
    Task<bool> IsAliveAsync(CancellationToken ct = default);
}
