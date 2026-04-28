using NetFirewall.Services.Daemon;
using NetFirewall.Models;
using NetFirewall.Models.System;
using NetFirewall.Services.Network;

namespace NetFirewall.Web.Daemon;

/// <summary>
/// <see cref="IStaticRouteApplicator"/> implementation that hands route
/// apply / remove off to the daemon. The local in-process applicator stays
/// behind the Daemon client only as a fallback that we currently don't use
/// — when <c>Daemon:Enabled = false</c>, the Web registers the original
/// <see cref="StaticRouteApplicator"/> directly.
/// </summary>
public sealed class DaemonStaticRouteApplicator : IStaticRouteApplicator
{
    private readonly IDaemonClient _daemon;

    public DaemonStaticRouteApplicator(IDaemonClient daemon) => _daemon = daemon;

    public Task<ServiceResponse<NetworkApplyResult>> ApplyAsync(Guid routeId, CancellationToken ct = default)
        => _daemon.ApplyRouteAsync(routeId, ct);

    public Task<ServiceResponse<NetworkApplyResult>> RemoveAsync(Guid routeId, CancellationToken ct = default)
        => _daemon.RemoveRouteAsync(routeId, ct);
}
