using NetFirewall.Models;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.System;

namespace NetFirewall.Services.Network;

/// <summary>
/// Cross-cutting "save route → reflect on the live system" flow. Hides the
/// orchestration (fetch route, fetch iface, regenerate config via the right
/// writer, optionally hot-add via <c>ip route</c>) so controllers stay thin
/// and so route management can be re-used by the setup wizard.
/// </summary>
public interface IStaticRouteApplicator
{
    /// <summary>
    /// Regenerates the owning interface's config so it includes all currently-enabled
    /// routes for that interface, then hot-adds <em>this</em> route so it takes
    /// effect without restarting networking.
    /// </summary>
    Task<ServiceResponse<NetworkApplyResult>> ApplyAsync(Guid routeId, CancellationToken ct = default);

    /// <summary>
    /// Removes a route from the live routing table (best effort) and regenerates
    /// the owning interface's config so the route does not come back at boot.
    /// </summary>
    Task<ServiceResponse<NetworkApplyResult>> RemoveAsync(Guid routeId, CancellationToken ct = default);
}
