using NetFirewall.Web.Models.Network;

namespace NetFirewall.Web.Services;

/// <summary>
/// Builds the single <see cref="WanHealthCardViewModel"/> consumed by every
/// WAN-health surface (failover page, Monitoring pod, Home dashboard). Centralizes
/// the daemon→DTO→view-model mapping + DB fallback that used to be copy-pasted
/// across three controllers, so there is exactly one source of truth.
/// </summary>
public interface IWanHealthCardBuilder
{
    /// <summary>
    /// Build the card model. Prefers the daemon's cooked health state (hysteresis
    /// applied); on a daemon miss falls back to a DB-direct read so the card still
    /// renders. <paramref name="options"/> drives presentation only — the data is
    /// identical regardless of which surface asks.
    /// </summary>
    Task<WanHealthCardViewModel> BuildAsync(WanCardOptions options, CancellationToken ct = default);
}
