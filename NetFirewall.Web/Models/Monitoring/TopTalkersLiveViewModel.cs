using NetFirewall.Web.Models;

namespace NetFirewall.Web.Models.Monitoring;

/// <summary>
/// View model for the Monitoring page's live top-talkers panel. Refreshed
/// via HTMX every 30s (same cadence as the daemon's ConntrackSampler).
/// Reuses <see cref="TopTalkerRow"/> from the home dashboard so the partial
/// markup is identical.
/// </summary>
public sealed class TopTalkersLiveViewModel
{
    public IReadOnlyList<TopTalkerRow> Hosts { get; init; } = [];
    public IReadOnlyList<TopTalkerRow> Services { get; init; } = [];

    public static readonly TopTalkersLiveViewModel Empty = new();
}
