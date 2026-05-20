using NetFirewall.Web.Models;

namespace NetFirewall.Web.Models.Monitoring;

/// <summary>
/// View model for the live top-talkers panel — used both on the Monitoring
/// page and the home dashboard, refreshed via HTMX. The window is selectable
/// (1h / 6h / 24h / 7d); <see cref="Range"/> drives the active button + title.
/// Reuses <see cref="TopTalkerRow"/> so the partial markup is identical.
/// </summary>
public sealed class TopTalkersLiveViewModel
{
    public IReadOnlyList<TopTalkerRow> Hosts { get; init; } = [];
    public IReadOnlyList<TopTalkerRow> Services { get; init; } = [];

    /// <summary>The selected window token: "1h", "6h", "24h" or "7d".</summary>
    public string Range { get; init; } = "24h";

    /// <summary>The window tokens offered by the selector, in display order.</summary>
    public static readonly string[] Ranges = ["1h", "6h", "24h", "7d"];

    /// <summary>Maps a range token to hours for the daemon query. Defaults to 24h.</summary>
    public static int RangeToHours(string? range) => range switch
    {
        "1h" => 1,
        "6h" => 6,
        "7d" => 168,
        _ => 24,
    };

    public static readonly TopTalkersLiveViewModel Empty = new();
}
