namespace NetFirewall.Web.Models.Monitoring;

/// <summary>
/// Host model for the reusable <c>_WanTrafficCharts</c> partial. The series
/// themselves are fetched by Alpine from <see cref="SeriesUrl"/> so the same
/// markup can live on the dashboard (compact) and Monitoring (full) without
/// duplicating Chart.js wiring.
/// </summary>
public sealed class WanTrafficChartsViewModel
{
    public string SeriesUrl { get; init; } = "/Monitoring/wan-traffic-series";
    public int IntervalMs { get; init; } = 5000;
    public int Minutes { get; init; } = 15;
    public bool Compact { get; init; }
    public string Heading { get; init; } = "WAN traffic";
    public string? Subheading { get; init; }
    public string ManageUrl { get; init; } = "/Network/Interfaces";

    public static WanTrafficChartsViewModel Dashboard(string? manageUrl = null) => new()
    {
        Compact = true,
        Minutes = 15,
        IntervalMs = 5000,
        Heading = "WAN traffic",
        Subheading = "Live download / upload per WAN · last 15 min",
        ManageUrl = manageUrl ?? "/Network/Interfaces"
    };

    public static WanTrafficChartsViewModel Monitoring(string? manageUrl = null) => new()
    {
        Compact = false,
        Minutes = 15,
        IntervalMs = 5000,
        Heading = "WAN traffic",
        Subheading = "Live ↓ download / ↑ upload per WAN · last 15 min · 5s samples",
        ManageUrl = manageUrl ?? "/Network/Interfaces"
    };

    public string SeriesUrlWithMinutes =>
        SeriesUrl.Contains('?', StringComparison.Ordinal)
            ? $"{SeriesUrl}&minutes={Minutes}"
            : $"{SeriesUrl}?minutes={Minutes}";
}
