namespace NetFirewall.Web.Models.Monitoring;

/// <summary>
/// Host for the reusable 24h (or N-hour) per-interface traffic chart.
/// Series are fetched by Alpine from <see cref="SeriesUrl"/> so the same
/// partial can live on the dashboard and elsewhere.
/// </summary>
public sealed class InterfaceTrafficChartViewModel
{
    public string SeriesUrl { get; init; } = "/Monitoring/interface-traffic-hourly";
    public int Hours { get; init; } = 24;
    public string Heading { get; init; } = "Traffic — last 24h";
    public string? Subheading { get; init; } = "Per interface · click a name to show or hide";

    public static InterfaceTrafficChartViewModel Last24h() => new();

    public string SeriesUrlWithHours =>
        SeriesUrl.Contains('?', StringComparison.Ordinal)
            ? $"{SeriesUrl}&hours={Hours}"
            : $"{SeriesUrl}?hours={Hours}";
}
