namespace NetFirewall.Web.Models.Monitoring;

/// <summary>
/// LAN-wide "where traffic is going" panel for the home dashboard — the busiest
/// destinations across all hosts, ASN-enriched. Replaces the old (mostly empty)
/// auth-events "Recent activity" panel. Auto-refreshed via HTMX.
/// </summary>
public sealed class TopDestinationsViewModel
{
    public IReadOnlyList<HostDestinationRow> Destinations { get; init; } = [];

    /// <summary>Set when the lookup failed, so the partial shows an inline note.</summary>
    public string? Error { get; init; }
}
