namespace NetFirewall.Web.Models;

/// <summary>
/// Typed model for the reusable <c>_KpiCard</c> partial.
/// Keep view models alongside the views that use them; do NOT put view-only
/// shapes in NetFirewall.Models (which is shared across services).
/// </summary>
public sealed class KpiCardViewModel
{
    public required string Label { get; init; }
    public required string Value { get; init; }
    public string? ValueSuffix { get; init; }
    public string? Delta { get; init; }
    public string? DeltaContext { get; init; }
    public DeltaTrend Trend { get; init; } = DeltaTrend.Neutral;

    /// <summary>Inline SVG path data for the icon shown in the top-right badge.</summary>
    public required string IconPath { get; init; }
}

public enum DeltaTrend { Up, Down, Neutral }
