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

    /// <summary>Inline SVG path data for the circular tint disc.</summary>
    public required string IconPath { get; init; }

    /// <summary>Hue of the icon disc so a KPI row reads as distinct vitals.</summary>
    public KpiTint Tint { get; init; } = KpiTint.Accent;

    /// <summary>Left-rail severity (CPU/mem thresholds, saturated pools, …).</summary>
    public KpiSeverity Severity { get; init; } = KpiSeverity.Normal;
}

public enum DeltaTrend { Up, Down, Neutral }

public enum KpiTint { Accent, Coral, Mint, Blue, Violet, Gold }

public enum KpiSeverity { Normal, Warning, Critical }

/// <summary>Live sparkline vital (CPU / Memory) on the dashboard.</summary>
public sealed class VitalCardViewModel
{
    public required string Field { get; init; }
    public required string Label { get; init; }
    public required string IconPath { get; init; }
    public KpiTint Tint { get; init; } = KpiTint.Coral;
    public string Unit { get; init; } = "%";
    public string Caption { get; init; } = "Last 60 min · % used";
}
