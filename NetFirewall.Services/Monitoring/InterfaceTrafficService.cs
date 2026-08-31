namespace NetFirewall.Services.Monitoring;

/// <summary>
/// Hourly per-interface traffic for the 24h chart. WAN interfaces default
/// visible; LAN/VPN/other start hidden so the operator can toggle them in.
/// </summary>
public interface IInterfaceTrafficService
{
    Task<InterfaceTrafficHourly> GetHourlyAsync(int hours, CancellationToken ct = default);
}

public sealed class InterfaceTrafficHourly
{
    public string[] Labels { get; init; } = [];
    public IReadOnlyList<InterfaceTrafficSeries> Interfaces { get; init; } = [];
}

public sealed class InterfaceTrafficSeries
{
    public string Name { get; init; } = "";
    public string Label { get; init; } = "";
    public string Type { get; init; } = "";
    public bool DefaultVisible { get; init; }
    public double[] InMbps { get; init; } = [];
    public double[] OutMbps { get; init; } = [];
    public long TotalBytes { get; init; }
}

public sealed class InterfaceTrafficService : IInterfaceTrafficService
{
    public const int DefaultHours = 24;
    public const int MinHours = 1;
    public const int MaxHours = 168;

    private const double BytesToMbps = 8.0 / 1_000_000;

    private readonly IMetricsQueryService _query;

    public InterfaceTrafficService(IMetricsQueryService query) => _query = query;

    public async Task<InterfaceTrafficHourly> GetHourlyAsync(int hours, CancellationToken ct = default)
    {
        hours = Math.Clamp(hours, MinHours, MaxHours);
        var to = DateTime.UtcNow;
        var from = to.AddHours(-hours);
        var rows = await _query.GetInterfaceTrafficHourlyAsync(from, to, ct);
        if (rows.Count == 0)
            return new InterfaceTrafficHourly();

        var buckets = rows.Select(r => r.Bucket).Distinct().OrderBy(b => b).ToList();
        var labels = buckets
            .Select(b => DateTime.SpecifyKind(b, DateTimeKind.Utc).ToLocalTime().ToString("HH:mm"))
            .ToArray();

        var series = rows
            .GroupBy(r => r.InterfaceName, StringComparer.OrdinalIgnoreCase)
            .Select(g => BuildSeries(g.Key, g.ToList(), buckets))
            .OrderBy(s => TypeRank(s.Type))
            .ThenBy(s => s.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        // If nothing is typed WAN, show everything rather than an empty chart.
        if (series.All(s => !s.DefaultVisible))
        {
            series = series.Select(s => new InterfaceTrafficSeries
            {
                Name = s.Name,
                Label = s.Label,
                Type = s.Type,
                DefaultVisible = true,
                InMbps = s.InMbps,
                OutMbps = s.OutMbps,
                TotalBytes = s.TotalBytes
            }).ToList();
        }

        return new InterfaceTrafficHourly { Labels = labels, Interfaces = series };
    }

    private static InterfaceTrafficSeries BuildSeries(
        string name,
        IReadOnlyList<InterfaceHourlyPoint> points,
        IReadOnlyList<DateTime> buckets)
    {
        var first = points[0];
        var byBucket = points
            .GroupBy(p => p.Bucket)
            .ToDictionary(g => g.Key, g => (
                Rx: g.Sum(x => x.RxBytes),
                Tx: g.Sum(x => x.TxBytes)));

        var inMbps = new double[buckets.Count];
        var outMbps = new double[buckets.Count];
        for (var i = 0; i < buckets.Count; i++)
        {
            if (!byBucket.TryGetValue(buckets[i], out var p)) continue;
            inMbps[i] = Math.Round(p.Rx * BytesToMbps / 3600, 2);
            outMbps[i] = Math.Round(p.Tx * BytesToMbps / 3600, 2);
        }

        var type = string.IsNullOrWhiteSpace(first.Type) ? "other" : first.Type;
        return new InterfaceTrafficSeries
        {
            Name = name,
            Label = SeriesLabel(first.Role, type),
            Type = type,
            DefaultVisible = string.Equals(type, "WAN", StringComparison.OrdinalIgnoreCase),
            InMbps = inMbps,
            OutMbps = outMbps,
            TotalBytes = points.Sum(p => p.RxBytes + p.TxBytes)
        };
    }

    internal static string SeriesLabel(string? role, string type) => role switch
    {
        "primary_wan" => "Primary",
        "secondary_wan" => "Secondary",
        _ => string.IsNullOrWhiteSpace(type) ? "other" : type
    };

    internal static int TypeRank(string type) => type.ToUpperInvariant() switch
    {
        "WAN" => 0,
        "LAN" => 1,
        "VPN" => 2,
        _ => 3
    };
}
