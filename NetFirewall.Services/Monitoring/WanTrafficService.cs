using NetFirewall.Services.Firewall;

namespace NetFirewall.Services.Monitoring;

/// <summary>
/// Live per-WAN download/upload series for the reusable traffic charts.
/// History comes from <c>system_metrics_net</c>; the latest point is the
/// instantaneous /proc snapshot so the line moves even between collector ticks.
/// </summary>
public interface IWanTrafficService
{
    Task<IReadOnlyList<WanLiveSeries>> GetLiveAsync(int minutes, CancellationToken ct = default);
}

/// <summary>One WAN's live up/down series, already in Mbps for the UI.</summary>
public sealed class WanLiveSeries
{
    public string Name { get; init; } = "";
    public string Label { get; init; } = "";
    public string? Role { get; init; }
    public string[] Labels { get; init; } = [];
    public double[] InSeries { get; init; } = [];
    public double[] OutSeries { get; init; } = [];
    public double InMbps { get; init; }
    public double OutMbps { get; init; }
}

public sealed class WanTrafficService : IWanTrafficService
{
    public const int DefaultMinutes = 15;
    public const int MinMinutes = 1;
    public const int MaxMinutes = 60;
    internal const int MaxPoints = 240;

    private const double BytesToMbps = 8.0 / 1_000_000;

    private readonly IFirewallService _firewall;
    private readonly IMetricsQueryService _query;
    private readonly ISystemMonitorService _monitor;

    public WanTrafficService(
        IFirewallService firewall,
        IMetricsQueryService query,
        ISystemMonitorService monitor)
    {
        _firewall = firewall;
        _query = query;
        _monitor = monitor;
    }

    public async Task<IReadOnlyList<WanLiveSeries>> GetLiveAsync(int minutes, CancellationToken ct = default)
    {
        minutes = Math.Clamp(minutes, MinMinutes, MaxMinutes);

        var ifacesTask = _firewall.GetInterfacesAsync(ct);
        var historyTask = _query.GetWanRatePerInterfaceAsync(minutes, ct);
        var snapTask = SafeSnapshotAsync(ct);
        await Task.WhenAll(ifacesTask, historyTask, snapTask);

        var wans = (await ifacesTask)
            .Where(i => i.Enabled && string.Equals(i.Type, "WAN", StringComparison.OrdinalIgnoreCase))
            .OrderBy(i => i.Role ?? "", StringComparer.OrdinalIgnoreCase)
            .ThenBy(i => i.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var history = (await historyTask)
            .ToDictionary(s => s.InterfaceName, s => s.Points, StringComparer.OrdinalIgnoreCase);

        var snap = await snapTask;
        var liveByName = (snap?.Network ?? [])
            .ToDictionary(n => n.InterfaceName, n => n, StringComparer.OrdinalIgnoreCase);

        var now = snap?.Timestamp ?? DateTime.UtcNow;
        var result = new List<WanLiveSeries>(wans.Count);

        foreach (var wan in wans)
        {
            var points = history.TryGetValue(wan.Name, out var hist)
                ? hist.ToList()
                : new List<WanInterfaceRatePoint>();

            if (liveByName.TryGetValue(wan.Name, out var live))
            {
                var livePoint = new WanInterfaceRatePoint(
                    now,
                    live.BytesReceivedPerSecond,
                    live.BytesSentPerSecond);
                if (points.Count == 0 || now - points[^1].Timestamp > TimeSpan.FromSeconds(2))
                    points.Add(livePoint);
                else
                    points[^1] = livePoint;
            }

            points = Downsample(points, MaxPoints);

            var inSeries = points.Select(p => Math.Round(p.RxBytesPerSec * BytesToMbps, 2)).ToArray();
            var outSeries = points.Select(p => Math.Round(p.TxBytesPerSec * BytesToMbps, 2)).ToArray();
            var labels = points
                .Select(p => DateTime.SpecifyKind(p.Timestamp, DateTimeKind.Utc).ToLocalTime().ToString("HH:mm"))
                .ToArray();

            result.Add(new WanLiveSeries
            {
                Name = wan.Name,
                Label = RoleLabel(wan.Role),
                Role = wan.Role,
                Labels = labels,
                InSeries = inSeries,
                OutSeries = outSeries,
                InMbps = inSeries.Length == 0 ? 0 : inSeries[^1],
                OutMbps = outSeries.Length == 0 ? 0 : outSeries[^1],
            });
        }

        return result;
    }

    private async Task<SystemMetricsSnapshot?> SafeSnapshotAsync(CancellationToken ct)
    {
        try { return await _monitor.GetSnapshotAsync(ct); }
        catch { return null; }
    }

    internal static string RoleLabel(string? role) => role switch
    {
        "primary_wan" => "Primary",
        "secondary_wan" => "Secondary",
        _ => "WAN"
    };

    internal static List<WanInterfaceRatePoint> Downsample(List<WanInterfaceRatePoint> src, int max)
    {
        if (src.Count <= max) return src;
        var step = (double)src.Count / max;
        var list = new List<WanInterfaceRatePoint>(max);
        for (var i = 0; i < max; i++)
            list.Add(src[(int)(i * step)]);
        list[^1] = src[^1];
        return list;
    }
}
