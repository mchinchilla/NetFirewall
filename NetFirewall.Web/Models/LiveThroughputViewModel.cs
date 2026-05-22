namespace NetFirewall.Web.Models;

/// <summary>
/// Live throughput pulse for the dashboard — refreshed every few seconds via
/// HTMX. Sits alongside the (static, hourly) 24h traffic chart to give the page
/// a real-time heartbeat without re-rendering the Chart.js canvas.
/// </summary>
public sealed class LiveThroughputViewModel
{
    /// <summary>Aggregate inbound rate across non-loopback interfaces, Mbps.</summary>
    public double InMbps { get; init; }

    /// <summary>Aggregate outbound rate across non-loopback interfaces, Mbps.</summary>
    public double OutMbps { get; init; }

    /// <summary>Per-interface rates, busiest first, for the small breakdown.</summary>
    public IReadOnlyList<InterfaceRate> PerInterface { get; init; } = [];

    /// <summary>Set when the snapshot couldn't be read (daemon/host issue).</summary>
    public bool Unavailable { get; init; }
}

public sealed record InterfaceRate(string Name, double InMbps, double OutMbps);
