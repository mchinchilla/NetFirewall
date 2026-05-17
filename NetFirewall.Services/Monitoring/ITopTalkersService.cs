using System.Net;

namespace NetFirewall.Services.Monitoring;

/// <summary>
/// Aggregates <c>lan_traffic_samples</c> for the dashboard. Two views:
/// top hosts (group by src_ip) and top services (group by proto+dport).
/// </summary>
public interface ITopTalkersService
{
    /// <summary>Top N hosts by total bytes (in+out) in the last <paramref name="hours"/> hours.</summary>
    Task<IReadOnlyList<TopTalkerHost>> GetTopHostsAsync(int hours, int limit, CancellationToken ct = default);

    /// <summary>Top N services by total bytes in the last <paramref name="hours"/> hours.</summary>
    Task<IReadOnlyList<TopTalkerService>> GetTopServicesAsync(int hours, int limit, CancellationToken ct = default);
}

public sealed record TopTalkerHost(
    IPAddress SrcIp,
    long BytesIn,
    long BytesOut,
    int FlowCount,
    string? Hostname);

public sealed record TopTalkerService(
    string Proto,
    int? DstPort,
    string? ServiceName,    // "https", "http", "sip", "dns" — null if unknown port
    long BytesIn,
    long BytesOut,
    int FlowCount);
