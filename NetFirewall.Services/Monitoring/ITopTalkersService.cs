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

    /// <summary>
    /// Top N destinations a single host talked to in the last <paramref name="hours"/>
    /// hours, enriched with ASN/org from <c>ip_asn_cache</c>. A row with a null
    /// <see cref="TopTalkerDestination.DstIp"/> is the "others" rollup (the tail
    /// beyond the sampler's per-host Top-N).
    /// </summary>
    Task<IReadOnlyList<TopTalkerDestination>> GetTopDestinationsForHostAsync(
        IPAddress srcIp, int hours, int limit, CancellationToken ct = default);

    /// <summary>
    /// Top N destinations across the WHOLE LAN (all hosts combined) in the last
    /// <paramref name="hours"/> hours, enriched with ASN/org. Powers the home
    /// dashboard's "where traffic is going" panel. Excludes the per-host "others"
    /// rollup rows (dst_ip NULL) so the list is concrete destinations only.
    /// </summary>
    Task<IReadOnlyList<TopTalkerDestination>> GetTopDestinationsGlobalAsync(
        int hours, int limit, CancellationToken ct = default);
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

public sealed record TopTalkerDestination(
    IPAddress? DstIp,       // null = the "others" rollup row
    string? Asn,            // "AS14618" — null if not resolved / rollup
    string? Org,            // "Amazon.com, Inc." — null if not resolved / rollup
    string? Country,        // ISO-3166 alpha-2 — null if not resolved / rollup
    long BytesIn,
    long BytesOut,
    int FlowCount);
