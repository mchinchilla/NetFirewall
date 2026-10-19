namespace NetFirewall.Models.Diagnostics;

/// <summary>
/// One WAN speed test: the daemon downloads from a test server through the
/// chosen uplink (steered by its probe fwmark, never by interface — policy
/// routing ignores the interface) and measures what arrived.
/// </summary>
public sealed record SpeedTestRequest(
    /// <summary>WAN interface name; the daemon looks up its probe fwmark in wan_health_config.</summary>
    string Wan,
    /// <summary>Id from <see cref="SpeedTestSources.All"/>, or <see cref="SpeedTestSources.CustomId"/> with <see cref="CustomUrl"/>.</summary>
    string SourceId,
    string? CustomUrl = null,
    int DurationSec = 10,
    int MaxMegabytes = 500,
    int Streams = 4,
    /// <summary>Keep the downloaded file for <c>SpeedTestRetentionHours</c> so it can be pulled to a LAN client.</summary>
    bool KeepFile = false);

public sealed record SpeedTestSource(string Id, string Name, string Url);

/// <summary>
/// Curated test servers. Every URL serves a large static payload over HTTPS and
/// is fetched repeatedly until the duration or byte cap is hit, so the file
/// size only has to be "big enough", not "big enough for the fastest link".
/// </summary>
public static class SpeedTestSources
{
    public const string CustomId = "custom";

    public static readonly IReadOnlyList<SpeedTestSource> All =
    [
        new("cloudflare",   "Cloudflare (nearest PoP)",   "https://speed.cloudflare.com/__down?bytes=100000000"),
        new("hetzner-ash",  "Hetzner · Ashburn, US",      "https://ash-speed.hetzner.com/1GB.bin"),
        new("hetzner-hil",  "Hetzner · Hillsboro, US",    "https://hil-speed.hetzner.com/1GB.bin"),
        new("hetzner-fsn",  "Hetzner · Falkenstein, DE",  "https://fsn1-speed.hetzner.com/1GB.bin"),
        new("ovh-rbx",      "OVH · Roubaix, FR",          "https://proof.ovh.net/files/1Gb.dat"),
    ];

    public static SpeedTestSource? Find(string? id) =>
        All.FirstOrDefault(s => string.Equals(s.Id, id, StringComparison.Ordinal));
}

public sealed record SpeedTestResult(
    string Wan,
    long Fwmark,
    string Source,
    string Url,
    int Streams,
    long Bytes,
    double Seconds,
    double AvgMbps,
    double PeakMbps,
    /// <summary>Request sent → first body byte, fastest stream.</summary>
    double? TtfbMs,
    /// <summary>Throughput of each whole second, in order.</summary>
    IReadOnlyList<double> SamplesMbps,
    bool ReachedByteCap,
    /// <summary>
    /// Bytes the WAN received during the test that were not ours (rx counter delta
    /// minus our bytes) — other users sharing the uplink. Null when the counter
    /// could not be read.
    /// </summary>
    long? OtherTrafficBytes = null,
    SpeedTestFile? File = null,
    string? Error = null,
    /// <summary>Something that makes the number less trustworthy (a stream failed mid-test) without voiding it.</summary>
    string? Warning = null)
{
    public double? OtherTrafficMbps => OtherTrafficBytes is { } b && Seconds > 0 ? b * 8 / Seconds / 1_000_000 : null;
}

/// <summary>A downloaded payload kept on the firewall until <see cref="ExpiresAtUtc"/>.</summary>
public sealed record SpeedTestFile(
    Guid Id,
    string FileName,
    long SizeBytes,
    /// <summary>False when the test ended before the first response finished — the file is a prefix of the source.</summary>
    bool Complete,
    string Wan,
    string Source,
    double AvgMbps,
    DateTime CreatedAtUtc,
    DateTime ExpiresAtUtc,
    string? RequestedBy,
    /// <summary>Bytes written ÷ time spent inside writes. Null when nothing was written.</summary>
    double? DiskWriteMbps = null,
    /// <summary>Writes took most of the writing stream's time: the disk, not the WAN, may have been the limit.</summary>
    bool DiskLimited = false)
{
    public bool IsExpired(DateTime nowUtc) => nowUtc >= ExpiresAtUtc;
}
