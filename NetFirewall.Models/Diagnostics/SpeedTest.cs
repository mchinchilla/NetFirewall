using System.Text.Json.Serialization;

namespace NetFirewall.Models.Diagnostics;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum SpeedTestMode
{
    /// <summary>Seconds-long burst: every connection re-requests the source until the time or byte cap ends it.</summary>
    Burst,
    /// <summary>
    /// Endurance: download the source ONCE, to the last byte, split into HTTP Range
    /// chunks across the connections, resuming a chunk when a connection drops.
    /// Bounded by a time limit in minutes, so a whole ISO fits.
    /// </summary>
    FullFile
}

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
    bool KeepFile = false,
    SpeedTestMode Mode = SpeedTestMode.Burst,
    /// <summary><see cref="SpeedTestMode.FullFile"/> only: give up (and keep nothing) after this long.</summary>
    int TimeLimitMinutes = 60);

public sealed record SpeedTestSource(string Id, string Name, string Url);

/// <summary>
/// Curated test servers. Every URL serves a large static payload over HTTPS. In a
/// burst it is fetched repeatedly until the duration or byte cap is hit, so the
/// file size only has to be "big enough"; a full download fetches it once. The
/// ISO entries use the distributions' stable "latest/Current" names — Fedora and
/// Debian version their file names, so those go through a custom URL.
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
        new("iso-tumbleweed", "ISO · openSUSE Tumbleweed DVD (~4.5 GB)", "https://download.opensuse.org/tumbleweed/iso/openSUSE-Tumbleweed-DVD-x86_64-Current.iso"),
        new("iso-alma9",      "ISO · AlmaLinux 9 minimal (~2 GB)",       "https://repo.almalinux.org/almalinux/9/isos/x86_64/AlmaLinux-9-latest-x86_64-minimal.iso"),
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
    string? Warning = null,
    SpeedTestMode Mode = SpeedTestMode.Burst,
    /// <summary>Full download: the source's size, when the server sent one.</summary>
    long? TotalBytes = null,
    /// <summary>Full download: every byte of the source arrived.</summary>
    bool Complete = false,
    /// <summary>Slowest whole second after the first 3 (TCP slow start excluded).</summary>
    double? LowestMbps = null,
    /// <summary>Whole seconds in which nothing arrived, after the first byte — the provider stalled.</summary>
    int StallSeconds = 0,
    /// <summary>Times a dropped connection was re-opened and its chunk resumed.</summary>
    int Reconnects = 0)
{
    public double? ProgressPct => TotalBytes is > 0 ? Math.Min(100, Bytes * 100.0 / TotalBytes.Value) : null;

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
