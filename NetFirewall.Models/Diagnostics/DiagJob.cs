using System.Text.Json.Serialization;

namespace NetFirewall.Models.Diagnostics;

/// <summary>
/// The two phase-2 tools that outlive a request: they mutate the box (a temporary
/// nftables table) or write a file, run for up to a minute, and are polled by the
/// UI. Admin-only, step-up gated, audited at start, stop and download.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum DiagJobKind
{
    Trace,
    Capture
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum DiagJobState
{
    Running,
    Completed,
    /// <summary>Stopped early by the operator — the partial result is kept.</summary>
    Cancelled,
    Failed
}

/// <summary>Immutable view of a job, safe to hand out while the job is still running.</summary>
public sealed record DiagJobSnapshot(
    Guid Id,
    DiagJobKind Kind,
    DiagJobState State,
    DateTime StartedAtUtc,
    DateTime? FinishedAtUtc,
    int ElapsedMs,
    string? RequestedBy,
    string Subject,
    /// <summary>Events (trace) or packets (capture) collected so far.</summary>
    int ItemCount,
    bool Truncated,
    string? Message,
    /// <summary>Set once the job is done; shape depends on <see cref="Kind"/>.</summary>
    TraceResult? Trace = null,
    CaptureResult? Capture = null)
{
    public bool IsRunning => State == DiagJobState.Running;
}

// ───────────────────────── flow inspector ─────────────────────────

/// <summary>
/// Which packets to trace. At least one of the matchers must be set: an unfiltered
/// trace on a live firewall floods the kernel log and costs real throughput.
/// </summary>
public sealed record TraceRequest(
    string? Src = null,
    string? Dst = null,
    string? Protocol = null,
    int? Port = null,
    string? Interface = null,
    int DurationSec = 20,
    int MaxEvents = 500);

/// <summary>
/// One line of <c>nft monitor trace</c>. A packet's whole journey shares a
/// <see cref="TraceId"/>: the <c>packet</c> line describes it, each <c>rule</c>
/// line is a rule it was tested against, and <c>verdict</c>/<c>policy</c> says
/// what finally happened to it.
/// </summary>
public sealed record TraceEvent(
    string TraceId,
    string Family,
    string Table,
    string Chain,
    /// <summary>packet | rule | verdict | policy</summary>
    string Kind,
    string Detail,
    string Raw);

public sealed record TraceResult(
    IReadOnlyList<TraceEvent> Events,
    /// <summary>The matchers that were installed, as nft syntax — shown so the operator can see exactly what was traced.</summary>
    string RuleSpec,
    bool Truncated,
    int DroppedLines,
    string? Error = null)
{
    public int PacketCount => Events.Select(e => e.TraceId).Distinct().Count();
}

// ───────────────────────── packet capture ─────────────────────────

public sealed record CaptureRequest(
    string Interface,
    string? Filter = null,
    int DurationSec = 20,
    int MaxPackets = 500,
    int Snaplen = 262144);

public sealed record CaptureResult(
    /// <summary>Download name; the file itself lives under the daemon's capture directory, keyed by job id.</summary>
    string FileName,
    long SizeBytes,
    int PacketsCaptured,
    /// <summary>First lines of <c>tcpdump -r</c> so the operator can see what landed without downloading.</summary>
    IReadOnlyList<string> Preview,
    bool ReachedLimit,
    string? Error = null);
