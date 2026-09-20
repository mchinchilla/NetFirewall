namespace NetFirewall.Models.Diagnostics;

// Result shapes for every tool. Pure records: produced in the daemon, carried in a
// ServiceResponse<DiagRunEnvelope<T>>, persisted as diag_runs.result JSON, and
// rendered by the same Razor partial whether they come from a live run or history.

/// <summary>Uniform wrapper around a tool result: the history row it was stored under plus timing and status.</summary>
public sealed record DiagRunEnvelope<T>(
    Guid RunId,
    DateTime StartedAtUtc,
    int DurationMs,
    string Status,
    T? Result);

// ───────────────────────── ping / traceroute ─────────────────────────

public sealed record PingReply(int Seq, int? Ttl, double TimeMs);

public sealed record PingResult(
    string Target,
    string? ResolvedIp,
    /// <summary>Human description of how the probe was steered: "fwmark 0x500", "iface ens192" or "default route".</summary>
    string Via,
    int Sent,
    int Received,
    double LossPct,
    double? RttMinMs,
    double? RttAvgMs,
    double? RttMaxMs,
    IReadOnlyList<PingReply> Replies,
    string Raw,
    string? Error = null);

public sealed record TracerouteHop(int Hop, string? Ip, string? Host, IReadOnlyList<double> RttMs);

public sealed record TracerouteResult(
    string Target,
    string Via,
    IReadOnlyList<TracerouteHop> Hops,
    bool Reached,
    string Raw,
    string? Error = null);

// ───────────────────────── routing ─────────────────────────

public sealed record RouteGetResult(
    string Target,
    string? Dev,
    string? Gateway,
    string? Src,
    string? Table,
    string? Mark,
    string Raw,
    IReadOnlyList<string> Warnings,
    string? Error = null);

public sealed record IpRuleEntry(int Priority, long? Fwmark, string? Table, string Raw);

public sealed record IpRouteEntry(string Destination, string? Gateway, string? Dev, int? Metric, string Raw);

// ───────────────────────── conntrack ─────────────────────────

public sealed record ConntrackFlow(
    string Proto,
    string Src,
    string Dst,
    int? Sport,
    int? Dport,
    string? State,
    string? Mark,
    long? BytesOrig,
    long? BytesReply,
    /// <summary>Reply-direction tuple as the kernel sees it — reveals NAT (the reply's dst is the address we masqueraded to).</summary>
    string? ReplySrc,
    string? ReplyDst,
    string Raw);

public sealed record ConntrackLookupResult(
    IReadOnlyList<ConntrackFlow> Flows,
    int Total,
    bool Truncated,
    string? Error = null);

// ───────────────────────── kernel drop log ─────────────────────────

public sealed record DropLogEntry(
    DateTime? At,
    string Prefix,
    string? In,
    string? Out,
    string? Src,
    string? Dst,
    string? Proto,
    int? Spt,
    int? Dpt,
    string? Mark,
    string Raw);

public sealed record DropLogTop(string Key, int Count);

public sealed record DropLogResult(
    IReadOnlyList<DropLogEntry> Entries,
    int Scanned,
    bool Truncated,
    IReadOnlyList<DropLogTop> TopPrefixes,
    IReadOnlyList<DropLogTop> TopSources,
    IReadOnlyList<DropLogTop> TopPorts,
    string? Error = null);

// ───────────────────────── interfaces / neighbours ─────────────────────────

public sealed record InterfaceHealth(
    string Name,
    bool Exists,
    string? OperState,
    bool? Carrier,
    int? Mtu,
    IReadOnlyList<string> Addresses,
    string? Speed,
    string? Duplex,
    long RxBytes,
    long TxBytes,
    long RxErrors,
    long TxErrors,
    long RxDropped,
    long TxDropped);

public sealed record NeighborEntry(string Ip, string? Mac, string Dev, string State);

// ───────────────────────── VPN probes ─────────────────────────

public sealed record VpnProbeResult(
    /// <summary>ok | remote-drops | local-routing | replies-dropped | no-handshake | inconclusive</summary>
    string Verdict,
    string Explanation,
    long TxBefore,
    long TxAfter,
    long RxBefore,
    long RxAfter,
    PingResult? PingByMark,
    PingResult? PingByBind);

public sealed record VpnCompareDifference(
    string Field,
    string? Issued,
    string? Ours,
    DiagCheckStatus Severity,
    string Note);

public sealed record VpnCompareResult(
    IReadOnlyList<VpnCompareDifference> Differences,
    DiagCheckStatus Overall);
