namespace NetFirewall.Models.Diagnostics;

/// <summary>One row of <c>diag_runs</c>: who ran which tool, with what, and what came back.</summary>
public sealed class DiagRun
{
    public Guid Id { get; set; }
    public string Tool { get; set; } = string.Empty;
    public string Status { get; set; } = DiagRunStatus.Running;
    public DateTime StartedAt { get; set; }
    public DateTime? FinishedAt { get; set; }
    public int? DurationMs { get; set; }
    public string? RequestedBy { get; set; }
    public string? Target { get; set; }
    /// <summary>Request as JSON (secrets already redacted by the caller).</summary>
    public string ParamsJson { get; set; } = "{}";
    /// <summary>Tool result as JSON; null while running or when the result exceeded the size cap.</summary>
    public string? ResultJson { get; set; }
    public bool ResultTruncated { get; set; }
    public string? Summary { get; set; }
}

/// <summary>Tool identifiers as stored in <c>diag_runs.tool</c> and used in routes.</summary>
public static class DiagTools
{
    public const string Ping        = "ping";
    public const string Traceroute  = "traceroute";
    public const string RouteGet    = "route-get";
    public const string Conntrack   = "conntrack";
    public const string DropLog     = "drop-log";
    public const string IfaceHealth = "iface-health";
    public const string Sysctl      = "sysctl";
    public const string VpnDoctor   = "vpn-doctor";
    public const string VpnProbe    = "vpn-probe";
    public const string VpnCompare  = "vpn-compare";
    public const string WanDoctor   = "wan-doctor";
    public const string DhcpDoctor  = "dhcp-doctor";
    public const string DnsDoctor   = "dns-doctor";

    public static readonly IReadOnlyList<string> All =
        [Ping, Traceroute, RouteGet, Conntrack, DropLog, IfaceHealth, Sysctl,
         VpnDoctor, VpnProbe, VpnCompare, WanDoctor, DhcpDoctor, DnsDoctor];
}

/// <summary>
/// <c>diag_runs.status</c>. <c>ok/warn/fail</c> mean the tool RAN and that is its
/// verdict (a ping with 100 % loss is <c>fail</c>, not <c>error</c>); the rest mean
/// it did not complete.
/// </summary>
public static class DiagRunStatus
{
    public const string Running = "running";
    public const string Ok      = "ok";
    public const string Warn    = "warn";
    public const string Fail    = "fail";
    public const string Error   = "error";
    public const string Timeout = "timeout";
    /// <summary>Never persisted — the concurrency gate refused the run.</summary>
    public const string Busy    = "busy";

    public static readonly IReadOnlyList<string> Persisted = [Running, Ok, Warn, Fail, Error, Timeout];

    /// <summary>True when the tool completed and produced a verdict.</summary>
    public static bool IsVerdict(string status) => status is Ok or Warn or Fail;
}

/// <summary>History page filters. Null = no constraint.</summary>
public sealed record DiagRunFilter(
    string? Tool = null,
    string? Status = null,
    DateTime? From = null,
    DateTime? To = null,
    string? RequestedBy = null);
