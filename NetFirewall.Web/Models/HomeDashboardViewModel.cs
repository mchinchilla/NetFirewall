namespace NetFirewall.Web.Models;

/// <summary>
/// All data needed by the dashboard's Index view, fetched in one async fan-out
/// in <c>HomeController.Index</c>. Empty arrays/zero counts when the system is
/// fresh — the view renders empty-state messaging.
/// </summary>
public sealed class HomeDashboardViewModel
{
    public int ActiveLeaseCount { get; init; }
    public int InterfaceCount { get; init; }
    public int WanInterfaceCount { get; init; }
    public int EnabledFilterRuleCount { get; init; }
    public int TotalFilterRuleCount { get; init; }
    public double CurrentThroughputMbps { get; init; }

    /// <summary>Total configured WireGuard peers (including disabled).</summary>
    public int WireGuardPeerCount { get; init; }
    /// <summary>Peers whose last handshake is within the last 3 minutes.</summary>
    public int WireGuardActivePeerCount { get; init; }
    /// <summary>True when a wg server row exists (controls whether the KPI shows).</summary>
    public bool WireGuardConfigured { get; init; }

    /// <summary>Total configured schedules (incl. disabled). 0 = no schedules feature in use.</summary>
    public int ScheduleCount { get; init; }
    /// <summary>How many schedules are currently active (in their timezone, day-of-week + window).</summary>
    public int ActiveScheduleCount { get; init; }

    /// <summary>Last 24h network bandwidth — labels + RX/TX series for Chart.js.</summary>
    public string[] TrafficLabels { get; init; } = [];
    public double[] TrafficRxMbps { get; init; } = [];
    public double[] TrafficTxMbps { get; init; } = [];
    public double TrafficAvgInMbps { get; init; }
    public double TrafficAvgOutMbps { get; init; }
    public long TrafficTotalBytes { get; init; }

    public IReadOnlyList<SubnetSummary> Subnets { get; init; } = [];

    /// <summary>systemd units (daemon, web, nginx, postgres, …) with active/failed state.</summary>
    public IReadOnlyList<SystemServiceStatus> Services { get; init; } = [];
    /// <summary>WAN reachability snapshot — one row per configured WAN interface.</summary>
    public IReadOnlyList<WanStatusSummary> WanStatus { get; init; } = [];
    /// <summary>Per-kind (nftables/tc/wireguard) pending change counts vs last successful Apply.</summary>
    public IReadOnlyList<PendingApplySummary> PendingChanges { get; init; } = [];

    /// <summary>Physical/VM host facts shown in the dashboard footer.</summary>
    public HostInfo Host { get; init; } = new();

    // Top talkers (hosts/services) are no longer fetched here — the home
    // dashboard loads them via HTMX from /Monitoring/toptalkers (shared
    // _TopTalkersLive partial) so the window selector works. See Home/Index.cshtml.

    /// <summary>Per-WAN health rows (state + last RTT + consecutive failures).</summary>
    public IReadOnlyList<WanHealthRow> WanHealth { get; init; } = [];
    /// <summary>Recent failover / up / down transitions across all WANs.</summary>
    public IReadOnlyList<WanTransition> WanTransitions { get; init; } = [];
}

public sealed class WanHealthRow
{
    public required string InterfaceName { get; init; }
    public required string Role { get; init; }
    public required bool IsUp { get; init; }
    public int ConsecutiveFailures { get; init; }
    public int ConsecutiveSuccesses { get; init; }
    public DateTime LastCheckAt { get; init; }
    public DateTime LastTransitionAt { get; init; }
    public double? LastRttMs { get; init; }
    public string? LastTarget { get; init; }
    public string? LastError { get; init; }
}

public sealed class WanTransition
{
    public required DateTime OccurredAt { get; init; }
    public required string InterfaceName { get; init; }
    public required string EventType { get; init; }   // up | down | failover | demoted
}

public sealed class TopTalkerRow
{
    public required string Label { get; init; }   // "192.168.99.10" or "tcp/443 (https)"
    public string? Sublabel { get; init; }         // hostname for hosts, flow count for services
    public required long BytesIn { get; init; }
    public required long BytesOut { get; init; }
    public long TotalBytes => BytesIn + BytesOut;
}

/// <summary>Host facts for the dashboard footer — OS, kernel, virt, cores, RAM, uptime.</summary>
public sealed class HostInfo
{
    public string Hostname { get; init; } = "";
    public string OsName { get; init; } = "";
    public string KernelVersion { get; init; } = "";
    public string Virtualization { get; init; } = "";   // "KVM", "bare-metal", …
    public int CoreCount { get; init; }
    public long TotalMemoryBytes { get; init; }
    public TimeSpan Uptime { get; init; }
}

public sealed class SystemServiceStatus
{
    public required string UnitName { get; init; }
    public required string DisplayName { get; init; }
    public required string ActiveState { get; init; }   // active | inactive | failed | activating | unknown
    public string? SubState { get; init; }
    public bool Enabled { get; init; }
    public DateTime? SinceUtc { get; init; }
    /// <summary>active = ok, failed = danger, activating = warning, others = neutral.</summary>
    public string SeverityClass => ActiveState switch
    {
        "active" => "success",
        "failed" => "danger",
        "activating" or "deactivating" => "warning",
        _ => "neutral"
    };
}

public sealed class WanStatusSummary
{
    public required string InterfaceName { get; init; }
    public required string Role { get; init; }
    public string? Target { get; init; }
    public required bool IsUp { get; init; }
    public double? RttMs { get; init; }
    public string? Message { get; init; }
}

public sealed class PendingApplySummary
{
    public required string Kind { get; init; }          // nftables | tc | wireguard
    public DateTime? LastAppliedAt { get; init; }
    public int PendingCount { get; init; }
    public bool HasPending => PendingCount > 0;
}

public sealed class SubnetSummary
{
    public required Guid Id { get; init; }
    public required string Name { get; init; }
    public required string Cidr { get; init; }
    public string? PoolRange { get; init; }
    public int UsedLeases { get; init; }
    public int Capacity { get; init; }
    public double UsagePercent => Capacity > 0 ? (double)UsedLeases / Capacity * 100 : 0;
    public string Status => UsagePercent switch
    {
        >= 90 => "danger",
        >= 75 => "warn",
        _     => "ok"
    };
}
