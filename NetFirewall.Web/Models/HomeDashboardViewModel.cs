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

    public IReadOnlyList<RecentActivity> RecentActivity { get; init; } = [];
    public IReadOnlyList<SubnetSummary> Subnets { get; init; } = [];

    /// <summary>systemd units (daemon, web, nginx, postgres, …) with active/failed state.</summary>
    public IReadOnlyList<SystemServiceStatus> Services { get; init; } = [];
    /// <summary>WAN reachability snapshot — one row per configured WAN interface.</summary>
    public IReadOnlyList<WanStatusSummary> WanStatus { get; init; } = [];
    /// <summary>Per-kind (nftables/tc/wireguard) pending change counts vs last successful Apply.</summary>
    public IReadOnlyList<PendingApplySummary> PendingChanges { get; init; } = [];
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

public sealed class RecentActivity
{
    public required string Title { get; init; }
    public required string Detail { get; init; }
    public required ActivitySeverity Severity { get; init; }
    public required DateTime Timestamp { get; init; }
}

public enum ActivitySeverity { Success, Info, Warning, Danger, Neutral }

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
