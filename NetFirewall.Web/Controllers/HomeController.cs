using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Auth;
using NetFirewall.Services.Dhcp;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Monitoring;
using NetFirewall.Services.Vpn;
using NetFirewall.Services.Daemon;
using NetFirewall.Web.Models;

namespace NetFirewall.Web.Controllers;

public class HomeController : Controller
{
    private readonly IDhcpAdminService _dhcp;
    private readonly IFirewallService _firewall;
    private readonly ISystemMonitorService _monitor;
    private readonly IMetricsQueryService _query;
    private readonly IWireGuardService _wg;
    private readonly IDaemonClient _daemon;
    private readonly IScheduleService _schedules;
    private readonly IAuthAuditService _authAudit;
    private readonly ILogger<HomeController> _logger;

    public HomeController(
        IDhcpAdminService dhcp,
        IFirewallService firewall,
        ISystemMonitorService monitor,
        IMetricsQueryService query,
        IWireGuardService wg,
        IDaemonClient daemon,
        IScheduleService schedules,
        IAuthAuditService authAudit,
        ILogger<HomeController> logger)
    {
        _dhcp = dhcp;
        _firewall = firewall;
        _monitor = monitor;
        _query = query;
        _wg = wg;
        _daemon = daemon;
        _schedules = schedules;
        _authAudit = authAudit;
        _logger = logger;
    }

    public async Task<IActionResult> Index(CancellationToken ct)
    {
        // Fan-out: every source is independent so parallel awaits cut latency.
        var leasesTask     = _dhcp.GetActiveLeasesAsync(ct);
        var subnetsTask    = _dhcp.GetSubnetsAsync(ct);
        var poolsTask      = _dhcp.GetPoolsAsync(null, ct);
        var ifacesTask     = _firewall.GetInterfacesAsync(ct);
        var filterTask     = _firewall.GetFilterRulesAsync(null, ct);
        var snapshotTask   = _monitor.GetSnapshotAsync(ct);
        var historyTask    = SafeQueryHistoryAsync(ct);
        var wgTask         = SafeQueryWireGuardAsync(ct);
        var schedulesTask  = SafeQuerySchedulesAsync(ct);

        // New panels — every daemon call has its own safe-wrapper so the page
        // still renders if the daemon is unreachable or the endpoint 4xx-es.
        var servicesTask   = SafeQueryServicesAsync(ct);
        var wanTask        = SafeQueryWanAsync(ct);
        var pendingTask    = SafeQueryPendingAsync(ct);
        var eventsTask     = SafeQueryCriticalEventsAsync(ct);
        var topTalkersTask = SafeQueryTopTalkersAsync(ct);
        var wanHealthTask  = SafeQueryWanHealthAsync(ct);

        await Task.WhenAll(leasesTask, subnetsTask, poolsTask, ifacesTask,
                           filterTask, snapshotTask, historyTask, wgTask, schedulesTask,
                           servicesTask, wanTask, pendingTask, eventsTask, topTalkersTask, wanHealthTask);

        var leases    = leasesTask.Result;
        var subnets   = subnetsTask.Result;
        var pools     = poolsTask.Result;
        var ifaces    = ifacesTask.Result;
        var filters   = filterTask.Result;
        var snapshot  = snapshotTask.Result;
        var history   = historyTask.Result;
        var wg        = wgTask.Result;
        var sched     = schedulesTask.Result;
        var services  = servicesTask.Result;
        var wanStatus = wanTask.Result;
        var pending   = pendingTask.Result;
        var events    = eventsTask.Result;
        var top       = topTalkersTask.Result;
        var wanHealth = wanHealthTask.Result;

        // Throughput right now = sum of bytes/sec across non-loopback interfaces.
        var totalBytesPerSec = snapshot.Network
            .Where(n => !string.Equals(n.InterfaceName, "lo", StringComparison.OrdinalIgnoreCase))
            .Sum(n => n.BytesReceivedPerSecond + n.BytesSentPerSecond);
        var currentThroughputMbps = Math.Round(totalBytesPerSec * 8 / 1_000_000, 1);

        // Subnet summaries — match leases to subnets via pool ranges.
        var subnetSummaries = BuildSubnetSummaries(subnets, pools, leases);

        var vm = new HomeDashboardViewModel
        {
            ActiveLeaseCount = leases.Count,
            InterfaceCount = ifaces.Count,
            WanInterfaceCount = ifaces.Count(i => string.Equals(i.Type, "WAN", StringComparison.OrdinalIgnoreCase)),
            EnabledFilterRuleCount = filters.Count(r => r.Enabled),
            TotalFilterRuleCount = filters.Count,
            CurrentThroughputMbps = currentThroughputMbps,

            WireGuardConfigured = wg.Configured,
            WireGuardPeerCount = wg.PeerCount,
            WireGuardActivePeerCount = wg.ActivePeerCount,

            ScheduleCount = sched.Total,
            ActiveScheduleCount = sched.ActiveNow,

            TrafficLabels   = history.Labels,
            TrafficRxMbps   = history.RxMbps,
            TrafficTxMbps   = history.TxMbps,
            TrafficAvgInMbps  = history.RxMbps.Length > 0 ? Math.Round(history.RxMbps.Average(), 1) : 0,
            TrafficAvgOutMbps = history.TxMbps.Length > 0 ? Math.Round(history.TxMbps.Average(), 1) : 0,
            TrafficTotalBytes = history.TotalBytes,

            RecentActivity = events,
            Subnets = subnetSummaries,
            Services = services,
            WanStatus = wanStatus,
            PendingChanges = pending,
            TopHosts = top.Hosts,
            TopServices = top.Services,
            WanHealth = wanHealth.Health,
            WanTransitions = wanHealth.Transitions,
        };

        return View(vm);
    }

    public IActionResult Privacy() => View();

    [AllowAnonymous]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }

    // ----- helpers --------------------------------------------------------

    private async Task<ScheduleSnapshot> SafeQuerySchedulesAsync(CancellationToken ct)
    {
        try
        {
            var all = await _schedules.GetAllAsync(ct);
            if (all.Count == 0) return ScheduleSnapshot.Empty;
            var now = DateTimeOffset.UtcNow;
            var active = all.Count(s => s.IsActiveAt(now));
            return new ScheduleSnapshot(Total: all.Count, ActiveNow: active);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Schedule summary unavailable — likely no migration");
            return ScheduleSnapshot.Empty;
        }
    }

    private sealed record ScheduleSnapshot(int Total, int ActiveNow)
    {
        public static readonly ScheduleSnapshot Empty = new(0, 0);
    }

    private async Task<WireGuardSnapshot> SafeQueryWireGuardAsync(CancellationToken ct)
    {
        // wg_servers may not exist (no migration yet) or daemon may be down.
        try
        {
            var server = await _wg.GetServerAsync(ct);
            if (server is null)
                return WireGuardSnapshot.Empty;

            var peers = await _wg.GetPeersAsync(server.Id, ct);
            // Try live status; if daemon is unreachable we still report configured peers.
            var statusEnvelope = await _daemon.GetWireGuardStatusAsync(ct);
            var threshold = DateTime.UtcNow - TimeSpan.FromMinutes(3);
            var active = statusEnvelope.Success && statusEnvelope.Data is not null
                ? statusEnvelope.Data.Count(s => s.LastHandshakeAt is { } h && h >= threshold)
                : 0;
            return new WireGuardSnapshot(Configured: true, PeerCount: peers.Count, ActivePeerCount: active);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "WireGuard summary unavailable — likely no migration or daemon down");
            return WireGuardSnapshot.Empty;
        }
    }

    private sealed record WireGuardSnapshot(bool Configured, int PeerCount, int ActivePeerCount)
    {
        public static readonly WireGuardSnapshot Empty = new(false, 0, 0);
    }

    private async Task<TrafficHistory> SafeQueryHistoryAsync(CancellationToken ct)
    {
        // Metrics tables may not exist on a fresh install; degrade gracefully.
        try
        {
            var to = DateTime.UtcNow;
            var from = to.AddHours(-24);
            var rows = await _query.GetHourlyMetricsAsync(from, to, hostname: null, ct);
            if (rows.Count == 0)
                return TrafficHistory.Empty;

            const double bytesToMbps = 8.0 / 1_000_000;
            return new TrafficHistory(
                Labels: rows.Select(r => r.Bucket.ToLocalTime().ToString("HH:mm")).ToArray(),
                RxMbps: rows.Select(r => Math.Round(r.NetworkRxTotal * bytesToMbps / 3600, 1)).ToArray(),
                TxMbps: rows.Select(r => Math.Round(r.NetworkTxTotal * bytesToMbps / 3600, 1)).ToArray(),
                TotalBytes: rows.Sum(r => r.NetworkRxTotal + r.NetworkTxTotal));
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Metrics history unavailable — likely fresh install or daemon down");
            return TrafficHistory.Empty;
        }
    }

    private static List<SubnetSummary> BuildSubnetSummaries(
        IReadOnlyList<NetFirewall.Models.Dhcp.DhcpSubnet> subnets,
        IReadOnlyList<NetFirewall.Models.Dhcp.DhcpPool> pools,
        IReadOnlyList<NetFirewall.Models.Dhcp.DhcpLease> leases)
    {
        var summaries = new List<SubnetSummary>(subnets.Count);
        foreach (var s in subnets)
        {
            var subnetPools = pools.Where(p => p.SubnetId == s.Id && p.Enabled).ToList();
            var capacity = subnetPools.Sum(p => CountIpsInRange(p.RangeStart, p.RangeEnd));
            var used = leases.Count(l => subnetPools.Any(p => IpInRange(l.IpAddress, p.RangeStart, p.RangeEnd)));
            var firstPool = subnetPools.FirstOrDefault();
            summaries.Add(new SubnetSummary
            {
                Id = s.Id,
                Name = string.IsNullOrEmpty(s.Name) ? s.Network : s.Name,
                Cidr = s.Network,
                PoolRange = firstPool is null ? null : $"{firstPool.RangeStart} – {firstPool.RangeEnd}",
                UsedLeases = used,
                Capacity = capacity,
            });
        }
        return summaries;
    }

    private static int CountIpsInRange(IPAddress start, IPAddress end)
    {
        if (start.AddressFamily != AddressFamily.InterNetwork || end.AddressFamily != AddressFamily.InterNetwork)
            return 0;
        var s = ToUInt32(start);
        var e = ToUInt32(end);
        return e >= s ? (int)Math.Min(e - s + 1, int.MaxValue) : 0;
    }

    private static bool IpInRange(IPAddress ip, IPAddress start, IPAddress end)
    {
        if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
        var i = ToUInt32(ip);
        return i >= ToUInt32(start) && i <= ToUInt32(end);
    }

    private static uint ToUInt32(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    // Event types we surface on the dashboard. Routine successes (login.success,
    // totp.verified, profile.updated) are noise here — they go to the full
    // audit log page. The dashboard shows only operationally interesting items.
    private static readonly HashSet<string> CriticalEvents = new(StringComparer.Ordinal)
    {
        AuthAuditEvents.LoginFailed,
        AuthAuditEvents.LoginLocked,
        AuthAuditEvents.TotpFailed,
        AuthAuditEvents.TotpReplayed,
        AuthAuditEvents.ElevationDenied,
        AuthAuditEvents.RecoveryUsed,
        AuthAuditEvents.BootstrapUsed,
        AuthAuditEvents.UserDisabled,
        AuthAuditEvents.SessionRevoked,
    };

    private async Task<IReadOnlyList<RecentActivity>> SafeQueryCriticalEventsAsync(CancellationToken ct)
    {
        try
        {
            var recent = await _authAudit.RecentAsync(50, ct);
            return recent
                .Where(e => CriticalEvents.Contains(e.EventType))
                .Take(6)
                .Select(MapAuthEvent)
                .ToList();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Auth audit query failed");
            return Array.Empty<RecentActivity>();
        }
    }

    private static RecentActivity MapAuthEvent(AuthAuditEntry e)
    {
        var sev = e.EventType switch
        {
            AuthAuditEvents.LoginLocked      => ActivitySeverity.Danger,
            AuthAuditEvents.LoginFailed      => ActivitySeverity.Warning,
            AuthAuditEvents.TotpFailed       => ActivitySeverity.Warning,
            AuthAuditEvents.TotpReplayed     => ActivitySeverity.Danger,
            AuthAuditEvents.ElevationDenied  => ActivitySeverity.Warning,
            AuthAuditEvents.RecoveryUsed     => ActivitySeverity.Warning,
            AuthAuditEvents.BootstrapUsed    => ActivitySeverity.Info,
            AuthAuditEvents.UserDisabled     => ActivitySeverity.Danger,
            AuthAuditEvents.SessionRevoked   => ActivitySeverity.Warning,
            _                                => ActivitySeverity.Neutral
        };
        return new RecentActivity
        {
            Title = e.EventType.Replace('.', ' '),
            Detail = string.IsNullOrEmpty(e.Username) ? (e.Ip?.ToString() ?? "—") : $"{e.Username}  ·  {e.Ip}",
            Severity = sev,
            Timestamp = e.OccurredAt.UtcDateTime,
        };
    }

    private async Task<IReadOnlyList<SystemServiceStatus>> SafeQueryServicesAsync(CancellationToken ct)
    {
        try
        {
            var env = await _daemon.GetSystemServicesAsync(ct);
            if (!env.Success || env.Data is null) return Array.Empty<SystemServiceStatus>();
            return env.Data.Select(s => new SystemServiceStatus
            {
                UnitName = s.UnitName,
                DisplayName = s.DisplayName,
                ActiveState = s.ActiveState,
                SubState = s.SubState,
                Enabled = s.Enabled,
                SinceUtc = s.SinceUtc,
            }).ToList();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "systemd services query failed");
            return Array.Empty<SystemServiceStatus>();
        }
    }

    private async Task<IReadOnlyList<WanStatusSummary>> SafeQueryWanAsync(CancellationToken ct)
    {
        try
        {
            var env = await _daemon.GetWanStatusAsync(ct);
            if (!env.Success || env.Data is null) return Array.Empty<WanStatusSummary>();
            return env.Data.Select(w => new WanStatusSummary
            {
                InterfaceName = w.InterfaceName,
                Role = w.Role,
                Target = w.Target,
                IsUp = w.IsUp,
                RttMs = w.RttMs,
                Message = w.Message,
            }).ToList();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "WAN status query failed");
            return Array.Empty<WanStatusSummary>();
        }
    }

    private sealed record WanHealthSnapshot(IReadOnlyList<WanHealthRow> Health, IReadOnlyList<WanTransition> Transitions)
    {
        public static readonly WanHealthSnapshot Empty =
            new(Array.Empty<WanHealthRow>(), Array.Empty<WanTransition>());
    }

    private async Task<WanHealthSnapshot> SafeQueryWanHealthAsync(CancellationToken ct)
    {
        try
        {
            var env = await _daemon.GetWanHealthAsync(ct);
            if (!env.Success || env.Data is null) return WanHealthSnapshot.Empty;

            var rows = env.Data.State.Select(s => new WanHealthRow
            {
                InterfaceName        = s.InterfaceName,
                Role                 = s.Role,
                IsUp                 = s.IsUp,
                ConsecutiveFailures  = s.ConsecutiveFailures,
                ConsecutiveSuccesses = s.ConsecutiveSuccesses,
                LastCheckAt          = s.LastCheckAt,
                LastTransitionAt     = s.LastTransitionAt,
                LastRttMs            = s.LastRttMs,
                LastTarget           = s.LastTarget,
                LastError            = s.LastError,
            }).ToList();

            var transitions = env.Data.RecentEvents.Select(e => new WanTransition
            {
                OccurredAt    = e.OccurredAt,
                InterfaceName = e.InterfaceName,
                EventType     = e.EventType,
            }).ToList();

            return new WanHealthSnapshot(rows, transitions);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "WAN health query failed");
            return WanHealthSnapshot.Empty;
        }
    }

    private sealed record TopTalkerSnapshot(IReadOnlyList<TopTalkerRow> Hosts, IReadOnlyList<TopTalkerRow> Services)
    {
        public static readonly TopTalkerSnapshot Empty =
            new(Array.Empty<TopTalkerRow>(), Array.Empty<TopTalkerRow>());
    }

    private async Task<TopTalkerSnapshot> SafeQueryTopTalkersAsync(CancellationToken ct)
    {
        try
        {
            var env = await _daemon.GetTopTalkersAsync(24, 5, ct);
            if (!env.Success || env.Data is null) return TopTalkerSnapshot.Empty;

            // Project the daemon DTOs into UI-friendly rows. Hostname goes in
            // the sublabel; service name (https/sip/…) is interpolated into
            // the main label so the user sees "tcp/443 (https)".
            var hosts = env.Data.Hosts.Select(h => new TopTalkerRow
            {
                Label = h.SrcIp.ToString(),
                Sublabel = h.Hostname ?? $"{h.FlowCount} flow(s)",
                BytesIn = h.BytesIn,
                BytesOut = h.BytesOut,
            }).ToList();

            var services = env.Data.Services.Select(s => new TopTalkerRow
            {
                Label = s.DstPort is int port
                    ? (s.ServiceName is { Length: > 0 } sn
                        ? $"{s.Proto}/{port} ({sn})"
                        : $"{s.Proto}/{port}")
                    : s.Proto,
                Sublabel = $"{s.FlowCount} flow(s)",
                BytesIn = s.BytesIn,
                BytesOut = s.BytesOut,
            }).ToList();

            return new TopTalkerSnapshot(hosts, services);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Top-talkers query failed");
            return TopTalkerSnapshot.Empty;
        }
    }

    private async Task<IReadOnlyList<PendingApplySummary>> SafeQueryPendingAsync(CancellationToken ct)
    {
        try
        {
            var env = await _daemon.GetPendingChangesAsync(ct);
            if (!env.Success || env.Data is null) return Array.Empty<PendingApplySummary>();
            return env.Data.Select(p => new PendingApplySummary
            {
                Kind = p.Kind,
                LastAppliedAt = p.LastAppliedAt,
                PendingCount = p.PendingCount,
            }).ToList();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Pending-changes query failed");
            return Array.Empty<PendingApplySummary>();
        }
    }

    private sealed record TrafficHistory(string[] Labels, double[] RxMbps, double[] TxMbps, long TotalBytes)
    {
        public static readonly TrafficHistory Empty = new([], [], [], 0);
    }
}
