using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Firewall;
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
    private readonly ILogger<HomeController> _logger;

    public HomeController(
        IDhcpAdminService dhcp,
        IFirewallService firewall,
        ISystemMonitorService monitor,
        IMetricsQueryService query,
        IWireGuardService wg,
        IDaemonClient daemon,
        IScheduleService schedules,
        ILogger<HomeController> logger)
    {
        _dhcp = dhcp;
        _firewall = firewall;
        _monitor = monitor;
        _query = query;
        _wg = wg;
        _daemon = daemon;
        _schedules = schedules;
        _logger = logger;
    }

    public async Task<IActionResult> Index(CancellationToken ct)
    {
        // Fan-out: every source is independent so parallel awaits cut latency.
        var leasesTask     = _dhcp.GetActiveLeasesAsync(ct: ct);
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
        var wanHealthTask  = SafeQueryWanHealthAsync(ct);

        await Task.WhenAll(leasesTask, subnetsTask, poolsTask, ifacesTask,
                           filterTask, snapshotTask, historyTask, wgTask, schedulesTask,
                           servicesTask, wanTask, pendingTask, wanHealthTask);

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

            Host = new HostInfo
            {
                Hostname = snapshot.System.Hostname,
                OsName = snapshot.System.OsName,
                KernelVersion = snapshot.System.KernelVersion,
                Virtualization = snapshot.System.Virtualization,
                CoreCount = snapshot.Cpu.CoreCount,
                TotalMemoryBytes = snapshot.Memory.TotalBytes,
                Uptime = snapshot.System.Uptime,
            },
            Subnets = subnetSummaries,
            Services = services,
            WanStatus = wanStatus,
            PendingChanges = pending,
            WanHealth = wanHealth.Health,
            WanTransitions = wanHealth.Transitions,
        };

        return View(vm);
    }

    // Live throughput pulse — polled every ~5s by the dashboard via HTMX. Reads
    // the same /proc snapshot the KPI uses, but as a standalone partial so it can
    // refresh without touching the (hourly, static) 24h Chart.js canvas.
    [HttpGet("/Home/Throughput")]
    public async Task<IActionResult> Throughput(CancellationToken ct)
    {
        try
        {
            var snapTask = _monitor.GetSnapshotAsync(ct);
            var ifacesTask = _firewall.GetInterfacesAsync(ct);
            await Task.WhenAll(snapTask, ifacesTask);
            var snap = snapTask.Result;

            // Count ONLY WAN interfaces. Summing every NIC double-counts every
            // routed packet (it's RX on the LAN NIC and TX on the WAN NIC),
            // which made in≈out. WAN RX = real download, WAN TX = real upload.
            var wanNames = ifacesTask.Result
                .Where(i => string.Equals(i.Type, "WAN", StringComparison.OrdinalIgnoreCase))
                .Select(i => i.Name)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            const double bytesToMbps = 8.0 / 1_000_000;
            // Fall back to all-non-loopback only if no WAN is configured, so the
            // panel still shows something rather than going blank.
            var nics = snap.Network
                .Where(n => wanNames.Count > 0
                    ? wanNames.Contains(n.InterfaceName)
                    : !string.Equals(n.InterfaceName, "lo", StringComparison.OrdinalIgnoreCase))
                .ToList();

            var perIface = nics
                .Select(n => new InterfaceRate(
                    n.InterfaceName,
                    Math.Round(n.BytesReceivedPerSecond * bytesToMbps, 1),
                    Math.Round(n.BytesSentPerSecond * bytesToMbps, 1)))
                .Where(i => i.InMbps > 0 || i.OutMbps > 0)
                .OrderByDescending(i => i.InMbps + i.OutMbps)
                .ToList();

            return PartialView("_LiveThroughput", new LiveThroughputViewModel
            {
                InMbps = Math.Round(nics.Sum(n => n.BytesReceivedPerSecond) * bytesToMbps, 1),
                OutMbps = Math.Round(nics.Sum(n => n.BytesSentPerSecond) * bytesToMbps, 1),
                PerInterface = perIface,
            });
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Live throughput snapshot unavailable");
            return PartialView("_LiveThroughput", new LiveThroughputViewModel { Unavailable = true });
        }
    }

    // LAN-wide top destinations — polled every ~30s by the dashboard. Replaces
    // the old auth-events "Recent activity" panel. Delegates to the daemon.
    [HttpGet("/Home/TopDestinations")]
    public async Task<IActionResult> TopDestinations(CancellationToken ct)
    {
        var vm = new NetFirewall.Web.Models.Monitoring.TopDestinationsViewModel();
        try
        {
            var env = await _daemon.GetTopDestinationsAsync(24, 8, ct);
            if (env.Success && env.Data is not null)
            {
                vm = new NetFirewall.Web.Models.Monitoring.TopDestinationsViewModel
                {
                    Destinations = env.Data.Destinations.Select(d => new NetFirewall.Web.Models.Monitoring.HostDestinationRow
                    {
                        DstIp = d.DstIp?.ToString(),
                        Asn = d.Asn,
                        Org = d.Org,
                        Country = d.Country,
                        BytesIn = d.BytesIn,
                        BytesOut = d.BytesOut,
                        FlowCount = d.FlowCount,
                    }).ToList(),
                };
            }
            else
            {
                vm = new NetFirewall.Web.Models.Monitoring.TopDestinationsViewModel { Error = env.Message };
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Top destinations unavailable");
            vm = new NetFirewall.Web.Models.Monitoring.TopDestinationsViewModel { Error = "Could not reach the daemon." };
        }

        return PartialView("_TopDestinations", vm);
    }

    // Live throughput sparkline series — last 60 min of WAN rates, per minute.
    // Returned as JSON so the client updates the existing Chart.js instance
    // in-place (no canvas re-creation = no Chart.js instance leak).
    [HttpGet("/Home/ThroughputSeries")]
    public async Task<IActionResult> ThroughputSeries(CancellationToken ct)
    {
        const double bytesToMbps = 8.0 / 1_000_000;
        try
        {
            var rows = await _query.GetWanRatePerMinuteAsync(60, ct);
            return Json(new
            {
                labels = rows.Select(r => r.Bucket.ToLocalTime().ToString("HH:mm")).ToArray(),
                inSeries = rows.Select(r => Math.Round(r.RxBytesPerSec * bytesToMbps, 2)).ToArray(),
                outSeries = rows.Select(r => Math.Round(r.TxBytesPerSec * bytesToMbps, 2)).ToArray(),
            });
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Throughput series unavailable");
            return Json(new { labels = Array.Empty<string>(), inSeries = Array.Empty<double>(), outSeries = Array.Empty<double>() });
        }
    }

    // Live CPU% / Memory% sparkline series — last 60 min, per minute. JSON so the
    // client updates the Chart.js sparklines in place (no canvas leak).
    [HttpGet("/Home/SystemSeries")]
    public async Task<IActionResult> SystemSeries(CancellationToken ct)
    {
        try
        {
            var rows = await _query.GetSystemRatePerMinuteAsync(60, ct);
            return Json(new
            {
                labels = rows.Select(r => r.Bucket.ToLocalTime().ToString("HH:mm")).ToArray(),
                cpu = rows.Select(r => Math.Round(r.CpuPercent, 1)).ToArray(),
                mem = rows.Select(r => Math.Round(r.MemoryPercent, 1)).ToArray(),
            });
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "System series unavailable");
            return Json(new { labels = Array.Empty<string>(), cpu = Array.Empty<double>(), mem = Array.Empty<double>() });
        }
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
            const double bytesToMbps = 8.0 / 1_000_000;

            // Preferred: WAN-only per-interface data — real download/upload, no
            // NAT double-count (which made in≈out on the all-NIC sum).
            var wan = await _query.GetWanTrafficHourlyAsync(from, to, ct);
            if (wan.Count > 0)
            {
                return new TrafficHistory(
                    Labels: wan.Select(r => r.Bucket.ToLocalTime().ToString("HH:mm")).ToArray(),
                    RxMbps: wan.Select(r => Math.Round(r.RxBytes * bytesToMbps / 3600, 1)).ToArray(),
                    TxMbps: wan.Select(r => Math.Round(r.TxBytes * bytesToMbps / 3600, 1)).ToArray(),
                    TotalBytes: wan.Sum(r => r.RxBytes + r.TxBytes));
            }

            // Fallback (no per-interface hour yet, or no WAN configured): the old
            // summed series. Double-counted, but better than a blank chart until
            // the new pipeline has collected an hour.
            var rows = await _query.GetHourlyMetricsAsync(from, to, hostname: null, ct);
            if (rows.Count == 0)
                return TrafficHistory.Empty;

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
