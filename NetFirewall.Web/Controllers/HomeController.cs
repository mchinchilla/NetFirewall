using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Dhcp;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Monitoring;
using NetFirewall.Services.Vpn;
using NetFirewall.Web.Daemon;
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
    private readonly ILogger<HomeController> _logger;

    public HomeController(
        IDhcpAdminService dhcp,
        IFirewallService firewall,
        ISystemMonitorService monitor,
        IMetricsQueryService query,
        IWireGuardService wg,
        IDaemonClient daemon,
        ILogger<HomeController> logger)
    {
        _dhcp = dhcp;
        _firewall = firewall;
        _monitor = monitor;
        _query = query;
        _wg = wg;
        _daemon = daemon;
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
        var auditTask      = _firewall.GetAuditLogsAsync(limit: 6, offset: 0, ct);
        var historyTask    = SafeQueryHistoryAsync(ct);
        var wgTask         = SafeQueryWireGuardAsync(ct);

        await Task.WhenAll(leasesTask, subnetsTask, poolsTask, ifacesTask,
                           filterTask, snapshotTask, auditTask, historyTask, wgTask);

        var leases    = leasesTask.Result;
        var subnets   = subnetsTask.Result;
        var pools     = poolsTask.Result;
        var ifaces    = ifacesTask.Result;
        var filters   = filterTask.Result;
        var snapshot  = snapshotTask.Result;
        var audit     = auditTask.Result;
        var history   = historyTask.Result;
        var wg        = wgTask.Result;

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

            TrafficLabels   = history.Labels,
            TrafficRxMbps   = history.RxMbps,
            TrafficTxMbps   = history.TxMbps,
            TrafficAvgInMbps  = history.RxMbps.Length > 0 ? Math.Round(history.RxMbps.Average(), 1) : 0,
            TrafficAvgOutMbps = history.TxMbps.Length > 0 ? Math.Round(history.TxMbps.Average(), 1) : 0,
            TrafficTotalBytes = history.TotalBytes,

            RecentActivity = audit.Select(MapAudit).ToList(),
            Subnets = subnetSummaries,
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

    private static RecentActivity MapAudit(FwAuditLog e)
    {
        var sev = e.Action switch
        {
            "INSERT" => ActivitySeverity.Success,
            "UPDATE" => ActivitySeverity.Info,
            "DELETE" => ActivitySeverity.Warning,
            _        => ActivitySeverity.Neutral
        };
        var prettyTable = e.TableName.Replace("_", " ");
        return new RecentActivity
        {
            Title = $"{prettyTable} · {e.Action.ToLowerInvariant()}",
            Detail = $"record {e.RecordId.ToString("N")[..8]}…",
            Severity = sev,
            Timestamp = e.CreatedAt,
        };
    }

    private sealed record TrafficHistory(string[] Labels, double[] RxMbps, double[] TxMbps, long TotalBytes)
    {
        public static readonly TrafficHistory Empty = new([], [], [], 0);
    }
}
