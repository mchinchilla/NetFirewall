using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Daemon;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Monitoring;
using NetFirewall.Web.Models;
using NetFirewall.Web.Models.Monitoring;
using Npgsql;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// System monitoring page — live snapshot from /proc plus historical charts
/// fed by the daemon's MetricsCollectorService.
/// </summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator},{UserRoles.Viewer}")]
[Route("/Monitoring")]
public sealed class MonitoringController : Controller
{
    private readonly ISystemMonitorService _monitor;
    private readonly IMetricsQueryService _query;
    private readonly IScheduleService _schedules;
    private readonly IDaemonClient _daemon;
    private readonly NpgsqlDataSource _ds;
    private readonly ILogger<MonitoringController> _logger;

    public MonitoringController(
        ISystemMonitorService monitor,
        IMetricsQueryService query,
        IScheduleService schedules,
        IDaemonClient daemon,
        NpgsqlDataSource ds,
        ILogger<MonitoringController> logger)
    {
        _monitor = monitor;
        _query = query;
        _schedules = schedules;
        _daemon = daemon;
        _ds = ds;
        _logger = logger;
    }

    [HttpGet("")]
    public IActionResult Index() => View();

    [HttpGet("snapshot")]
    public async Task<IActionResult> Snapshot(CancellationToken ct)
    {
        var snap = await _monitor.GetSnapshotAsync(ct);
        return PartialView("_MonitoringSnapshot", snap);
    }

    [HttpGet("history")]
    public async Task<IActionResult> History(string? range, CancellationToken ct)
    {
        var (from, to, useHourly) = ResolveRange(range);
        var vm = new MonitoringHistoryViewModel { Range = range ?? "24h", From = from, To = to };

        if (useHourly)
        {
            var rows = await _query.GetHourlyMetricsAsync(from, to, hostname: null, ct);
            vm.Labels = rows.Select(r => r.Bucket.ToLocalTime().ToString("MM-dd HH:mm")).ToArray();
            vm.CpuSeries = rows.Select(r => Math.Round(r.CpuAvg, 1)).ToArray();
            vm.MemorySeries = rows.Select(r => Math.Round(r.MemoryUsedAvg, 1)).ToArray();
            vm.LoadSeries = rows.Select(r => Math.Round(r.LoadAvg, 2)).ToArray();
            vm.RxSeries = rows.Select(r => (double)r.NetworkRxTotal).ToArray();
            vm.TxSeries = rows.Select(r => (double)r.NetworkTxTotal).ToArray();
            vm.SampleCount = rows.Sum(r => r.SampleCount);
        }
        else
        {
            var rows = await _query.GetRawMetricsAsync(from, to, hostname: null, ct);
            vm.Labels = rows.Select(r => r.Timestamp.ToLocalTime().ToString("HH:mm:ss")).ToArray();
            vm.CpuSeries = rows.Select(r => Math.Round(r.CpuUsage, 1)).ToArray();
            vm.MemorySeries = rows.Select(r => Math.Round(r.MemoryUsagePercent, 1)).ToArray();
            vm.LoadSeries = rows.Select(r => Math.Round(r.LoadAvg1m, 2)).ToArray();
            vm.RxSeries = rows.Select(r => r.NetworkRxRate).ToArray();
            vm.TxSeries = rows.Select(r => r.NetworkTxRate).ToArray();
            vm.SampleCount = rows.Count;
        }

        return PartialView("_MonitoringHistory", vm);
    }

    // Mirrors HomeController.SafeQueryTopTalkersAsync but renders directly as
    // a partial so HTMX can swap it in-place on the Monitoring page every 30s
    // (the daemon's ConntrackSampler cadence — faster polling is wasted work).
    [HttpGet("toptalkers")]
    public async Task<IActionResult> TopTalkers(string? range, CancellationToken ct)
    {
        // Normalize to one of the known tokens so the selector always echoes a
        // valid state back; unknown values fall through to the 24h default.
        var window = TopTalkersLiveViewModel.Ranges.Contains(range) ? range! : "24h";
        var hours = TopTalkersLiveViewModel.RangeToHours(window);

        TopTalkersLiveViewModel vm;
        try
        {
            var env = await _daemon.GetTopTalkersAsync(hours, 5, ct);
            if (env.Success && env.Data is not null)
            {
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

                vm = new TopTalkersLiveViewModel { Hosts = hosts, Services = services, Range = window };
            }
            else
            {
                vm = new TopTalkersLiveViewModel { Range = window };
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Top-talkers query failed");
            vm = new TopTalkersLiveViewModel { Range = window };
        }

        return PartialView("_TopTalkersLive", vm);
    }

    [HttpGet("schedules")]
    public async Task<IActionResult> Schedules(CancellationToken ct)
    {
        var all = await _schedules.GetAllAsync(ct);

        // Count attached filter rules per schedule. One small SQL beats N round-trips.
        var attached = new Dictionary<Guid, int>();
        try
        {
            await using var conn = await _ds.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(
                "SELECT schedule_id, COUNT(*) FROM fw_filter_rules WHERE schedule_id IS NOT NULL GROUP BY schedule_id",
                conn);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
                attached[reader.GetGuid(0)] = reader.GetInt32(1);
        }
        catch (PostgresException ex) when (ex.SqlState == "42P01" || ex.SqlState == "42703")
        {
            // fw_filter_rules.schedule_id may not exist yet — degrade to zeros.
        }

        ViewBag.Attached = attached;
        return PartialView("_SchedulesLive", all);
    }

    private static (DateTime From, DateTime To, bool UseHourly) ResolveRange(string? range)
    {
        var to = DateTime.UtcNow;
        return range switch
        {
            "1h"  => (to.AddHours(-1),  to, false),
            "6h"  => (to.AddHours(-6),  to, false),
            "7d"  => (to.AddDays(-7),   to, true),
            _     => (to.AddHours(-24), to, false), // default 24h raw
        };
    }
}
