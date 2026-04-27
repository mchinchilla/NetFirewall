using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Monitoring;
using NetFirewall.Web.Models.Monitoring;

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

    public MonitoringController(ISystemMonitorService monitor, IMetricsQueryService query)
    {
        _monitor = monitor;
        _query = query;
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
