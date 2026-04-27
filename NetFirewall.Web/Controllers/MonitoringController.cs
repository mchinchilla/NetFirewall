using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Monitoring;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// System monitoring page — live snapshot of CPU, memory, disks, and per-NIC
/// counters straight from /proc. Future iteration adds historical charts
/// once the metrics collector is running and DB tables exist.
/// </summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator},{UserRoles.Viewer}")]
[Route("/Monitoring")]
public sealed class MonitoringController : Controller
{
    private readonly ISystemMonitorService _monitor;

    public MonitoringController(ISystemMonitorService monitor) => _monitor = monitor;

    [HttpGet("")]
    public IActionResult Index() => View();

    [HttpGet("snapshot")]
    public async Task<IActionResult> Snapshot(CancellationToken ct)
    {
        var snap = await _monitor.GetSnapshotAsync(ct);
        return PartialView("_MonitoringSnapshot", snap);
    }
}
