using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Monitoring.Host;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models.Monitoring;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// Monitoring → Server: CPU, memory, load, disk and network of the firewall
/// host, plus the busiest programs and the local disks. Everything comes from
/// the Web's in-memory host monitor (one /proc sample per second) — a refresh
/// never touches PostgreSQL or the daemon.
/// </summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator},{UserRoles.Viewer}")]
[Route("/Monitoring/Server")]
public sealed class ServerMonitorController(IHostMonitorQueryService monitor) : Controller
{
    /// <summary>The page; HTMX polls and window chips get just the live section.</summary>
    [HttpGet("")]
    public async Task<IActionResult> Index(int? window, CancellationToken ct)
    {
        var seconds = HostWindows.Clean(window);
        var model = new ServerMonitorViewModel(await monitor.GetAsync(seconds, ct), seconds);
        return Request.IsHtmxRequest() ? PartialView("_ServerLive", model) : View(model);
    }

    /// <summary>The five-tile strip (last 5 minutes) for the dashboard and Monitoring overview.</summary>
    [HttpGet("strip")]
    public async Task<IActionResult> Strip(CancellationToken ct)
    {
        var model = new ServerMonitorViewModel(await monitor.GetAsync(HostWindows.Strip, ct), HostWindows.Strip);
        return PartialView("_ServerStrip", model);
    }
}
