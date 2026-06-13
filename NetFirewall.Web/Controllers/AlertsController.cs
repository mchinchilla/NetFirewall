using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Daemon;
using NetFirewall.Web.Models;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// Serves the active-system-alerts banner fragment that the layout polls. Thin
/// orchestrator (project rule #10): it asks the daemon for VPN health and shapes
/// the active alerts into the banner view model — no data access of its own.
/// </summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator},{UserRoles.Viewer}")]
[Route("/Alerts")]
public sealed class AlertsController : Controller
{
    private readonly IDaemonClient _daemon;
    private readonly ILogger<AlertsController> _logger;

    public AlertsController(IDaemonClient daemon, ILogger<AlertsController> logger)
    {
        _daemon = daemon;
        _logger = logger;
    }

    // GET /Alerts/banner — HTMX-polled fragment. Returns the active alerts banner,
    // or empty markup when nothing is active (so the poll self-clears on recovery).
    [HttpGet("banner")]
    public async Task<IActionResult> Banner(CancellationToken ct)
    {
        var model = new AlertsBannerViewModel();
        try
        {
            var env = await _daemon.GetVpnHealthAsync(ct);
            if (env.Success && env.Data is not null)
            {
                model = new AlertsBannerViewModel
                {
                    Alerts = env.Data.ActiveAlerts
                        .Select(a => new ActiveAlertViewModel(a.Severity, a.Title, a.Body, a.RaisedAt))
                        .ToList(),
                };
            }
        }
        catch (Exception ex)
        {
            // Banner is best-effort chrome — never surface a daemon hiccup as a
            // page error. Log and render the empty (no-alerts) state.
            _logger.LogDebug(ex, "Active-alerts query failed");
        }

        return PartialView("_AlertsBanner", model);
    }
}
