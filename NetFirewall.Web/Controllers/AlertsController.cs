using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Daemon;
using NetFirewall.Web.Helpers;
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
                        .Select(a => new ActiveAlertViewModel(a.Severity, a.Title, a.Body, a.RaisedAt, a.DedupeKey, a.Source))
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

        // Emit the current active-danger alert keys so the client can detect
        // newly-appeared (→ alarm) and disappeared (→ recovery chime) alerts and
        // play the audible cue. Sent on every poll; the client diffs against the
        // previous set. Cheap: just keys + source, no bodies.
        this.AttachHxEvent("alertsState", new
        {
            danger = model.Alerts
                .Where(a => a.Severity == "danger")
                .Select(a => new { key = a.Key, source = a.Source })
                .ToList(),
        });

        return PartialView("_AlertsBanner", model);
    }

    // GET /Alerts/menu — HTMX fragment for the header notifications dropdown.
    // Recent alerts (active + resolved), newest first, capped for the popover.
    [HttpGet("menu")]
    public async Task<IActionResult> Menu(CancellationToken ct)
    {
        var model = await BuildNotificationsAsync(limit: 8, ct);
        return PartialView("_NotificationsList", model);
    }

    // GET /Alerts — full "View all activity" history page.
    [HttpGet("")]
    public async Task<IActionResult> Index(CancellationToken ct)
    {
        var model = await BuildNotificationsAsync(limit: 100, ct);
        return View(model);
    }

    private async Task<NotificationsViewModel> BuildNotificationsAsync(int limit, CancellationToken ct)
    {
        try
        {
            var env = await _daemon.GetRecentAlertsAsync(limit, ct);
            if (env.Success && env.Data is not null)
            {
                return new NotificationsViewModel
                {
                    Items = env.Data.Alerts
                        .Select(a => new NotificationItemViewModel(a.Severity, a.Source, a.Title, a.Body, a.RaisedAt, a.ResolvedAt))
                        .ToList(),
                };
            }
        }
        catch (Exception ex)
        {
            // Notifications are best-effort chrome — never page-error on a daemon
            // hiccup. Log and render the empty state.
            _logger.LogDebug(ex, "Recent-alerts query failed");
        }
        return new NotificationsViewModel();
    }
}
