using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Auth;
using NetFirewall.Services.Diagnostics;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models.Diagnostics;
using Npgsql;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// Diagnostics history: every persisted run (who, when, tool, params, result).
/// Reads <c>diag_runs</c> directly — no daemon round-trip — so it works while the
/// daemon is down. Purge is Admin-only behind step-up and audited.
/// </summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Diagnostics/History")]
public sealed class DiagnosticsHistoryController : Controller
{

    private readonly IDiagnosticRunStore _runs;
    private readonly IAuthAuditService _audit;
    private readonly ILogger<DiagnosticsHistoryController> _logger;

    public DiagnosticsHistoryController(IDiagnosticRunStore runs, IAuthAuditService audit, ILogger<DiagnosticsHistoryController> logger)
    {
        _runs = runs;
        _audit = audit;
        _logger = logger;
    }

    [HttpGet("")]
    public IActionResult Index([FromQuery] HistoryFilterViewModel filter) => View(filter);

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Detail(Guid id, CancellationToken ct)
    {
        var run = await _runs.GetAsync(id, ct);
        if (run is null) return NotFound();
        var (partial, model) = DiagRunPartials.Resolve(run);
        return PartialView("_RunDetail", new RunDetailViewModel(run, partial, model,
            DiagRunPartials.Pretty(run.ParamsJson), DiagRunPartials.Pretty(run.ResultJson)));
    }

    /// <summary>
    /// Expanded row of the History grid: meta, params and raw result. Lean on purpose (it renders
    /// inside the grid frame); the rich report stays in <see cref="Detail"/>, opened in the drawer.
    /// </summary>
    [HttpGet("detail/{id:guid}")]
    public async Task<IActionResult> RowDetail(Guid id, CancellationToken ct)
    {
        var run = await _runs.GetAsync(id, ct);
        if (run is null)
            return Content("<p class=\"text-sm text-surface-fg-muted\">This run is gone (purged). Refresh the grid.</p>", "text/html");
        return PartialView("_RunRowDetail", new RunDetailViewModel(run, null, null,
            DiagRunPartials.Pretty(run.ParamsJson), DiagRunPartials.Pretty(run.ResultJson)));
    }

    /// <summary><paramref name="olderThanDays"/> null or 0 = purge everything.</summary>
    [HttpPost("purge"), ValidateAntiForgeryToken]
    [Authorize(Roles = UserRoles.Admin)]
    [Filters.RequireElevated]
    public async Task<IActionResult> Purge([FromForm] int? olderThanDays, CancellationToken ct)
    {
        int deleted;
        try
        {
            deleted = olderThanDays is > 0
                ? await _runs.PurgeOlderThanAsync(TimeSpan.FromDays(olderThanDays.Value), ct)
                : await _runs.PurgeAllAsync(ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Diagnostics history purge failed");
            return this.ToHtmxResponse(ServiceResponse<object>.Fail($"Purge failed: {ex.Message}"));
        }

        try
        {
            await _audit.LogAsync(AuthAuditEvents.DiagPurge,
                username: User.Identity?.Name,
                ip: HttpContext.Connection.RemoteIpAddress,
                userAgent: Request.Headers.UserAgent.ToString(),
                detail: new { olderThanDays, deleted },
                ct: ct);
        }
        catch (Exception ex) { _logger.LogWarning(ex, "diag.purge audit failed"); }

        var resp = this.ToHtmxResponse(ServiceResponse<object>.Ok(new { deleted },
            deleted == 0 ? "Nothing to purge." : $"Purged {deleted} run{(deleted == 1 ? "" : "s")}."));
        this.AttachHxEvent("refreshDiagHistory", new { });
        return resp;
    }

    private static string? Blank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}
