using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Daemon;
using NetFirewall.Services.Diagnostics;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Settings;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models.Diagnostics;
using Npgsql;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// Diagnostics section — tool pages. The Web validates the form, proxies the
/// request to the daemon (which re-validates and executes), and renders the
/// result partial. History rows are written by the daemon; the landing page
/// reads them straight from PostgreSQL so it works while the daemon is down.
/// Read-only tools: Admin and Operator, no step-up (see docs/diagnostics.md).
/// </summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Diagnostics")]
public sealed class DiagnosticsController : Controller
{
    private readonly IDaemonClient _daemon;
    private readonly IFirewallService _fw;
    private readonly IDiagnosticRunStore _runs;
    private readonly IAppSettingsService _settings;
    private readonly ILogger<DiagnosticsController> _logger;

    public DiagnosticsController(
        IDaemonClient daemon,
        IFirewallService fw,
        IDiagnosticRunStore runs,
        IAppSettingsService settings,
        ILogger<DiagnosticsController> logger)
    {
        _daemon = daemon;
        _fw = fw;
        _runs = runs;
        _settings = settings;
        _logger = logger;
    }

    // ───────────────────────── landing ─────────────────────────

    [HttpGet("")]
    public async Task<IActionResult> Index(CancellationToken ct) => View(await PageModelAsync(ct));

    [HttpGet("recent")]
    public async Task<IActionResult> Recent(CancellationToken ct)
    {
        try
        {
            return PartialView("_RecentRuns", new PanelViewModel<IReadOnlyList<DiagRun>>(await _runs.RecentAsync(10, ct), null));
        }
        catch (PostgresException ex) when (ex.SqlState == "42P01")
        {
            return PartialView("_RecentRuns", new PanelViewModel<IReadOnlyList<DiagRun>>(null, "History table missing — apply migration 00041."));
        }
    }

    // ───────────────────────── ping ─────────────────────────

    [HttpGet("ping")]
    public async Task<IActionResult> Ping(CancellationToken ct) => View(await PageModelAsync(ct));

    [HttpPost("ping/run"), ValidateAntiForgeryToken]
    public async Task<IActionResult> PingRun(PingFormViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid) return Invalid<PingResult>();
        var env = await _daemon.RunPingAsync(
            new PingRequest(form.Target.Trim(), Blank(form.Interface), form.EffectiveFwmark, form.Count, form.TimeoutSec), ct);
        return RenderRun(env, "_PingResult");
    }

    // ───────────────────────── traceroute ─────────────────────────

    [HttpGet("traceroute")]
    public async Task<IActionResult> Traceroute(CancellationToken ct) => View(await PageModelAsync(ct));

    [HttpPost("traceroute/run"), ValidateAntiForgeryToken]
    public async Task<IActionResult> TracerouteRun(TracerouteFormViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid) return Invalid<TracerouteResult>();
        var env = await _daemon.RunTracerouteAsync(
            new TracerouteRequest(form.Target.Trim(), Blank(form.Interface), form.EffectiveFwmark, form.MaxHops, form.TimeoutSec), ct);
        return RenderRun(env, "_TracerouteResult");
    }

    // ───────────────────────── route oracle ─────────────────────────

    [HttpGet("route")]
    public async Task<IActionResult> Route(CancellationToken ct) => View(await PageModelAsync(ct));

    [HttpPost("route/run"), ValidateAntiForgeryToken]
    public async Task<IActionResult> RouteRun(RouteGetFormViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid) return Invalid<RouteGetResult>();
        var env = await _daemon.RunRouteGetAsync(
            new RouteGetRequest(form.Target.Trim(), form.EffectiveFwmark, Blank(form.From), Blank(form.Interface)), ct);
        return RenderRun(env, "_RouteResult");
    }

    // ───────────────────────── conntrack ─────────────────────────

    [HttpGet("conntrack")]
    public async Task<IActionResult> Conntrack(CancellationToken ct) => View(await PageModelAsync(ct));

    [HttpPost("conntrack/run"), ValidateAntiForgeryToken]
    public async Task<IActionResult> ConntrackRun(ConntrackFormViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid) return Invalid<ConntrackLookupResult>();
        var env = await _daemon.RunConntrackLookupAsync(
            new ConntrackLookupRequest(Blank(form.Src), Blank(form.Dst), Blank(form.Proto), form.Port, form.Limit), ct);
        return RenderRun(env, "_ConntrackResult");
    }

    // ───────────────────────── drop log ─────────────────────────

    [HttpGet("drop-log")]
    public async Task<IActionResult> DropLog(CancellationToken ct) => View(await PageModelAsync(ct));

    [HttpPost("drop-log/run"), ValidateAntiForgeryToken]
    public async Task<IActionResult> DropLogRun(DropLogFormViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid) return Invalid<DropLogResult>();
        var env = await _daemon.RunDropLogAsync(
            new DropLogRequest(Blank(form.Interface), form.SinceMinutes, form.Lines, form.Filter), ct);
        return RenderRun(env, "_DropLogResult");
    }

    // ───────────────────────── live panels ─────────────────────────

    [HttpGet("interfaces")]
    public async Task<IActionResult> Interfaces(CancellationToken ct) => View(await PageModelAsync(ct));

    [HttpGet("interfaces/table")]
    public async Task<IActionResult> InterfacesTable(CancellationToken ct)
    {
        var env = await _daemon.GetInterfaceHealthAsync(ct);
        return PartialView("_InterfacesTable", new PanelViewModel<IReadOnlyList<InterfaceHealth>>(env.Data, env.Success ? null : env.Message));
    }

    [HttpGet("neighbors/table")]
    public async Task<IActionResult> NeighborsTable([FromQuery] string? iface, CancellationToken ct)
    {
        var env = await _daemon.GetNeighborsAsync(Blank(iface), ct);
        return PartialView("_NeighborsTable", new PanelViewModel<IReadOnlyList<NeighborEntry>>(env.Data, env.Success ? null : env.Message));
    }

    [HttpGet("sysctl")]
    public async Task<IActionResult> Sysctl(CancellationToken ct) => View(await PageModelAsync(ct));

    [HttpGet("sysctl/table")]
    public async Task<IActionResult> SysctlTable([FromQuery] string? iface, CancellationToken ct)
    {
        var env = await _daemon.GetSysctlSanityAsync(Blank(iface), ct);
        if (!env.Success || env.Data is null)
            return PartialView("_DiagCheckList", new DiagReport(DiagTools.Sysctl, iface ?? "all", DateTime.UtcNow, 0,
                [DiagCheck.Skip("sys.daemon", "Kernel", "Kernel tunables", env.Message ?? "Daemon unavailable.")]));
        return PartialView("_DiagCheckList", new DiagReport(DiagTools.Sysctl, iface ?? "all", DateTime.UtcNow, 0, env.Data));
    }

    // ───────────────────────── helpers ─────────────────────────

    private async Task<DiagToolPageViewModel> PageModelAsync(CancellationToken ct)
    {
        var target = "1.1.1.1";
        try { target = await _settings.GetStringAsync("diagnostics.probe_default_target", ct); }
        catch (Exception ex) { _logger.LogDebug(ex, "probe default target setting unavailable"); }

        return new DiagToolPageViewModel
        {
            Interfaces = await _fw.GetInterfacesAsync(ct),
            Marks = await _fw.GetTrafficMarksAsync(ct),
            DefaultTarget = string.IsNullOrWhiteSpace(target) ? "1.1.1.1" : target,
            DaemonEnabled = _daemon is not NullDaemonClient,
        };
    }

    /// <summary>
    /// A completed run renders its partial (the verdict lives in the status pill);
    /// the toast is green only for <c>ok</c>. No data (daemon disabled, validation
    /// refused upstream, gate busy) → JSON + toast, HTMX leaves the result area as it was.
    /// </summary>
    private IActionResult RenderRun<T>(ServiceResponse<DiagRunEnvelope<T>> env, string partial)
    {
        var ok = env.Success && env.Data?.Status == DiagRunStatus.Ok;
        this.AttachToastTrigger(ok ? env : new ServiceResponse<DiagRunEnvelope<T>> { Success = false, Message = env.Message, Data = env.Data });

        if (env.Data is null || env.Data.Status == DiagRunStatus.Busy)
        {
            Response.StatusCode = env.Data?.Status == DiagRunStatus.Busy ? 409 : 400;
            return Json(env);
        }
        return PartialView(partial, env.Data);
    }

    private IActionResult Invalid<T>() =>
        this.ToHtmxResponse(ServiceResponse<DiagRunEnvelope<T>>.Fail("Form validation failed: " +
            string.Join(" ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage))));

    private static string? Blank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}
