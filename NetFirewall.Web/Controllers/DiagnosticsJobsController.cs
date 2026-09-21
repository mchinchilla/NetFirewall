using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Daemon;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Settings;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models.Diagnostics;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// The two invasive diagnostics: the flow inspector (a temporary nftables table
/// plus <c>nft monitor trace</c>) and bounded packet capture. Both mutate the box
/// or write raw traffic to disk, so unlike the rest of Diagnostics they are
/// **Admin only behind TOTP step-up** and audited at start, cancel and download.
///
/// They also outlive a request: the daemon runs them as jobs and the page polls
/// the job until it finishes. Only one may run at a time, box-wide.
/// </summary>
[Authorize(Roles = UserRoles.Admin)]
[Route("/Diagnostics/Jobs")]
public sealed class DiagnosticsJobsController : Controller
{
    private readonly IDaemonClient _daemon;
    private readonly IFirewallService _fw;
    private readonly IAppSettingsService _settings;
    private readonly ILogger<DiagnosticsJobsController> _logger;

    public DiagnosticsJobsController(IDaemonClient daemon, IFirewallService fw, IAppSettingsService settings, ILogger<DiagnosticsJobsController> logger)
    {
        _daemon = daemon;
        _fw = fw;
        _settings = settings;
        _logger = logger;
    }

    // ───────────────────────── flow inspector ─────────────────────────

    [HttpGet("~/Diagnostics/trace")]
    public async Task<IActionResult> Trace(CancellationToken ct) => View("Trace", new JobPageViewModel(await PageAsync(ct)));

    [HttpPost("trace/start"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    public async Task<IActionResult> TraceStart(TraceFormViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid) return Invalid();
        if (!form.HasMatcher)
            return this.ToHtmxResponse(ServiceResponse<object>.Fail(
                "Give at least one matcher — an unfiltered trace marks every packet on the firewall."));

        var env = await _daemon.StartTraceAsync(new TraceRequest(
            Blank(form.Src), Blank(form.Dst), Blank(form.Protocol), form.Port,
            Blank(form.Interface), form.DurationSec, form.MaxEvents), ct);

        return StartedOrToast(env, DiagJobKind.Trace);
    }

    // ───────────────────────── packet capture ─────────────────────────

    [HttpGet("~/Diagnostics/capture")]
    public async Task<IActionResult> Capture(CancellationToken ct) => View("Capture", new JobPageViewModel(await PageAsync(ct)));

    [HttpPost("capture/start"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    public async Task<IActionResult> CaptureStart(CaptureFormViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid) return Invalid();

        var env = await _daemon.StartCaptureAsync(new CaptureRequest(
            form.Interface.Trim(), Blank(form.Filter), form.DurationSec, form.MaxPackets, form.Snaplen), ct);

        return StartedOrToast(env, DiagJobKind.Capture);
    }

    // ───────────────────────── job lifecycle ─────────────────────────

    /// <summary>Polled by the panel every 2 s while the job runs; the panel stops polling itself when it does not.</summary>
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Status(Guid id, CancellationToken ct)
    {
        var env = await _daemon.GetDiagJobAsync(id, ct);
        return PartialView("_JobPanel", new PanelViewModel<DiagJobSnapshot>(env.Data, env.Success ? null : env.Message));
    }

    [HttpPost("{id:guid}/cancel"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    public async Task<IActionResult> Cancel(Guid id, CancellationToken ct)
    {
        var env = await _daemon.CancelDiagJobAsync(id, ct);
        this.AttachToastTrigger(env);
        var job = await _daemon.GetDiagJobAsync(id, ct);
        return PartialView("_JobPanel", new PanelViewModel<DiagJobSnapshot>(job.Data, job.Success ? null : job.Message));
    }

    [HttpGet("{id:guid}/download")]
    [Filters.RequireElevated]
    public async Task<IActionResult> Download(Guid id, CancellationToken ct)
    {
        var stream = await _daemon.DownloadCaptureAsync(id, ct);
        if (stream is null) return NotFound();

        var job = await _daemon.GetDiagJobAsync(id, ct);
        var name = job.Data?.Capture?.FileName ?? $"netfirewall-{id:N}.pcap";
        // Streamed straight through: a 2000-packet capture at full snaplen is tens of MB.
        return File(stream, "application/vnd.tcpdump.pcap", name);
    }

    [HttpPost("{id:guid}/delete"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var env = await _daemon.DeleteCaptureAsync(id, ct);
        var resp = this.ToHtmxResponse(env);
        this.AttachHxEvent("refreshDiagJobs", new { });
        return resp;
    }

    // ───────────────────────── helpers ─────────────────────────

    private async Task<DiagToolPageViewModel> PageAsync(CancellationToken ct)
    {
        var target = "1.1.1.1";
        try { target = await _settings.GetStringAsync("diagnostics.probe_default_target", ct); }
        catch (Exception ex) { _logger.LogDebug(ex, "probe default target unavailable"); }

        return new DiagToolPageViewModel
        {
            Interfaces = await _fw.GetInterfacesAsync(ct),
            Marks = await _fw.GetTrafficMarksAsync(ct),
            DefaultTarget = string.IsNullOrWhiteSpace(target) ? "1.1.1.1" : target,
            DaemonEnabled = _daemon is not NullDaemonClient,
        };
    }

    /// <summary>On success swap in the polling panel; otherwise leave the page alone and toast why.</summary>
    private IActionResult StartedOrToast(ServiceResponse<Guid> env, DiagJobKind kind)
    {
        if (!env.Success || env.Data == Guid.Empty)
        {
            this.AttachToastTrigger(env);
            // 409 = the single invasive slot is taken; anything else is a bad request.
            Response.StatusCode = (env.Message ?? string.Empty).Contains("already running", StringComparison.OrdinalIgnoreCase) ? 409 : 400;
            return Json(env);
        }
        this.AttachToastTrigger(ServiceResponse<object>.Ok(new { }, env.Message ?? "Started."));
        // Optimistic first frame so the panel appears immediately; the poll it starts
        // replaces it with the daemon's own snapshot ~2 s later. The kind has to be the
        // caller's — hardcoding Trace here labelled every capture "Flow inspector".
        return PartialView("_JobPanel", new PanelViewModel<DiagJobSnapshot>(
            new DiagJobSnapshot(env.Data, kind, DiagJobState.Running, DateTime.UtcNow, null, 0, User.Identity?.Name, "starting…", 0, false, null), null));
    }

    private IActionResult Invalid() =>
        this.ToHtmxResponse(ServiceResponse<object>.Fail("Form validation failed: " +
            string.Join(" ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage))));

    private static string? Blank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}
