using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Daemon;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models.Diagnostics;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// The WAN, DHCP and DNS doctors. They differ only in which checks the daemon
/// runs, so one controller and one view serve all three — the report itself is
/// rendered by the shared <c>_DiagCheckList</c> the VPN doctor uses.
/// </summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Diagnostics")]
public sealed class DiagnosticsDoctorsController : Controller
{
    private readonly IDaemonClient _daemon;

    public DiagnosticsDoctorsController(IDaemonClient daemon) => _daemon = daemon;

    [HttpGet("Wan")]
    public IActionResult Wan() => View("Doctor", DoctorPageViewModel.Wan(DaemonEnabled));

    [HttpPost("Wan/run"), ValidateAntiForgeryToken]
    public async Task<IActionResult> WanRun(CancellationToken ct) =>
        Render(await _daemon.RunWanDoctorAsync(ct), DiagTools.WanDoctor);

    [HttpGet("Dhcp")]
    public IActionResult Dhcp() => View("Doctor", DoctorPageViewModel.Dhcp(DaemonEnabled));

    [HttpPost("Dhcp/run"), ValidateAntiForgeryToken]
    public async Task<IActionResult> DhcpRun(CancellationToken ct) =>
        Render(await _daemon.RunDhcpDoctorAsync(ct), DiagTools.DhcpDoctor);

    [HttpGet("Dns")]
    public IActionResult Dns() => View("Doctor", DoctorPageViewModel.Dns(DaemonEnabled));

    [HttpPost("Dns/run"), ValidateAntiForgeryToken]
    public async Task<IActionResult> DnsRun(CancellationToken ct) =>
        Render(await _daemon.RunDnsDoctorAsync(ct), DiagTools.DnsDoctor);

    private bool DaemonEnabled => _daemon is not NullDaemonClient;

    private IActionResult Render(ServiceResponse<DiagRunEnvelope<DiagReport>> env, string tool)
    {
        if (env.Data?.Result is null)
        {
            this.AttachToastTrigger(ServiceResponse<object>.Fail(env.Message ?? "The doctor could not run."));
            Response.StatusCode = env.Data?.Status == DiagRunStatus.Busy ? 409 : 400;
            return Json(env);
        }
        // Green toast only when nothing needs attention; the pills carry the detail.
        this.AttachToastTrigger(env.Data.Status == DiagRunStatus.Ok
            ? ServiceResponse<object>.Ok(new { }, env.Message ?? "All checks passed.")
            : ServiceResponse<object>.Fail(env.Message ?? "Checks found problems."));
        return PartialView("~/Views/DiagnosticsVpn/_DoctorReport.cshtml", env.Data);
    }
}
