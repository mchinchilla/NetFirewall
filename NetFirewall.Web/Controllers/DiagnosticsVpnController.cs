using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Daemon;
using NetFirewall.Services.Diagnostics;
using NetFirewall.Services.Vpn;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models.Diagnostics;
using NetFirewall.Web.Models.Vpn;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// The VPN doctor page: run the checklist, probe the data plane, and compare what
/// we run against the config the remote admin issued. Read-only like the rest of
/// Diagnostics — the remedies are links to the pages that already apply changes.
/// </summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Diagnostics/Vpn")]
public sealed class DiagnosticsVpnController : Controller
{
    private readonly IDaemonClient _daemon;
    private readonly IWireGuardService _wg;
    private readonly IDiagnosticInputValidator _validator;

    public DiagnosticsVpnController(IDaemonClient daemon, IWireGuardService wg, IDiagnosticInputValidator validator)
    {
        _daemon = daemon;
        _wg = wg;
        _validator = validator;
    }

    [HttpGet("")]
    public async Task<IActionResult> Index([FromQuery] string? iface, CancellationToken ct)
    {
        // Which interface to diagnose: ?iface= (server or an outbound connection), else the first.
        var servers = await _wg.ListServersAsync(ct);
        var server = servers.FirstOrDefault(s => s.Name == iface) ?? servers.FirstOrDefault();
        ViewBag.ServerName = server?.Name;
        ViewBag.Interfaces = servers.Select(s => s.Name).ToArray();
        ViewBag.DaemonEnabled = _daemon is not NullDaemonClient;
        return View();
    }

    /// <summary>Compact live status, reusing the WireGuard page's own partial.</summary>
    [HttpGet("status")]
    public async Task<IActionResult> Status([FromQuery] string? iface, CancellationToken ct)
    {
        var servers = await _wg.ListServersAsync(ct);
        var server = servers.FirstOrDefault(s => s.Name == iface) ?? servers.FirstOrDefault();
        if (server is null)
            return PartialView("~/Views/WireGuard/_Status.cshtml", new WgStatusViewModel
            {
                Server = null,
                Peers = Array.Empty<NetFirewall.Models.Vpn.WgPeer>(),
                Status = Array.Empty<NetFirewall.Models.Vpn.WgPeerLiveStatus>(),
            });

        var status = await _daemon.GetWireGuardStatusAsync(server.Name, ct);
        return PartialView("~/Views/WireGuard/_Status.cshtml", new WgStatusViewModel
        {
            Server = server,
            Peers = await _wg.GetPeersAsync(server.Id, ct),
            Status = status.Data ?? Array.Empty<NetFirewall.Models.Vpn.WgPeerLiveStatus>(),
        });
    }

    [HttpPost("run"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Run([FromForm] string? iface, CancellationToken ct)
    {
        if (iface is { Length: > 0 } && !NetFirewall.Models.Vpn.WgInterfaceName.IsValid(iface))
            return this.ToHtmxResponse(ServiceResponse<object>.Fail("Invalid WireGuard interface name."));
        var env = await _daemon.RunVpnDoctorAsync(new VpnDoctorRequest(Interface: iface), ct);
        if (env.Data?.Result is null)
        {
            this.AttachToastTrigger(ServiceResponse<object>.Fail(env.Message ?? "The doctor could not run."));
            Response.StatusCode = env.Data?.Status == DiagRunStatus.Busy ? 409 : 400;
            return Json(env);
        }
        this.AttachToastTrigger(env.Data.Status == DiagRunStatus.Ok
            ? ServiceResponse<object>.Ok(new { }, env.Message ?? "All checks passed.")
            : ServiceResponse<object>.Fail(env.Message ?? "Checks found problems."));
        return PartialView("_DoctorReport", env.Data);
    }

    [HttpPost("probe"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Probe(VpnProbeFormViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid)
            return this.ToHtmxResponse(ServiceResponse<object>.Fail("Form validation failed: " +
                string.Join(" ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage))));

        var iface = Request.HasFormContentType ? Request.Form["iface"].ToString() : null;
        if (iface is { Length: > 0 } && !NetFirewall.Models.Vpn.WgInterfaceName.IsValid(iface))
            return this.ToHtmxResponse(ServiceResponse<object>.Fail("Invalid WireGuard interface name."));
        var env = await _daemon.RunVpnProbeAsync(new VpnProbeRequest(
            string.IsNullOrWhiteSpace(form.Target) ? null : form.Target.Trim(), form.Mode,
            string.IsNullOrEmpty(iface) ? null : iface), ct);
        if (env.Data?.Result is null)
        {
            this.AttachToastTrigger(ServiceResponse<object>.Fail(env.Message ?? "The probe could not run."));
            Response.StatusCode = env.Data?.Status == DiagRunStatus.Busy ? 409 : 400;
            return Json(env);
        }
        this.AttachToastTrigger(env.Data.Status == DiagRunStatus.Ok
            ? ServiceResponse<object>.Ok(new { }, env.Message ?? "Probe finished.")
            : ServiceResponse<object>.Fail(env.Message ?? "The probe found a problem."));
        return PartialView("_ProbeResult", env.Data);
    }

    [HttpPost("compare"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Compare(VpnCompareFormViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid)
            return this.ToHtmxResponse(ServiceResponse<object>.Fail("Form validation failed: " +
                string.Join(" ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage))));

        // Strip the keys here, at the edge, so a private key never leaves the browser's request.
        var redacted = _validator.RedactWgConfig(form.ConfigText ?? string.Empty);
        var iface = Request.HasFormContentType ? Request.Form["iface"].ToString() : null;
        if (iface is { Length: > 0 } && !NetFirewall.Models.Vpn.WgInterfaceName.IsValid(iface))
            return this.ToHtmxResponse(ServiceResponse<object>.Fail("Invalid WireGuard interface name."));
        var env = await _daemon.RunVpnCompareAsync(new VpnCompareRequest(redacted, string.IsNullOrEmpty(iface) ? null : iface), ct);
        if (env.Data?.Result is null)
        {
            this.AttachToastTrigger(ServiceResponse<object>.Fail(env.Message ?? "The comparison could not run."));
            Response.StatusCode = 400;
            return Json(env);
        }
        this.AttachToastTrigger(env.Data.Status == DiagRunStatus.Ok
            ? ServiceResponse<object>.Ok(new { }, env.Message ?? "Configs match.")
            : ServiceResponse<object>.Fail(env.Message ?? "The configs differ."));
        return PartialView("_CompareResult", env.Data);
    }
}
