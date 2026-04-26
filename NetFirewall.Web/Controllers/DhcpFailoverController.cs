using System.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models.Dhcp;

namespace NetFirewall.Web.Controllers;

[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Dhcp/Failover")]
public sealed class DhcpFailoverController : Controller
{
    private readonly IDhcpAdminService _admin;
    private readonly ILogger<DhcpFailoverController> _logger;

    public DhcpFailoverController(IDhcpAdminService admin, ILogger<DhcpFailoverController> logger)
    {
        _admin = admin;
        _logger = logger;
    }

    [HttpGet("")]
    public async Task<IActionResult> Index(CancellationToken ct)
    {
        ViewBag.Status = await _admin.GetFailoverStatusAsync(ct);
        return View();
    }

    [HttpGet("table")]
    public async Task<IActionResult> Table(CancellationToken ct)
    {
        var rows = await _admin.GetFailoverPeersAsync(ct);
        return PartialView("_FailoverTable", rows);
    }

    [HttpGet("edit/{id:guid?}")]
    public async Task<IActionResult> Edit(Guid? id, CancellationToken ct)
    {
        if (id is null) return PartialView("_FailoverForm", new FailoverPeerFormViewModel());
        var p = await _admin.GetFailoverPeerByIdAsync(id.Value, ct);
        return p is null ? NotFound() : PartialView("_FailoverForm", FromEntity(p));
    }

    [HttpPost("save"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(FailoverPeerFormViewModel form, CancellationToken ct)
    {
        try
        {
            var entity = ToEntity(form);
            FailoverPeer saved;
            if (form.Id.HasValue && await _admin.GetFailoverPeerByIdAsync(form.Id.Value, ct) is not null)
            {
                entity.Id = form.Id.Value;
                saved = await _admin.UpdateFailoverPeerAsync(entity, ct);
            }
            else
            {
                saved = await _admin.CreateFailoverPeerAsync(entity, ct);
            }
            var envelope = ServiceResponse<FailoverPeer>.Ok(saved, $"Peer '{saved.Name}' saved.");
            this.AttachToastTrigger(envelope);
            Response.Headers["HX-Trigger"] = "refreshFailover";
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save failover peer");
            return this.ToHtmxResponse(ServiceResponse<FailoverPeer>.Fail($"Save failed: {ex.Message}"));
        }
    }

    [HttpPost("delete/{id:guid}"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var ok = await _admin.DeleteFailoverPeerAsync(id, ct);
        Response.Headers["HX-Trigger"] = "refreshFailover";
        return this.ToHtmxResponse(ok
            ? ServiceResponse<object>.Ok(new { }, "Peer deleted.")
            : ServiceResponse<object>.Fail("Peer not found."));
    }

    private static FailoverPeerFormViewModel FromEntity(FailoverPeer p) => new()
    {
        Id = p.Id, Name = p.Name, Role = p.Role,
        PeerAddress = p.PeerAddress.ToString(), PeerPort = p.PeerPort,
        LocalAddress = p.LocalAddress?.ToString(), LocalPort = p.LocalPort,
        MaxResponseDelay = p.MaxResponseDelay, MaxUnackedUpdates = p.MaxUnackedUpdates,
        Mclt = p.Mclt, Split = p.Split,
        LoadBalanceMax = p.LoadBalanceMax, AutoPartnerDown = p.AutoPartnerDown,
        SharedSecret = p.SharedSecret, Enabled = p.Enabled
    };

    private static FailoverPeer ToEntity(FailoverPeerFormViewModel f) => new()
    {
        Name = f.Name, Role = f.Role,
        PeerAddress = IPAddress.Parse(f.PeerAddress), PeerPort = f.PeerPort,
        LocalAddress = string.IsNullOrWhiteSpace(f.LocalAddress) ? null : IPAddress.Parse(f.LocalAddress),
        LocalPort = f.LocalPort,
        MaxResponseDelay = f.MaxResponseDelay, MaxUnackedUpdates = f.MaxUnackedUpdates,
        Mclt = f.Mclt, Split = f.Split,
        LoadBalanceMax = f.LoadBalanceMax, AutoPartnerDown = f.AutoPartnerDown,
        SharedSecret = f.SharedSecret, Enabled = f.Enabled
    };
}
