using System.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Firewall;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models.Firewall;

namespace NetFirewall.Web.Controllers;

[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Firewall/PortForwards")]
public sealed class FwPortForwardsController : Controller
{
    private readonly IFirewallService _firewall;
    private readonly ILogger<FwPortForwardsController> _logger;

    public FwPortForwardsController(IFirewallService firewall, ILogger<FwPortForwardsController> logger)
    {
        _firewall = firewall;
        _logger = logger;
    }

    [HttpGet("")]
    public IActionResult Index() => View();

    [HttpGet("table")]
    public async Task<IActionResult> Table(CancellationToken ct)
    {
        var rows = await _firewall.GetPortForwardsAsync(ct);
        var ifaces = await _firewall.GetInterfacesAsync(ct);
        ViewBag.InterfaceNames = ifaces.ToDictionary(i => i.Id, i => i.Name);
        return PartialView("_PortForwardsTable", rows);
    }

    [HttpGet("edit/{id:guid?}")]
    public async Task<IActionResult> Edit(Guid? id, CancellationToken ct)
    {
        ViewBag.Interfaces = await _firewall.GetInterfacesAsync(ct);
        if (id is null) return PartialView("_PortForwardForm", new PortForwardFormViewModel());
        var r = await _firewall.GetPortForwardByIdAsync(id.Value, ct);
        return r is null ? NotFound() : PartialView("_PortForwardForm", FromEntity(r));
    }

    [HttpPost("save"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(PortForwardFormViewModel form, CancellationToken ct)
    {
        try
        {
            var entity = ToEntity(form);
            FwPortForward saved;
            if (form.Id.HasValue && await _firewall.GetPortForwardByIdAsync(form.Id.Value, ct) is not null)
            {
                entity.Id = form.Id.Value;
                saved = await _firewall.UpdatePortForwardAsync(entity, ct);
            }
            else
            {
                saved = await _firewall.CreatePortForwardAsync(entity, ct);
            }
            var envelope = ServiceResponse<FwPortForward>.Ok(saved,
                $"Port forward {saved.Protocol}/{saved.ExternalPortStart} → {saved.InternalIp}:{saved.InternalPort} saved.");
            this.AttachToastTrigger(envelope);
            Response.Headers["HX-Trigger"] = "refreshPortForwards";
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save port forward");
            return this.ToHtmxResponse(ServiceResponse<FwPortForward>.Fail($"Save failed: {ex.Message}"));
        }
    }

    [HttpPost("delete/{id:guid}"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var ok = await _firewall.DeletePortForwardAsync(id, ct);
        Response.Headers["HX-Trigger"] = "refreshPortForwards";
        return this.ToHtmxResponse(ok
            ? ServiceResponse<object>.Ok(new { }, "Port forward deleted.")
            : ServiceResponse<object>.Fail("Forward not found."));
    }

    private static PortForwardFormViewModel FromEntity(FwPortForward r) => new()
    {
        Id = r.Id, Description = r.Description, Protocol = r.Protocol,
        InterfaceId = r.InterfaceId,
        SourceAddresses = FwArrayHelpers.Join(r.SourceAddresses),
        ExternalPortStart = r.ExternalPortStart,
        ExternalPortEnd = r.ExternalPortEnd,
        InternalIp = r.InternalIp.ToString(),
        InternalPort = r.InternalPort,
        Priority = r.Priority, Enabled = r.Enabled
    };

    private static FwPortForward ToEntity(PortForwardFormViewModel f) => new()
    {
        Description = f.Description, Protocol = f.Protocol,
        InterfaceId = f.InterfaceId,
        SourceAddresses = FwArrayHelpers.Split(f.SourceAddresses),
        ExternalPortStart = f.ExternalPortStart,
        ExternalPortEnd = f.ExternalPortEnd,
        InternalIp = IPAddress.Parse(f.InternalIp),
        InternalPort = f.InternalPort,
        Priority = f.Priority, Enabled = f.Enabled
    };
}
