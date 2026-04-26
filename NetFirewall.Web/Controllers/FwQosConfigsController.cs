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
[Route("/Firewall/Qos")]
public sealed class FwQosConfigsController : Controller
{
    private readonly IFirewallService _firewall;
    private readonly ILogger<FwQosConfigsController> _logger;

    public FwQosConfigsController(IFirewallService firewall, ILogger<FwQosConfigsController> logger)
    {
        _firewall = firewall;
        _logger = logger;
    }

    [HttpGet("")]
    public IActionResult Index() => View();

    [HttpGet("table")]
    public async Task<IActionResult> Table(CancellationToken ct)
    {
        var rows = await _firewall.GetQosConfigsAsync(ct);
        var ifaces = await _firewall.GetInterfacesAsync(ct);
        ViewBag.InterfaceNames = ifaces.ToDictionary(i => i.Id, i => i.Name);
        return PartialView("_QosConfigsTable", rows);
    }

    [HttpGet("edit/{id:guid?}")]
    public async Task<IActionResult> Edit(Guid? id, CancellationToken ct)
    {
        ViewBag.Interfaces = await _firewall.GetInterfacesAsync(ct);
        if (id is null) return PartialView("_QosConfigForm", new QosConfigFormViewModel());
        var c = await _firewall.GetQosConfigByIdAsync(id.Value, ct);
        return c is null ? NotFound() : PartialView("_QosConfigForm", FromEntity(c));
    }

    [HttpPost("save"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(QosConfigFormViewModel form, CancellationToken ct)
    {
        try
        {
            var entity = ToEntity(form);
            FwQosConfig saved;
            if (form.Id.HasValue && await _firewall.GetQosConfigByIdAsync(form.Id.Value, ct) is not null)
            {
                entity.Id = form.Id.Value;
                saved = await _firewall.UpdateQosConfigAsync(entity, ct);
            }
            else
            {
                saved = await _firewall.CreateQosConfigAsync(entity, ct);
            }
            var envelope = ServiceResponse<FwQosConfig>.Ok(saved, $"QoS config saved ({saved.TotalBandwidthMbps} Mbps).");
            this.AttachToastTrigger(envelope);
            Response.Headers["HX-Trigger"] = "refreshQosConfigs";
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save QoS config");
            return this.ToHtmxResponse(ServiceResponse<FwQosConfig>.Fail($"Save failed: {ex.Message}"));
        }
    }

    [HttpPost("delete/{id:guid}"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var ok = await _firewall.DeleteQosConfigAsync(id, ct);
        Response.Headers["HX-Trigger"] = "refreshQosConfigs";
        return this.ToHtmxResponse(ok
            ? ServiceResponse<object>.Ok(new { }, "QoS config deleted (cascades classes).")
            : ServiceResponse<object>.Fail("Config not found."));
    }

    private static QosConfigFormViewModel FromEntity(FwQosConfig c) => new()
    {
        Id = c.Id, InterfaceId = c.InterfaceId ?? Guid.Empty,
        TotalBandwidthMbps = c.TotalBandwidthMbps,
        Enabled = c.Enabled
    };

    private static FwQosConfig ToEntity(QosConfigFormViewModel f) => new()
    {
        InterfaceId = f.InterfaceId,
        TotalBandwidthMbps = f.TotalBandwidthMbps,
        Enabled = f.Enabled
    };
}
