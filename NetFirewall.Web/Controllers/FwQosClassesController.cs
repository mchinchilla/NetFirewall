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
[Route("/Firewall/Qos/{configId:guid}/Classes")]
public sealed class FwQosClassesController : Controller
{
    private readonly IFirewallService _firewall;
    private readonly ILogger<FwQosClassesController> _logger;

    public FwQosClassesController(IFirewallService firewall, ILogger<FwQosClassesController> logger)
    {
        _firewall = firewall;
        _logger = logger;
    }

    [HttpGet("")]
    public async Task<IActionResult> Index(Guid configId, CancellationToken ct)
    {
        var config = await _firewall.GetQosConfigByIdAsync(configId, ct);
        if (config is null) return NotFound();
        var ifaces = await _firewall.GetInterfacesAsync(ct);
        ViewBag.Config = config;
        ViewBag.InterfaceName = ifaces.FirstOrDefault(i => i.Id == config.InterfaceId)?.Name ?? "(unknown)";
        return View();
    }

    [HttpGet("table")]
    public async Task<IActionResult> Table(Guid configId, CancellationToken ct)
    {
        var rows = await _firewall.GetQosClassesAsync(configId, ct);
        var marks = await _firewall.GetTrafficMarksAsync(ct);
        ViewBag.MarkNames = marks.ToDictionary(m => m.Id, m => $"{m.Name} (0x{m.MarkValue:X})");
        ViewBag.ConfigId = configId;
        return PartialView("_QosClassesTable", rows);
    }

    [HttpGet("edit/{id:guid?}")]
    public async Task<IActionResult> Edit(Guid configId, Guid? id, CancellationToken ct)
    {
        ViewBag.Marks = await _firewall.GetTrafficMarksAsync(ct);
        if (id is null)
            return PartialView("_QosClassForm", new QosClassFormViewModel { QosConfigId = configId });

        var classes = await _firewall.GetQosClassesAsync(configId, ct);
        var c = classes.FirstOrDefault(x => x.Id == id);
        return c is null ? NotFound() : PartialView("_QosClassForm", FromEntity(c));
    }

    [HttpPost("save"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(Guid configId, QosClassFormViewModel form, CancellationToken ct)
    {
        try
        {
            var entity = ToEntity(form);
            FwQosClass saved;
            var existing = (await _firewall.GetQosClassesAsync(configId, ct)).FirstOrDefault(x => x.Id == form.Id);
            if (existing is not null)
            {
                entity.Id = existing.Id;
                saved = await _firewall.UpdateQosClassAsync(entity, ct);
            }
            else
            {
                saved = await _firewall.CreateQosClassAsync(entity, ct);
            }
            var envelope = ServiceResponse<FwQosClass>.Ok(saved,
                $"Class '{saved.Name}' saved ({saved.GuaranteedMbps}/{saved.CeilingMbps} Mbps, prio {saved.Priority}).");
            this.AttachToastTrigger(envelope);
            Response.Headers["HX-Trigger"] = "refreshQosClasses";
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save QoS class");
            return this.ToHtmxResponse(ServiceResponse<FwQosClass>.Fail($"Save failed: {ex.Message}"));
        }
    }

    [HttpPost("delete/{id:guid}"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    public async Task<IActionResult> Delete(Guid configId, Guid id, CancellationToken ct)
    {
        _ = configId;
        var ok = await _firewall.DeleteQosClassAsync(id, ct);
        Response.Headers["HX-Trigger"] = "refreshQosClasses";
        return this.ToHtmxResponse(ok
            ? ServiceResponse<object>.Ok(new { }, "Class deleted.")
            : ServiceResponse<object>.Fail("Class not found."));
    }

    private static QosClassFormViewModel FromEntity(FwQosClass c) => new()
    {
        Id = c.Id, QosConfigId = c.QosConfigId ?? Guid.Empty, Name = c.Name,
        MarkId = c.MarkId,
        GuaranteedMbps = c.GuaranteedMbps, CeilingMbps = c.CeilingMbps,
        Priority = c.Priority
    };

    private static FwQosClass ToEntity(QosClassFormViewModel f) => new()
    {
        QosConfigId = f.QosConfigId, Name = f.Name,
        MarkId = f.MarkId,
        GuaranteedMbps = f.GuaranteedMbps, CeilingMbps = f.CeilingMbps,
        Priority = f.Priority
    };
}
