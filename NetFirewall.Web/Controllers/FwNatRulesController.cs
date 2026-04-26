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
[Route("/Firewall/NatRules")]
public sealed class FwNatRulesController : Controller
{
    private readonly IFirewallService _firewall;
    private readonly ILogger<FwNatRulesController> _logger;

    public FwNatRulesController(IFirewallService firewall, ILogger<FwNatRulesController> logger)
    {
        _firewall = firewall;
        _logger = logger;
    }

    [HttpGet("")]
    public IActionResult Index() => View();

    [HttpGet("table")]
    public async Task<IActionResult> Table(CancellationToken ct)
    {
        var rows = await _firewall.GetNatRulesAsync(ct);
        var ifaces = await _firewall.GetInterfacesAsync(ct);
        ViewBag.InterfaceNames = ifaces.ToDictionary(i => i.Id, i => i.Name);
        return PartialView("_NatRulesTable", rows);
    }

    [HttpGet("edit/{id:guid?}")]
    public async Task<IActionResult> Edit(Guid? id, CancellationToken ct)
    {
        ViewBag.Interfaces = await _firewall.GetInterfacesAsync(ct);
        if (id is null) return PartialView("_NatRuleForm", new NatRuleFormViewModel());
        var r = await _firewall.GetNatRuleByIdAsync(id.Value, ct);
        return r is null ? NotFound() : PartialView("_NatRuleForm", FromEntity(r));
    }

    [HttpPost("save"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(NatRuleFormViewModel form, CancellationToken ct)
    {
        try
        {
            var entity = ToEntity(form);
            FwNatRule saved;
            if (form.Id.HasValue && await _firewall.GetNatRuleByIdAsync(form.Id.Value, ct) is not null)
            {
                entity.Id = form.Id.Value;
                saved = await _firewall.UpdateNatRuleAsync(entity, ct);
            }
            else
            {
                saved = await _firewall.CreateNatRuleAsync(entity, ct);
            }
            var envelope = ServiceResponse<FwNatRule>.Ok(saved, $"NAT rule {saved.Type} for {saved.SourceNetwork} saved.");
            this.AttachToastTrigger(envelope);
            Response.Headers["HX-Trigger"] = "refreshNatRules";
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save NAT rule");
            return this.ToHtmxResponse(ServiceResponse<FwNatRule>.Fail($"Save failed: {ex.Message}"));
        }
    }

    [HttpPost("delete/{id:guid}"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var ok = await _firewall.DeleteNatRuleAsync(id, ct);
        Response.Headers["HX-Trigger"] = "refreshNatRules";
        return this.ToHtmxResponse(ok
            ? ServiceResponse<object>.Ok(new { }, "NAT rule deleted.")
            : ServiceResponse<object>.Fail("Rule not found."));
    }

    private static NatRuleFormViewModel FromEntity(FwNatRule r) => new()
    {
        Id = r.Id, Type = r.Type, Description = r.Description,
        SourceNetwork = r.SourceNetwork,
        OutputInterfaceId = r.OutputInterfaceId,
        SnatAddress = r.SnatAddress?.ToString(),
        Priority = r.Priority, Enabled = r.Enabled
    };

    private static FwNatRule ToEntity(NatRuleFormViewModel f) => new()
    {
        Type = f.Type, Description = f.Description,
        SourceNetwork = f.SourceNetwork,
        OutputInterfaceId = f.OutputInterfaceId,
        SnatAddress = string.IsNullOrWhiteSpace(f.SnatAddress) ? null : IPAddress.Parse(f.SnatAddress),
        Priority = f.Priority, Enabled = f.Enabled
    };
}
