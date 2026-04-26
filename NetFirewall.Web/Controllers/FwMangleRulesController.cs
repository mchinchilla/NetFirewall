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
[Route("/Firewall/MangleRules")]
public sealed class FwMangleRulesController : Controller
{
    private readonly IFirewallService _firewall;
    private readonly ILogger<FwMangleRulesController> _logger;

    public FwMangleRulesController(IFirewallService firewall, ILogger<FwMangleRulesController> logger)
    {
        _firewall = firewall;
        _logger = logger;
    }

    [HttpGet("")]
    public IActionResult Index() => View();

    [HttpGet("table")]
    public async Task<IActionResult> Table([FromQuery] string? chain, CancellationToken ct)
    {
        var rows = await _firewall.GetMangleRulesAsync(chain, ct);
        var marks = await _firewall.GetTrafficMarksAsync(ct);
        ViewBag.MarkNames = marks.ToDictionary(m => m.Id, m => $"{m.Name} (0x{m.MarkValue:X})");
        ViewBag.ChainFilter = chain;
        return PartialView("_MangleRulesTable", rows);
    }

    [HttpGet("edit/{id:guid?}")]
    public async Task<IActionResult> Edit(Guid? id, CancellationToken ct)
    {
        ViewBag.Marks = await _firewall.GetTrafficMarksAsync(ct);
        if (id is null) return PartialView("_MangleRuleForm", new MangleRuleFormViewModel());
        var r = await _firewall.GetMangleRuleByIdAsync(id.Value, ct);
        return r is null ? NotFound() : PartialView("_MangleRuleForm", FromEntity(r));
    }

    [HttpPost("save"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(MangleRuleFormViewModel form, CancellationToken ct)
    {
        try
        {
            var entity = ToEntity(form);
            FwMangleRule saved;
            if (form.Id.HasValue && await _firewall.GetMangleRuleByIdAsync(form.Id.Value, ct) is not null)
            {
                entity.Id = form.Id.Value;
                saved = await _firewall.UpdateMangleRuleAsync(entity, ct);
            }
            else
            {
                saved = await _firewall.CreateMangleRuleAsync(entity, ct);
            }
            var envelope = ServiceResponse<FwMangleRule>.Ok(saved, $"Mangle rule on {saved.Chain} saved.");
            this.AttachToastTrigger(envelope);
            Response.Headers["HX-Trigger"] = "refreshMangleRules";
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save mangle rule");
            return this.ToHtmxResponse(ServiceResponse<FwMangleRule>.Fail($"Save failed: {ex.Message}"));
        }
    }

    [HttpPost("delete/{id:guid}"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var ok = await _firewall.DeleteMangleRuleAsync(id, ct);
        Response.Headers["HX-Trigger"] = "refreshMangleRules";
        return this.ToHtmxResponse(ok
            ? ServiceResponse<object>.Ok(new { }, "Mangle rule deleted.")
            : ServiceResponse<object>.Fail("Rule not found."));
    }

    private static MangleRuleFormViewModel FromEntity(FwMangleRule r) => new()
    {
        Id = r.Id, Chain = r.Chain, Description = r.Description,
        MarkId = r.MarkId, Protocol = r.Protocol,
        SourceAddresses = FwArrayHelpers.Join(r.SourceAddresses),
        DestinationAddresses = FwArrayHelpers.Join(r.DestinationAddresses),
        DestinationPorts = FwArrayHelpers.Join(r.DestinationPorts),
        Priority = r.Priority, Enabled = r.Enabled
    };

    private static FwMangleRule ToEntity(MangleRuleFormViewModel f) => new()
    {
        Chain = f.Chain, Description = f.Description,
        MarkId = f.MarkId, Protocol = f.Protocol,
        SourceAddresses = FwArrayHelpers.Split(f.SourceAddresses),
        DestinationAddresses = FwArrayHelpers.Split(f.DestinationAddresses),
        DestinationPorts = FwArrayHelpers.Split(f.DestinationPorts),
        Priority = f.Priority, Enabled = f.Enabled
    };
}
