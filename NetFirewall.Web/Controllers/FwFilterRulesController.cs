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
[Route("/Firewall/FilterRules")]
public sealed class FwFilterRulesController : Controller
{
    private readonly IFirewallService _firewall;
    private readonly ILogger<FwFilterRulesController> _logger;

    public FwFilterRulesController(IFirewallService firewall, ILogger<FwFilterRulesController> logger)
    {
        _firewall = firewall;
        _logger = logger;
    }

    [HttpGet("")]
    public IActionResult Index() => View();

    [HttpGet("table")]
    public async Task<IActionResult> Table([FromQuery] string? chain, CancellationToken ct)
    {
        var rows = await _firewall.GetFilterRulesAsync(chain, ct);
        var ifaces = await _firewall.GetInterfacesAsync(ct);
        ViewBag.InterfaceNames = ifaces.ToDictionary(i => i.Id, i => i.Name);
        ViewBag.ChainFilter = chain;
        return PartialView("_FilterRulesTable", rows);
    }

    [HttpGet("edit/{id:guid?}")]
    public async Task<IActionResult> Edit(Guid? id, [FromServices] IScheduleService schedules, CancellationToken ct)
    {
        ViewBag.Interfaces = await _firewall.GetInterfacesAsync(ct);
        ViewBag.Schedules  = await schedules.GetAllAsync(ct);
        if (id is null) return PartialView("_FilterRuleForm", new FilterRuleFormViewModel());
        var r = await _firewall.GetFilterRuleByIdAsync(id.Value, ct);
        return r is null ? NotFound() : PartialView("_FilterRuleForm", FromEntity(r));
    }

    [HttpPost("save"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(FilterRuleFormViewModel form, CancellationToken ct)
    {
        try
        {
            var entity = ToEntity(form);
            FwFilterRule saved;
            if (form.Id.HasValue && await _firewall.GetFilterRuleByIdAsync(form.Id.Value, ct) is not null)
            {
                entity.Id = form.Id.Value;
                saved = await _firewall.UpdateFilterRuleAsync(entity, ct);
            }
            else
            {
                saved = await _firewall.CreateFilterRuleAsync(entity, ct);
            }
            var envelope = ServiceResponse<FwFilterRule>.Ok(saved,
                $"Filter rule on {saved.Chain}/{saved.Action} saved.");
            this.AttachToastTrigger(envelope);
            Response.Headers["HX-Trigger"] = "refreshFilterRules";
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save filter rule");
            return this.ToHtmxResponse(ServiceResponse<FwFilterRule>.Fail($"Save failed: {ex.Message}"));
        }
    }

    [HttpPost("delete/{id:guid}"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var ok = await _firewall.DeleteFilterRuleAsync(id, ct);
        Response.Headers["HX-Trigger"] = "refreshFilterRules";
        return this.ToHtmxResponse(ok
            ? ServiceResponse<object>.Ok(new { }, "Filter rule deleted.")
            : ServiceResponse<object>.Fail("Rule not found."));
    }

    private static FilterRuleFormViewModel FromEntity(FwFilterRule r) => new()
    {
        Id = r.Id, Chain = r.Chain, Description = r.Description,
        Action = r.Action, Protocol = r.Protocol,
        InterfaceInId = r.InterfaceInId, InterfaceOutId = r.InterfaceOutId,
        SourceAddresses = FwArrayHelpers.Join(r.SourceAddresses),
        DestinationAddresses = FwArrayHelpers.Join(r.DestinationAddresses),
        DestinationPorts = FwArrayHelpers.Join(r.DestinationPorts),
        ConnectionStates = FwArrayHelpers.Join(r.ConnectionState),
        RateLimit = r.RateLimit, LogPrefix = r.LogPrefix,
        Priority = r.Priority, Enabled = r.Enabled,
        ScheduleId = r.ScheduleId
    };

    private static FwFilterRule ToEntity(FilterRuleFormViewModel f) => new()
    {
        Chain = f.Chain, Description = f.Description,
        Action = f.Action, Protocol = f.Protocol,
        InterfaceInId = f.InterfaceInId, InterfaceOutId = f.InterfaceOutId,
        SourceAddresses = FwArrayHelpers.Split(f.SourceAddresses),
        DestinationAddresses = FwArrayHelpers.Split(f.DestinationAddresses),
        DestinationPorts = FwArrayHelpers.Split(f.DestinationPorts),
        ConnectionState = FwArrayHelpers.Split(f.ConnectionStates),
        RateLimit = string.IsNullOrWhiteSpace(f.RateLimit) ? null : f.RateLimit,
        LogPrefix = f.LogPrefix,
        Priority = f.Priority, Enabled = f.Enabled,
        ScheduleId = f.ScheduleId
    };
}
