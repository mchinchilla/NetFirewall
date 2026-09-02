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
    private readonly IScheduleService _schedules;
    private readonly ILogger<FwFilterRulesController> _logger;

    public FwFilterRulesController(
        IFirewallService firewall,
        IScheduleService schedules,
        ILogger<FwFilterRulesController> logger)
    {
        _firewall = firewall;
        _schedules = schedules;
        _logger = logger;
    }

    [HttpGet("")]
    public IActionResult Index() => View();

    [HttpGet("table")]
    public async Task<IActionResult> Table([FromQuery] string? chain, [FromQuery] string? view, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(chain)) chain = null;
        var rows = await _firewall.GetFilterRulesAsync(chain, ct);
        var ifaces = await _firewall.GetInterfacesAsync(ct);
        var schedules = await _schedules.GetAllAsync(ct);

        // Unknown or missing view falls back to evaluation order — the only
        // arrangement that tells the truth about how the ruleset runs.
        if (!Enum.TryParse<FilterRuleView>(view, ignoreCase: true, out var mode))
            mode = FilterRuleView.Evaluation;

        var model = FilterRuleGrouper.Build(
            rows,
            ifaces.ToDictionary(i => i.Id, i => i.Name),
            mode,
            chain,
            schedules.ToDictionary(s => s.Id, s => s.Name),
            ifaces.ToDictionary(i => i.Id, i => i.Type));

        return PartialView("_FilterRulesTable", model);
    }

    [HttpGet("edit/{id:guid?}")]
    public async Task<IActionResult> Edit(Guid? id, CancellationToken ct)
    {
        ViewBag.Interfaces = await _firewall.GetInterfacesAsync(ct);
        ViewBag.Schedules  = await _schedules.GetAllAsync(ct);
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
            this.AttachHxEvent("refreshFilterRules", new { });
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save filter rule");
            return this.ToHtmxResponse(ServiceResponse<FwFilterRule>.Fail($"Save failed: {ex.Message}"));
        }
    }

    /// <summary>
    /// Live preview of the nft line the form currently describes. Rendered by
    /// the same generator an apply uses, so what the operator reads here is
    /// literally what would be written — the form stops being a set of fields
    /// whose combined effect you have to imagine.
    /// </summary>
    [HttpPost("preview"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Preview(FilterRuleFormViewModel form, CancellationToken ct)
    {
        var entity = ToEntity(form);

        try
        {
            var line = await _firewall.PreviewFilterRuleAsync(entity, ct);
            return PartialView("_RulePreview", new RulePreviewViewModel
            {
                Line = line,
                Bypass = FwFilterRuleGuard.DescribeBypass(entity)
            });
        }
        catch (Exception ex)
        {
            // A preview must never break the form it is helping with.
            _logger.LogDebug(ex, "Filter rule preview failed");
            return PartialView("_RulePreview", new RulePreviewViewModel
            {
                Line = "",
                Problem = "Preview unavailable for the current values."
            });
        }
    }

    [HttpPost("delete/{id:guid}"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var ok = await _firewall.DeleteFilterRuleAsync(id, ct);
        this.AttachHxEvent("refreshFilterRules", new { });
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
        ScheduleId = r.ScheduleId,
        ScheduleInvert = r.ScheduleInvert
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
        ScheduleId = f.ScheduleId,
        ScheduleInvert = f.ScheduleInvert
    };

    [HttpGet("time-policy")]
    public async Task<IActionResult> TimePolicy(Guid? scheduleId, CancellationToken ct)
    {
        ViewBag.Schedules = await _schedules.GetAllAsync(ct);
        return PartialView("_TimePolicyForm", new TimePolicyFormViewModel
        {
            ScheduleId = scheduleId
        });
    }

    [HttpPost("time-policy"), ValidateAntiForgeryToken]
    public async Task<IActionResult> TimePolicySave(TimePolicyFormViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid)
            return this.ToHtmxResponse(ServiceResponse<FwFilterRule>.Fail(
                string.Join(" ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage))));

        var sched = await _schedules.GetByIdAsync(form.ScheduleId!.Value, ct);
        if (sched is null)
            return this.ToHtmxResponse(ServiceResponse<FwFilterRule>.Fail("Pick a schedule."));

        try
        {
            var rule = TimePolicyComposer.Compose(form, sched.Name);
            var twins = (await _firewall.GetFilterRulesAsync(rule.Chain, ct))
                .Where(r => TimePolicyComposer.SamePolicy(r, rule))
                .OrderBy(r => r.CreatedAt)
                .ToList();

            FwFilterRule saved;
            var removed = 0;
            if (twins.Count == 0)
            {
                saved = await _firewall.CreateFilterRuleAsync(rule, ct);
            }
            else
            {
                rule.Id = twins[0].Id;
                saved = await _firewall.UpdateFilterRuleAsync(rule, ct);
                foreach (var extra in twins.Skip(1))
                {
                    if (await _firewall.DeleteFilterRuleAsync(extra.Id, ct))
                        removed++;
                }
            }

            var msg = twins.Count == 0
                ? $"Time policy saved as a drop on {saved.Chain}. The daemon installs it now and at each schedule edge."
                : removed > 0
                    ? $"Time policy updated on {saved.Chain}; removed {removed} duplicate{(removed == 1 ? "" : "s")}."
                    : $"Time policy already existed on {saved.Chain}; updated in place.";
            var envelope = ServiceResponse<FwFilterRule>.Ok(saved, msg);
            this.AttachToastTrigger(envelope);
            this.AttachHxEvent("refreshFilterRules", new { });
            this.AttachHxEvent("refreshSchedules", new { });
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Time policy save failed");
            return this.ToHtmxResponse(ServiceResponse<FwFilterRule>.Fail($"Save failed: {ex.Message}"));
        }
    }
}
