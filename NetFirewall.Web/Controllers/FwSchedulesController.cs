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
[Route("/Firewall/Schedules")]
public sealed class FwSchedulesController : Controller
{
    private readonly IScheduleService _schedules;
    private readonly ILogger<FwSchedulesController> _logger;

    public FwSchedulesController(IScheduleService schedules, ILogger<FwSchedulesController> logger)
    {
        _schedules = schedules;
        _logger = logger;
    }

    [HttpGet("")]
    public IActionResult Index() => View();

    [HttpGet("table")]
    public async Task<IActionResult> Table(CancellationToken ct)
    {
        var rows = await _schedules.GetAllAsync(ct);
        return PartialView("_SchedulesTable", rows);
    }

    [HttpGet("edit/{id:guid?}")]
    public async Task<IActionResult> Edit(Guid? id, CancellationToken ct)
    {
        if (id is null) return PartialView("_ScheduleForm", new ScheduleFormViewModel());
        var s = await _schedules.GetByIdAsync(id.Value, ct);
        return s is null ? NotFound() : PartialView("_ScheduleForm", FromEntity(s));
    }

    [HttpPost("save"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(ScheduleFormViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid)
            return this.ToHtmxResponse(ServiceResponse<FwSchedule>.Fail(
                string.Join(" ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage))));

        try
        {
            var entity = ToEntity(form);
            FwSchedule saved;
            if (form.Id.HasValue && await _schedules.GetByIdAsync(form.Id.Value, ct) is not null)
            {
                entity.Id = form.Id.Value;
                saved = await _schedules.UpdateAsync(entity, ct);
            }
            else
            {
                saved = await _schedules.CreateAsync(entity, ct);
            }
            var envelope = ServiceResponse<FwSchedule>.Ok(saved, $"Schedule '{saved.Name}' saved.");
            this.AttachToastTrigger(envelope);
            Response.Headers["HX-Trigger"] = "refreshSchedules";
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Schedule save failed");
            return this.ToHtmxResponse(ServiceResponse<FwSchedule>.Fail($"Save failed: {ex.Message}"));
        }
    }

    [HttpPost("delete/{id:guid}"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var ok = await _schedules.DeleteAsync(id, ct);
        Response.Headers["HX-Trigger"] = "refreshSchedules";
        return this.ToHtmxResponse(ok
            ? ServiceResponse<object>.Ok(new { }, "Schedule deleted. Filter rules referencing it now apply unconditionally.")
            : ServiceResponse<object>.Fail("Schedule not found."));
    }

    private static ScheduleFormViewModel FromEntity(FwSchedule s) => new()
    {
        Id          = s.Id,
        Name        = s.Name,
        Description = s.Description,
        DaysOfWeek  = s.DaysOfWeek,
        StartTime   = s.StartTime,
        EndTime     = s.EndTime,
        Timezone    = s.Timezone,
        Enabled     = s.Enabled
    };

    private static FwSchedule ToEntity(ScheduleFormViewModel f) => new()
    {
        Name        = f.Name.Trim(),
        Description = string.IsNullOrWhiteSpace(f.Description) ? null : f.Description,
        DaysOfWeek  = f.DaysOfWeek,
        StartTime   = f.StartTime,
        EndTime     = f.EndTime,
        Timezone    = string.IsNullOrWhiteSpace(f.Timezone) ? "UTC" : f.Timezone.Trim(),
        Enabled     = f.Enabled
    };
}
