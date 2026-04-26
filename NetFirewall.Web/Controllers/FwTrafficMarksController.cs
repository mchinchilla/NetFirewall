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
[Route("/Firewall/TrafficMarks")]
public sealed class FwTrafficMarksController : Controller
{
    private readonly IFirewallService _firewall;
    private readonly ILogger<FwTrafficMarksController> _logger;

    public FwTrafficMarksController(IFirewallService firewall, ILogger<FwTrafficMarksController> logger)
    {
        _firewall = firewall;
        _logger = logger;
    }

    [HttpGet("")]
    public IActionResult Index() => View();

    [HttpGet("table")]
    public async Task<IActionResult> Table(CancellationToken ct)
    {
        var rows = await _firewall.GetTrafficMarksAsync(ct);
        return PartialView("_TrafficMarksTable", rows);
    }

    [HttpGet("edit/{id:guid?}")]
    public async Task<IActionResult> Edit(Guid? id, CancellationToken ct)
    {
        if (id is null) return PartialView("_TrafficMarkForm", new TrafficMarkFormViewModel());
        var m = await _firewall.GetTrafficMarkByIdAsync(id.Value, ct);
        return m is null ? NotFound() : PartialView("_TrafficMarkForm", FromEntity(m));
    }

    [HttpPost("save"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(TrafficMarkFormViewModel form, CancellationToken ct)
    {
        try
        {
            var entity = ToEntity(form);
            FwTrafficMark saved;
            if (form.Id.HasValue && await _firewall.GetTrafficMarkByIdAsync(form.Id.Value, ct) is not null)
            {
                entity.Id = form.Id.Value;
                saved = await _firewall.UpdateTrafficMarkAsync(entity, ct);
            }
            else
            {
                saved = await _firewall.CreateTrafficMarkAsync(entity, ct);
            }
            var envelope = ServiceResponse<FwTrafficMark>.Ok(saved, $"Mark '{saved.Name}' saved.");
            this.AttachToastTrigger(envelope);
            Response.Headers["HX-Trigger"] = "refreshTrafficMarks";
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save traffic mark");
            return this.ToHtmxResponse(ServiceResponse<FwTrafficMark>.Fail($"Save failed: {ex.Message}"));
        }
    }

    [HttpPost("delete/{id:guid}"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var ok = await _firewall.DeleteTrafficMarkAsync(id, ct);
        Response.Headers["HX-Trigger"] = "refreshTrafficMarks";
        return this.ToHtmxResponse(ok
            ? ServiceResponse<object>.Ok(new { }, "Mark deleted.")
            : ServiceResponse<object>.Fail("Mark not found."));
    }

    private static TrafficMarkFormViewModel FromEntity(FwTrafficMark m) => new()
    {
        Id = m.Id, Name = m.Name, MarkValue = m.MarkValue,
        Description = m.Description, RouteTable = m.RouteTable
    };

    private static FwTrafficMark ToEntity(TrafficMarkFormViewModel f) => new()
    {
        Name = f.Name, MarkValue = f.MarkValue,
        Description = f.Description, RouteTable = f.RouteTable
    };
}
