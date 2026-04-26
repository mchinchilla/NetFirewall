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

/// <summary>Exclusions live under a subnet — same nesting as pools.</summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Dhcp/Subnets/{subnetId:guid}/Exclusions")]
public sealed class DhcpExclusionsController : Controller
{
    private readonly IDhcpAdminService _admin;
    private readonly ILogger<DhcpExclusionsController> _logger;

    public DhcpExclusionsController(IDhcpAdminService admin, ILogger<DhcpExclusionsController> logger)
    {
        _admin = admin;
        _logger = logger;
    }

    [HttpGet("")]
    public async Task<IActionResult> Index(Guid subnetId, CancellationToken ct)
    {
        var subnet = await _admin.GetSubnetByIdAsync(subnetId, ct);
        if (subnet is null) return NotFound();
        ViewBag.Subnet = subnet;
        return View();
    }

    [HttpGet("table")]
    public async Task<IActionResult> Table(Guid subnetId, CancellationToken ct)
    {
        var rows = await _admin.GetExclusionsAsync(subnetId, ct);
        ViewBag.SubnetId = subnetId;
        return PartialView("_ExclusionsTable", rows);
    }

    [HttpGet("edit/{id:guid?}")]
    public async Task<IActionResult> Edit(Guid subnetId, Guid? id, CancellationToken ct)
    {
        if (id is null)
            return PartialView("_ExclusionForm", new ExclusionFormViewModel { SubnetId = subnetId });

        var ex = await _admin.GetExclusionByIdAsync(id.Value, ct);
        return ex is null ? NotFound() : PartialView("_ExclusionForm", FromEntity(ex));
    }

    [HttpPost("save"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(Guid subnetId, ExclusionFormViewModel form, CancellationToken ct)
    {
        try
        {
            var entity = ToEntity(form);
            DhcpExclusion saved;
            if (form.Id.HasValue && await _admin.GetExclusionByIdAsync(form.Id.Value, ct) is not null)
            {
                entity.Id = form.Id.Value;
                saved = await _admin.UpdateExclusionAsync(entity, ct);
            }
            else
            {
                saved = await _admin.CreateExclusionAsync(entity, ct);
            }
            var envelope = ServiceResponse<DhcpExclusion>.Ok(saved, "Exclusion saved.");
            this.AttachToastTrigger(envelope);
            Response.Headers["HX-Trigger"] = "refreshExclusions";
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save exclusion");
            return this.ToHtmxResponse(ServiceResponse<DhcpExclusion>.Fail($"Save failed: {ex.Message}"));
        }
    }

    [HttpPost("delete/{id:guid}"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    public async Task<IActionResult> Delete(Guid subnetId, Guid id, CancellationToken ct)
    {
        _ = subnetId;
        var ok = await _admin.DeleteExclusionAsync(id, ct);
        Response.Headers["HX-Trigger"] = "refreshExclusions";
        return this.ToHtmxResponse(ok
            ? ServiceResponse<object>.Ok(new { }, "Exclusion deleted.")
            : ServiceResponse<object>.Fail("Exclusion not found."));
    }

    private static ExclusionFormViewModel FromEntity(DhcpExclusion e) => new()
    {
        Id = e.Id, SubnetId = e.SubnetId,
        IpStart = e.IpStart.ToString(),
        IpEnd = e.IpEnd?.ToString(),
        Reason = e.Reason
    };

    private static DhcpExclusion ToEntity(ExclusionFormViewModel f) => new()
    {
        SubnetId = f.SubnetId,
        IpStart = IPAddress.Parse(f.IpStart),
        IpEnd = string.IsNullOrWhiteSpace(f.IpEnd) ? null : IPAddress.Parse(f.IpEnd),
        Reason = f.Reason
    };
}
