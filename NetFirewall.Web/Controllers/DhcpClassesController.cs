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

[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Dhcp/Classes")]
public sealed class DhcpClassesController : Controller
{
    private readonly IDhcpAdminService _admin;
    private readonly ILogger<DhcpClassesController> _logger;

    public DhcpClassesController(IDhcpAdminService admin, ILogger<DhcpClassesController> logger)
    {
        _admin = admin;
        _logger = logger;
    }

    [HttpGet("")]
    public IActionResult Index() => View();

    [HttpGet("table")]
    public async Task<IActionResult> Table(CancellationToken ct)
    {
        var rows = await _admin.GetClassesAsync(ct);
        return PartialView("_ClassesTable", rows);
    }

    [HttpGet("edit/{id:guid?}")]
    public async Task<IActionResult> Edit(Guid? id, CancellationToken ct)
    {
        if (id is null) return PartialView("_ClassForm", new ClassFormViewModel());
        var c = await _admin.GetClassByIdAsync(id.Value, ct);
        return c is null ? NotFound() : PartialView("_ClassForm", FromEntity(c));
    }

    [HttpPost("save"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(ClassFormViewModel form, CancellationToken ct)
    {
        try
        {
            var entity = ToEntity(form);
            DhcpClass saved;
            if (form.Id.HasValue && await _admin.GetClassByIdAsync(form.Id.Value, ct) is not null)
            {
                entity.Id = form.Id.Value;
                saved = await _admin.UpdateClassAsync(entity, ct);
            }
            else
            {
                saved = await _admin.CreateClassAsync(entity, ct);
            }
            var envelope = ServiceResponse<DhcpClass>.Ok(saved, $"Class '{saved.Name}' saved.");
            this.AttachToastTrigger(envelope);
            Response.Headers["HX-Trigger"] = "refreshClasses";
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save class");
            return this.ToHtmxResponse(ServiceResponse<DhcpClass>.Fail($"Save failed: {ex.Message}"));
        }
    }

    [HttpPost("delete/{id:guid}"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var ok = await _admin.DeleteClassAsync(id, ct);
        Response.Headers["HX-Trigger"] = "refreshClasses";
        return this.ToHtmxResponse(ok
            ? ServiceResponse<object>.Ok(new { }, "Class deleted.")
            : ServiceResponse<object>.Fail("Class not found."));
    }

    private static ClassFormViewModel FromEntity(DhcpClass c) => new()
    {
        Id = c.Id, Name = c.Name,
        MatchType = c.MatchType, MatchValue = c.MatchValue,
        NextServer = c.NextServer?.ToString(),
        BootFilename = c.BootFilename,
        Priority = c.Priority, Enabled = c.Enabled
    };

    private static DhcpClass ToEntity(ClassFormViewModel f) => new()
    {
        Name = f.Name,
        MatchType = f.MatchType,
        MatchValue = f.MatchValue,
        NextServer = string.IsNullOrWhiteSpace(f.NextServer) ? null : IPAddress.Parse(f.NextServer),
        BootFilename = f.BootFilename,
        Priority = f.Priority,
        Enabled = f.Enabled
    };
}
