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
[Route("/Dhcp/Ddns")]
public sealed class DhcpDdnsController : Controller
{
    private readonly IDhcpAdminService _admin;
    private readonly ILogger<DhcpDdnsController> _logger;

    public DhcpDdnsController(IDhcpAdminService admin, ILogger<DhcpDdnsController> logger)
    {
        _admin = admin;
        _logger = logger;
    }

    [HttpGet("")]
    public IActionResult Index() => View();

    [HttpGet("table")]
    public async Task<IActionResult> Table(CancellationToken ct)
    {
        var rows = await _admin.GetDdnsConfigsAsync(ct);
        var subnets = await _admin.GetSubnetsAsync(ct);
        ViewBag.SubnetNames = subnets.ToDictionary(s => s.Id, s => s.Name);
        return PartialView("_DdnsTable", rows);
    }

    [HttpGet("edit/{id:guid?}")]
    public async Task<IActionResult> Edit(Guid? id, CancellationToken ct)
    {
        ViewBag.Subnets = await _admin.GetSubnetsAsync(ct);
        if (id is null) return PartialView("_DdnsForm", new DdnsFormViewModel());
        var d = await _admin.GetDdnsConfigByIdAsync(id.Value, ct);
        return d is null ? NotFound() : PartialView("_DdnsForm", FromEntity(d));
    }

    [HttpPost("save"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(DdnsFormViewModel form, CancellationToken ct)
    {
        try
        {
            var entity = ToEntity(form);
            DdnsConfig saved;
            if (form.Id.HasValue && await _admin.GetDdnsConfigByIdAsync(form.Id.Value, ct) is not null)
            {
                entity.Id = form.Id.Value;
                saved = await _admin.UpdateDdnsConfigAsync(entity, ct);
            }
            else
            {
                saved = await _admin.CreateDdnsConfigAsync(entity, ct);
            }
            var envelope = ServiceResponse<DdnsConfig>.Ok(saved,
                $"DDNS config{(saved.SubnetId is null ? " (global)" : "")} saved.");
            this.AttachToastTrigger(envelope);
            Response.Headers["HX-Trigger"] = "refreshDdns";
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save DDNS config");
            return this.ToHtmxResponse(ServiceResponse<DdnsConfig>.Fail($"Save failed: {ex.Message}"));
        }
    }

    [HttpPost("delete/{id:guid}"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var ok = await _admin.DeleteDdnsConfigAsync(id, ct);
        Response.Headers["HX-Trigger"] = "refreshDdns";
        return this.ToHtmxResponse(ok
            ? ServiceResponse<object>.Ok(new { }, "DDNS config deleted.")
            : ServiceResponse<object>.Fail("Config not found."));
    }

    private static DdnsFormViewModel FromEntity(DdnsConfig d) => new()
    {
        Id = d.Id, SubnetId = d.SubnetId,
        EnableForward = d.EnableForward, EnableReverse = d.EnableReverse,
        ForwardZone = d.ForwardZone, ReverseZone = d.ReverseZone,
        DnsServer = d.DnsServer?.ToString() ?? string.Empty,
        DnsPort = d.DnsPort,
        TsigKeyName = d.TsigKeyName, TsigKeySecret = d.TsigKeySecret,
        TsigAlgorithm = d.TsigAlgorithm,
        Ttl = d.Ttl, UpdateStyle = d.UpdateStyle,
        OverrideClientUpdate = d.OverrideClientUpdate,
        AllowClientUpdates = d.AllowClientUpdates,
        ConflictResolution = d.ConflictResolution,
        Enabled = d.Enabled
    };

    private static DdnsConfig ToEntity(DdnsFormViewModel f) => new()
    {
        SubnetId = f.SubnetId,
        EnableForward = f.EnableForward, EnableReverse = f.EnableReverse,
        ForwardZone = f.ForwardZone, ReverseZone = f.ReverseZone,
        DnsServer = IPAddress.Parse(f.DnsServer),
        DnsPort = f.DnsPort,
        TsigKeyName = f.TsigKeyName, TsigKeySecret = f.TsigKeySecret,
        TsigAlgorithm = f.TsigAlgorithm,
        Ttl = f.Ttl, UpdateStyle = f.UpdateStyle,
        OverrideClientUpdate = f.OverrideClientUpdate,
        AllowClientUpdates = f.AllowClientUpdates,
        ConflictResolution = f.ConflictResolution,
        Enabled = f.Enabled
    };
}
