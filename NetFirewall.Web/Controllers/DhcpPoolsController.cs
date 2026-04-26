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

/// <summary>
/// Pools live nested under a subnet. URL shape: <c>/Dhcp/Subnets/{subnetId}/Pools/...</c>.
/// All IO via <see cref="IDhcpAdminService"/> per rule #10.
/// </summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Dhcp/Subnets/{subnetId:guid}/Pools")]
public sealed class DhcpPoolsController : Controller
{
    private readonly IDhcpAdminService _admin;
    private readonly ILogger<DhcpPoolsController> _logger;

    public DhcpPoolsController(IDhcpAdminService admin, ILogger<DhcpPoolsController> logger)
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
        var pools = await _admin.GetPoolsAsync(subnetId, ct);
        ViewBag.SubnetId = subnetId;
        return PartialView("_PoolsTable", pools);
    }

    [HttpGet("edit/{id:guid?}")]
    public async Task<IActionResult> Edit(Guid subnetId, Guid? id, CancellationToken ct)
    {
        if (id is null)
            return PartialView("_PoolForm", new PoolFormViewModel { SubnetId = subnetId });

        var pools = await _admin.GetPoolsAsync(subnetId, ct);
        var pool = pools.FirstOrDefault(p => p.Id == id);
        return pool is null ? NotFound() : PartialView("_PoolForm", FromEntity(pool));
    }

    [HttpPost("save"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(Guid subnetId, PoolFormViewModel form, CancellationToken ct)
    {
        try
        {
            var entity = ToEntity(form);
            DhcpPool saved;
            var existing = (await _admin.GetPoolsAsync(subnetId, ct)).FirstOrDefault(p => p.Id == form.Id);
            if (existing is not null)
            {
                entity.Id = existing.Id;
                saved = await _admin.UpdatePoolAsync(entity, ct);
            }
            else
            {
                saved = await _admin.CreatePoolAsync(entity, ct);
            }

            var envelope = ServiceResponse<DhcpPool>.Ok(saved, $"Pool {saved.RangeStart}–{saved.RangeEnd} saved.");
            this.AttachToastTrigger(envelope);
            Response.Headers["HX-Trigger"] = "refreshPools";
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save pool");
            return this.ToHtmxResponse(ServiceResponse<DhcpPool>.Fail($"Save failed: {ex.Message}"));
        }
    }

    [HttpPost("delete/{id:guid}"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    public async Task<IActionResult> Delete(Guid subnetId, Guid id, CancellationToken ct)
    {
        _ = subnetId; // route parameter used only for auth grouping
        var ok = await _admin.DeletePoolAsync(id, ct);
        var envelope = ok
            ? ServiceResponse<object>.Ok(new { }, "Pool deleted.")
            : ServiceResponse<object>.Fail("Pool not found.");
        Response.Headers["HX-Trigger"] = "refreshPools";
        return this.ToHtmxResponse(envelope);
    }

    // ---------- mapping ----------

    private static PoolFormViewModel FromEntity(DhcpPool p) => new()
    {
        Id = p.Id,
        SubnetId = p.SubnetId ?? Guid.Empty,
        Name = p.Name,
        RangeStart = p.RangeStart.ToString(),
        RangeEnd = p.RangeEnd.ToString(),
        AllowUnknownClients = p.AllowUnknownClients,
        DenyBootp = p.DenyBootp,
        KnownClientsOnly = p.KnownClientsOnly,
        Priority = p.Priority,
        Enabled = p.Enabled
    };

    private static DhcpPool ToEntity(PoolFormViewModel f) => new()
    {
        SubnetId = f.SubnetId,
        Name = f.Name,
        RangeStart = IPAddress.Parse(f.RangeStart),
        RangeEnd = IPAddress.Parse(f.RangeEnd),
        AllowUnknownClients = f.AllowUnknownClients,
        DenyBootp = f.DenyBootp,
        KnownClientsOnly = f.KnownClientsOnly,
        Priority = f.Priority,
        Enabled = f.Enabled
    };
}
