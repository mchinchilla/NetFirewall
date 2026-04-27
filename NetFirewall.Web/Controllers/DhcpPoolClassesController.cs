using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Dhcp;
using NetFirewall.Web.Helpers;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// Allow / deny client classes per pool. Backed by dhcp_pool_classes —
/// a row exists per (pool, class) the operator has explicitly bound.
/// </summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Dhcp/Subnets/{subnetId:guid}/Pools/{poolId:guid}/Classes")]
public sealed class DhcpPoolClassesController : Controller
{
    private readonly IDhcpAdminService _admin;
    private readonly ILogger<DhcpPoolClassesController> _logger;

    public DhcpPoolClassesController(IDhcpAdminService admin, ILogger<DhcpPoolClassesController> logger)
    {
        _admin = admin;
        _logger = logger;
    }

    [HttpGet("")]
    public async Task<IActionResult> Index(Guid subnetId, Guid poolId, CancellationToken ct)
    {
        var pools = await _admin.GetPoolsAsync(subnetId, ct);
        var pool = pools.FirstOrDefault(p => p.Id == poolId);
        if (pool is null) return NotFound();

        var subnet = await _admin.GetSubnetByIdAsync(subnetId, ct);
        ViewBag.Pool = pool;
        ViewBag.SubnetName = subnet?.Name ?? subnet?.Network ?? "(unknown)";
        ViewBag.SubnetId = subnetId;
        return View();
    }

    [HttpGet("table")]
    public async Task<IActionResult> Table(Guid poolId, CancellationToken ct)
    {
        var allClasses = await _admin.GetClassesAsync(ct);
        var bindings = await _admin.GetPoolClassesAsync(poolId, ct);
        ViewBag.Bindings = bindings.ToDictionary(b => b.Class.Id, b => b.Allow);
        ViewBag.PoolId = poolId;
        return PartialView("_PoolClassesTable", allClasses);
    }

    [HttpPost("set"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Set(Guid poolId, Guid classId, string mode, CancellationToken ct)
    {
        try
        {
            ServiceResponse<object> envelope;
            if (string.Equals(mode, "remove", StringComparison.OrdinalIgnoreCase))
            {
                await _admin.RemovePoolClassAsync(poolId, classId, ct);
                envelope = ServiceResponse<object>.Ok(new { }, "Binding removed.");
            }
            else
            {
                var allow = string.Equals(mode, "allow", StringComparison.OrdinalIgnoreCase);
                await _admin.SetPoolClassAsync(poolId, classId, allow, ct);
                envelope = ServiceResponse<object>.Ok(new { }, $"Class {(allow ? "allowed" : "denied")} on pool.");
            }
            this.AttachToastTrigger(envelope);
            Response.Headers["HX-Trigger"] = "refreshPoolClasses";
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to set pool/class binding");
            return this.ToHtmxResponse(ServiceResponse<object>.Fail($"Save failed: {ex.Message}"));
        }
    }
}
