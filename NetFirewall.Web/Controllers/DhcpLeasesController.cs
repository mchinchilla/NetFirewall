using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Dhcp;
using NetFirewall.Web.Helpers;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// Read-only listing of DHCP leases. Two destructive ops: release a single
/// lease + cleanup expired (bulk). Both [RequireElevated]. All IO via
/// <see cref="IDhcpAdminService"/>.
/// </summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator},{UserRoles.Viewer}")]
[Route("/Dhcp/Leases")]
public sealed class DhcpLeasesController : Controller
{
    private readonly IDhcpAdminService _admin;
    private readonly ILogger<DhcpLeasesController> _logger;

    public DhcpLeasesController(IDhcpAdminService admin, ILogger<DhcpLeasesController> logger)
    {
        _admin = admin;
        _logger = logger;
    }

    [HttpGet("")]
    public IActionResult Index() => View();

    [HttpGet("table")]
    public async Task<IActionResult> Table([FromQuery] bool includeExpired = false, CancellationToken ct = default)
    {
        var leases = includeExpired
            ? await _admin.GetAllLeasesAsync(includeExpired: true, ct)
            : await _admin.GetActiveLeasesAsync(ct);
        ViewBag.IncludeExpired = includeExpired;
        return PartialView("_LeasesTable", leases);
    }

    [HttpPost("release/{id:guid}"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    [Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
    public async Task<IActionResult> Release(Guid id, CancellationToken ct)
    {
        var ok = await _admin.ReleaseLeaseAsync(id, ct);
        var envelope = ok
            ? ServiceResponse<object>.Ok(new { }, "Lease released.")
            : ServiceResponse<object>.Fail("Lease not found or already gone.");
        Response.Headers["HX-Trigger"] = "refreshLeases";
        return this.ToHtmxResponse(envelope);
    }

    [HttpPost("cleanup-expired"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    [Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
    public async Task<IActionResult> CleanupExpired(CancellationToken ct)
    {
        var n = await _admin.CleanupExpiredLeasesAsync(ct);
        var envelope = ServiceResponse<int>.Ok(n, $"Removed {n} expired lease(s).");
        Response.Headers["HX-Trigger"] = "refreshLeases";
        return this.ToHtmxResponse(envelope);
    }
}
