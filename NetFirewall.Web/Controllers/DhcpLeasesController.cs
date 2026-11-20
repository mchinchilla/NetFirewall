using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Dhcp;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Services;

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
    private readonly IDhcpLeaseDetailService _detail;
    private readonly ILogger<DhcpLeasesController> _logger;

    public DhcpLeasesController(IDhcpAdminService admin, IDhcpLeaseDetailService detail, ILogger<DhcpLeasesController> logger)
    {
        _admin = admin;
        _detail = detail;
        _logger = logger;
    }

    [HttpGet("")]
    public IActionResult Index() => View();

    /// <summary>Expanded row of the Leases grid (fetched once per row, on first expand).</summary>
    [HttpGet("detail/{mac}")]
    public async Task<IActionResult> Detail(string mac, CancellationToken ct)
    {
        var model = await _detail.GetAsync(mac, ct);
        return model is null
            ? Content("<p class=\"text-sm text-surface-fg-muted\">This lease is gone (released or purged). Refresh the grid.</p>", "text/html")
            : PartialView("_LeaseDetail", model);
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
        this.AttachHxEvent("refreshLeases", new { });
        return this.ToHtmxResponse(envelope);
    }

    [HttpPost("cleanup-expired"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    [Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
    public async Task<IActionResult> CleanupExpired(CancellationToken ct)
    {
        var n = await _admin.CleanupExpiredLeasesAsync(ct);
        var envelope = ServiceResponse<int>.Ok(n, $"Removed {n} expired lease(s).");
        this.AttachHxEvent("refreshLeases", new { });
        return this.ToHtmxResponse(envelope);
    }
}
