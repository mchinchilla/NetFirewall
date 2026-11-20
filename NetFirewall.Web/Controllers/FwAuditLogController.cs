using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Firewall;

namespace NetFirewall.Web.Controllers;

[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Firewall/AuditLog")]
public sealed class FwAuditLogController : Controller
{

    private readonly IFirewallService _firewall;

    public FwAuditLogController(IFirewallService firewall) => _firewall = firewall;

    /// <summary>The page hosts the <c>fw-audit-log</c> grid; its rows are queried in PostgreSQL by the grid itself.</summary>
    [HttpGet("")]
    public IActionResult Index() => View();

    /// <summary>
    /// Expanded row of the Audit log grid: the entry's before/after JSON, fetched once per row on
    /// first expand. The source comes from the action so existing constructor callers stay valid.
    /// </summary>
    [HttpGet("detail/{id:guid}")]
    public async Task<IActionResult> Detail(Guid id, [FromServices] IAuditLogGridSource audit, CancellationToken ct)
    {
        var entry = await audit.GetEntryAsync(id, ct);
        return entry is null
            ? Content("<p class=\"text-sm text-surface-fg-muted\">This audit entry no longer exists. Refresh the grid.</p>", "text/html")
            : PartialView("_AuditLogDetail", entry);
    }

}
