using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Firewall;

namespace NetFirewall.Web.Controllers;

[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Firewall/AuditLog")]
public sealed class FwAuditLogController : Controller
{
    private const int PageSize = 50;

    private readonly IFirewallService _firewall;

    public FwAuditLogController(IFirewallService firewall) => _firewall = firewall;

    [HttpGet("")]
    public async Task<IActionResult> Index(CancellationToken ct)
    {
        ViewBag.TableNames = await _firewall.GetAuditTableNamesAsync(ct);
        return View();
    }

    [HttpGet("table")]
    public async Task<IActionResult> Table(string? table, string? action, string? since, int page, CancellationToken ct)
    {
        var p = page < 1 ? 1 : page;
        var sinceDt = ParseSince(since);
        var rows = await _firewall.SearchAuditLogsAsync(
            tableName: string.IsNullOrWhiteSpace(table) ? null : table,
            action: string.IsNullOrWhiteSpace(action) ? null : action,
            since: sinceDt,
            limit: PageSize,
            offset: (p - 1) * PageSize,
            ct: ct);

        ViewBag.Page = p;
        ViewBag.HasNext = rows.Count == PageSize;
        ViewBag.Table = table;
        ViewBag.Action = action;
        ViewBag.Since = since;
        return PartialView("_AuditLogTable", rows);
    }

    private static DateTime? ParseSince(string? s) => s switch
    {
        null or ""    => null,
        "1h"          => DateTime.UtcNow.AddHours(-1),
        "24h"         => DateTime.UtcNow.AddHours(-24),
        "7d"          => DateTime.UtcNow.AddDays(-7),
        "30d"         => DateTime.UtcNow.AddDays(-30),
        _             => DateTime.TryParse(s, out var dt) ? dt.ToUniversalTime() : null
    };
}
