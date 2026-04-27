using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models.Auth;
using NetFirewall.Web.Services;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// Read-only viewer over the /Bash reference scripts. Admin-only because
/// the contents may reveal infra topology (interface names, IPs, etc).
/// </summary>
[Authorize(Roles = UserRoles.Admin)]
[Route("/Admin/BashScripts")]
public sealed class BashScriptsController : Controller
{
    private readonly IBashScriptCatalog _catalog;

    public BashScriptsController(IBashScriptCatalog catalog) => _catalog = catalog;

    [HttpGet("")]
    public async Task<IActionResult> Index(CancellationToken ct)
    {
        var entries = await _catalog.ListAsync(ct);
        return View(entries);
    }

    [HttpGet("view/{name}")]
    public async Task<IActionResult> View(string name, CancellationToken ct)
    {
        var content = await _catalog.ReadAsync(name, ct);
        if (content is null) return NotFound();
        ViewBag.Name = name;
        return base.View("_ViewScript", content);
    }
}
