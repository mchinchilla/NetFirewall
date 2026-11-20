using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models.Auth;

namespace NetFirewall.Web.Controllers;

/// <summary>DHCP → Lease history (the grid reads <c>IDhcpLeaseHistoryService</c> itself).</summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Dhcp/History")]
public sealed class DhcpLeaseHistoryController : Controller
{
    [HttpGet("")]
    public IActionResult Index() => View();
}
