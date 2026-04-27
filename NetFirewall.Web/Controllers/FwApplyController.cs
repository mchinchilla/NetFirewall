using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Firewall;
using NetFirewall.Web.Daemon;
using NetFirewall.Web.Helpers;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// Firewall apply page.
///   - Preview: pure local string-build of the would-be /etc/nftables.conf
///     via IFirewallService.GenerateNftablesConfigPreviewAsync — no privilege.
///   - Apply : delegates to the daemon (which writes the file + runs `nft -f`).
///   - Current ruleset: read live `nft list ruleset` from the daemon.
/// </summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Firewall/Apply")]
public sealed class FwApplyController : Controller
{
    private readonly IFirewallService _firewall;
    private readonly IDaemonClient _daemon;
    private readonly ILogger<FwApplyController> _logger;

    public FwApplyController(
        IFirewallService firewall,
        IDaemonClient daemon,
        ILogger<FwApplyController> logger)
    {
        _firewall = firewall;
        _daemon = daemon;
        _logger = logger;
    }

    [HttpGet("")]
    public IActionResult Index() => View();

    [HttpGet("preview")]
    public async Task<IActionResult> Preview(CancellationToken ct)
    {
        try
        {
            var generated = await _firewall.GenerateNftablesConfigPreviewAsync(ct);
            return PartialView("_PreviewBlock", generated);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to generate nftables preview");
            return this.ToHtmxResponse(ServiceResponse<string>.Fail($"Preview failed: {ex.Message}"));
        }
    }

    [HttpGet("current-ruleset")]
    public async Task<IActionResult> CurrentRuleset(CancellationToken ct)
    {
        var current = await _daemon.GetCurrentRulesetAsync(ct)
                      ?? "(daemon unreachable — could not read live ruleset)";
        return PartialView("_CurrentRulesetBlock", current);
    }

    [HttpPost("execute"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    public async Task<IActionResult> Execute(CancellationToken ct)
    {
        var envelope = await _daemon.ApplyFirewallAsync(ct);
        Response.Headers["HX-Trigger"] = "firewallApplied";
        return this.ToHtmxResponse(envelope);
    }

    [HttpGet("qos-preview")]
    public async Task<IActionResult> QosPreview(CancellationToken ct)
    {
        try
        {
            var script = await _firewall.GenerateTcScriptAsync(ct);
            return PartialView("_PreviewBlock", script);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to generate tc script");
            return this.ToHtmxResponse(ServiceResponse<string>.Fail($"Preview failed: {ex.Message}"));
        }
    }

    [HttpPost("qos-execute"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    public async Task<IActionResult> QosExecute(CancellationToken ct)
    {
        var envelope = await _daemon.ApplyQosAsync(ct);
        Response.Headers["HX-Trigger"] = "qosApplied";
        return this.ToHtmxResponse(envelope);
    }
}
