using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Daemon;
using NetFirewall.Services.Vpn;
using NetFirewall.Web.Filters;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models.Vpn;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// VPN → Outbound connections: what this firewall DIALS — a VPN provider it egresses through, or
/// a remote site it links to. Each connection is its own client-kind interface (wgc1, wgc2 …),
/// created from the config the other side issued. Apply / Stop / Delete reuse the per-interface
/// WireGuard endpoints with an explicit <c>iface</c>.
/// </summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Vpn/Outbound")]
public sealed class OutboundConnectionsController(
    IWireGuardInterfaceResolver ifaces,
    IVpnRoutingService vpnRouting,
    IDaemonClient daemon,
    IWireGuardSplitService split,
    ILogger<OutboundConnectionsController> logger) : Controller
{
    [HttpGet("")]
    public async Task<IActionResult> Index(string? created, string? deleted, CancellationToken ct)
    {
        var vm = OutboundConnectionsPageViewModel.From(
            await ifaces.ListWithPeersAsync(ct), created, deleted, Request.Query.ContainsKey("applyWarn"));
        vm.PendingSplit = await SafePendingAsync(ct);
        return View(vm);
    }

    // ── Split a dual-role interface (dry run → execute → confirm or auto-revert) ──

    /// <summary>The dry run: what moves where, the addresses to choose, hand rules to review.</summary>
    [HttpGet("split/{iface}")]
    public async Task<IActionResult> SplitPlan(string iface, [FromQuery] string[]? serverAddress, CancellationToken ct)
    {
        if (!NetFirewall.Models.Vpn.WgInterfaceName.IsValid(iface)) return NotFound();
        var plan = await split.PlanAsync(iface, serverAddress is { Length: > 0 } ? serverAddress : null, ct);
        return plan is null ? NotFound() : PartialView("_SplitPlan", plan);
    }

    [HttpPost("split/{iface}"), ValidateAntiForgeryToken, RequireElevated]
    public async Task<IActionResult> Split(string iface, [FromForm] string[]? serverAddress, [FromForm] string? confirmName, CancellationToken ct)
    {
        if (!NetFirewall.Models.Vpn.WgInterfaceName.IsValid(iface))
            return this.ToHtmxResponse(ServiceResponse<object>.Fail("Invalid interface name."));
        if (!string.Equals(confirmName?.Trim(), iface, StringComparison.Ordinal))
            return this.ToHtmxResponse(ServiceResponse<object>.Fail($"Type the interface name ('{iface}') to confirm the split."));
        if (serverAddress is not { Length: > 0 })
            return this.ToHtmxResponse(ServiceResponse<object>.Fail("Pick the address the VPN server keeps."));

        var done = await split.ExecuteAsync(iface, serverAddress, User.Identity?.Name, ct);
        if (!done.Success) return this.ToHtmxResponse(done);
        Response.Headers["HX-Redirect"] = "/Vpn/Outbound";
        return Json(done);
    }

    [HttpPost("split/confirm/{id:guid}"), ValidateAntiForgeryToken, RequireElevated]
    public async Task<IActionResult> ConfirmSplit(Guid id, CancellationToken ct)
    {
        var r = await split.ConfirmAsync(id, ct);
        if (r.Success) this.AttachHxEvent("refreshWireGuard", new { });
        Response.Headers["HX-Refresh"] = "true";
        return this.ToHtmxResponse(r);
    }

    [HttpPost("split/revert/{id:guid}"), ValidateAntiForgeryToken, RequireElevated]
    public async Task<IActionResult> RevertSplit(Guid id, CancellationToken ct)
    {
        var r = await split.RevertAsync(id, "reverted by the operator", ct);
        Response.Headers["HX-Refresh"] = "true";
        return this.ToHtmxResponse(r);
    }

    private async Task<WgSplitPending?> SafePendingAsync(CancellationToken ct)
    {
        try { return await split.PendingAsync(ct); }
        catch (Npgsql.PostgresException ex) when (ex.SqlState == Npgsql.PostgresErrorCodes.UndefinedTable) { return null; }
    }

    [HttpGet("new")]
    public IActionResult New() => PartialView("_NewConnection", new OutboundConnectionFormViewModel());

    /// <summary>
    /// Daemon validates the paste (no script hooks, one peer) and stores the interface; then the
    /// routing scaffold (interface row, table, mark) and the peer's forwarding are built here, so
    /// the connection is complete before the operator applies.
    /// </summary>
    [HttpPost("create"), ValidateAntiForgeryToken, RequireElevated]
    public async Task<IActionResult> Create(OutboundConnectionFormViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid)
            return this.ToHtmxResponse(ServiceResponse<object>.Fail(
                string.Join(" ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage))));

        var created = await daemon.CreateWireGuardOutboundAsync(new WgOutboundCreateRequest(form.ConfigText, form.Label), ct);
        if (!created.Success || created.Data is null)
            return this.ToHtmxResponse(ServiceResponse<object>.Fail(created.Message ?? "The connection could not be created."));

        var server = await ifaces.RequireAsync(created.Data.Interface, ct);
        if (server is not null)
        {
            try
            {
                await vpnRouting.EnsureRoutingScaffoldAsync(server, ct);
                foreach (var (s, peers) in (await ifaces.ListWithPeersAsync(ct)).Where(x => x.Server.Id == server.Id))
                    foreach (var p in peers) await vpnRouting.EnsurePeerForwardingAsync(s, p, ct);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Routing scaffold for {Iface} failed after create", server.Name);
                return this.ToHtmxResponse(ServiceResponse<object>.Fail(
                    $"{server.Name} was created, but its routing could not be prepared: {ex.Message}. Open it and save again, or delete it."));
            }
        }

        Response.Headers["HX-Redirect"] = $"/Vpn/Outbound?created={Uri.EscapeDataString(created.Data.Interface)}";
        return Json(ServiceResponse<object>.Ok(new { created.Data.Interface }, created.Message ?? "Connection created."));
    }
}
