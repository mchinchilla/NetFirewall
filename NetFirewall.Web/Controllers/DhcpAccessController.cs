using System.Net;
using System.Net.NetworkInformation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models.Dhcp;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// DHCP → Access control: MAC addresses the server never answers, and the relay agents it
/// trusts. Both lists live in the DB; their triggers tell the DHCP server (00053 / 00054).
/// </summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Dhcp/Access")]
public sealed class DhcpAccessController(IDhcpAccessControlService access) : Controller
{
    [HttpGet("")]
    public IActionResult Index() => View();

    // ---------- blocked MACs ----------

    [HttpGet("blocked/edit/{id:guid?}")]
    public async Task<IActionResult> EditBlocked(Guid? id, [FromQuery] string? mac, CancellationToken ct)
    {
        if (id is null) return PartialView("_BlockedMacForm", new BlockedMacFormViewModel { MacAddress = mac ?? string.Empty });
        var entry = await access.GetBlockedMacAsync(id.Value, ct);
        return entry is null ? NotFound() : PartialView("_BlockedMacForm", new BlockedMacFormViewModel
        {
            Id = entry.Id, MacAddress = MacText(entry.MacAddress), Reason = entry.Reason,
        });
    }

    [HttpPost("blocked/save"), ValidateAntiForgeryToken]
    public async Task<IActionResult> SaveBlocked(BlockedMacFormViewModel form, CancellationToken ct)
    {
        var result = await access.SaveBlockedMacAsync(new DhcpBlockedMac
        {
            Id = form.Id ?? Guid.Empty,
            MacAddress = PhysicalAddress.Parse(form.MacAddress.Replace(":", "-").ToUpperInvariant()),
            Reason = form.Reason,
        }, ct);
        if (result.Success) this.AttachHxEvent("refreshDhcpAccess", new { });
        return this.ToHtmxResponse(result.Success
            ? NetFirewall.Models.ServiceResponse<object>.Ok(new { id = result.Data!.Id }, result.Message)
            : NetFirewall.Models.ServiceResponse<object>.Fail(result.Message ?? "Save failed."));
    }

    [HttpPost("blocked/delete/{id:guid}"), ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteBlocked(Guid id, CancellationToken ct)
    {
        var result = await access.DeleteBlockedMacAsync(id, ct);
        this.AttachHxEvent("refreshDhcpAccess", new { });
        return this.ToHtmxResponse(result);
    }

    // ---------- relay agents ----------

    [HttpGet("relays/edit/{id:guid?}")]
    public async Task<IActionResult> EditRelay(Guid? id, CancellationToken ct)
    {
        if (id is null) return PartialView("_RelayAgentForm", new RelayAgentFormViewModel());
        var relay = await access.GetRelayAgentAsync(id.Value, ct);
        return relay is null ? NotFound() : PartialView("_RelayAgentForm", new RelayAgentFormViewModel
        {
            Id = relay.Id, IpAddress = relay.IpAddress.ToString(), Description = relay.Description, Trusted = relay.Trusted,
        });
    }

    // Changing who may relay can cut off whole remote subnets: Admin + step-up.
    [HttpPost("relays/save"), ValidateAntiForgeryToken]
    [Authorize(Roles = UserRoles.Admin)]
    [Filters.RequireElevated]
    public async Task<IActionResult> SaveRelay(RelayAgentFormViewModel form, CancellationToken ct)
    {
        var result = await access.SaveRelayAgentAsync(new DhcpRelayAgent
        {
            Id = form.Id ?? Guid.Empty,
            IpAddress = IPAddress.Parse(form.IpAddress),
            Description = form.Description,
            Trusted = form.Trusted,
        }, ct);
        if (result.Success) this.AttachHxEvent("refreshDhcpAccess", new { });
        return this.ToHtmxResponse(result.Success
            ? NetFirewall.Models.ServiceResponse<object>.Ok(new { id = result.Data!.Id }, result.Message)
            : NetFirewall.Models.ServiceResponse<object>.Fail(result.Message ?? "Save failed."));
    }

    [HttpPost("relays/delete/{id:guid}"), ValidateAntiForgeryToken]
    [Authorize(Roles = UserRoles.Admin)]
    [Filters.RequireElevated]
    public async Task<IActionResult> DeleteRelay(Guid id, CancellationToken ct)
    {
        var result = await access.DeleteRelayAgentAsync(id, ct);
        this.AttachHxEvent("refreshDhcpAccess", new { });
        return this.ToHtmxResponse(result);
    }

    private static string MacText(PhysicalAddress mac) => string.Join(":", mac.GetAddressBytes().Select(b => b.ToString("X2")));
}
