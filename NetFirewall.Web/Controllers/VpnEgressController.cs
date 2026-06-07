using System.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Dhcp;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Vpn;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models.Vpn;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// "Which LAN devices egress via the tunnel" panel. Thin: composes IVpnRoutingService
/// (which compiles selections down to traffic-mark + mangle rows) + the DHCP lease
/// picker + LAN subnet list.
/// </summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Vpn/WireGuard/Egress")]
public sealed class VpnEgressController : Controller
{
    private readonly IWireGuardService _wg;
    private readonly IVpnRoutingService _vpnRouting;
    private readonly IFirewallService _fw;
    private readonly IDhcpAdminService _dhcp;
    private readonly ILogger<VpnEgressController> _logger;

    public VpnEgressController(
        IWireGuardService wg,
        IVpnRoutingService vpnRouting,
        IFirewallService fw,
        IDhcpAdminService dhcp,
        ILogger<VpnEgressController> logger)
    {
        _wg = wg;
        _vpnRouting = vpnRouting;
        _fw = fw;
        _dhcp = dhcp;
        _logger = logger;
    }

    [HttpGet("panel")]
    public async Task<IActionResult> Panel(CancellationToken ct)
    {
        var server = await _wg.GetServerAsync(ct);
        if (server is null) return PartialView("_EgressPanel", EmptyVm("wg0", false));

        var sources = await _vpnRouting.GetEgressSourcesAsync(server, ct);
        // ScaffoldReady = there's a mark/table the egress sources can attach to.
        var scaffoldReady = sources.Count > 0
            || (await _fw.GetTrafficMarksAsync(ct)).Any(m =>
                   string.Equals(m.RouteTable, server.Name, StringComparison.OrdinalIgnoreCase));

        var leases = await SafeLeasesAsync(ct);
        var lanSubnets = LanSubnets(await _fw.GetInterfacesAsync(ct));

        return PartialView("_EgressPanel", new VpnEgressViewModel
        {
            TunnelName = server.Name,
            ScaffoldReady = scaffoldReady,
            CurrentSources = sources,
            Leases = leases,
            LanSubnets = lanSubnets,
        });
    }

    [HttpPost("save"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Save([FromForm] string[]? sources, CancellationToken ct)
    {
        var server = await _wg.GetServerAsync(ct);
        if (server is null)
            return this.ToHtmxResponse(ServiceResponse<object>.Fail("No WireGuard tunnel configured."));

        try
        {
            await _vpnRouting.SetEgressSourcesAsync(server, sources ?? Array.Empty<string>(), ct);
            Response.Headers["HX-Trigger"] = "refreshWireGuard";
            return this.ToHtmxResponse(ServiceResponse<object>.Ok(new { },
                "Egress devices updated. Apply to push the routing to the kernel."));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "VPN egress save failed");
            return this.ToHtmxResponse(ServiceResponse<object>.Fail($"Save failed: {ex.Message}"));
        }
    }

    // ----- helpers -----

    private static VpnEgressViewModel EmptyVm(string name, bool ready) => new()
    {
        TunnelName = name, ScaffoldReady = ready,
        CurrentSources = Array.Empty<string>(), Leases = Array.Empty<EgressHost>(),
        LanSubnets = Array.Empty<string>(),
    };

    private async Task<IReadOnlyList<EgressHost>> SafeLeasesAsync(CancellationToken ct)
    {
        try
        {
            var leases = await _dhcp.GetActiveLeasesAsync(null, ct);
            return leases
                .Select(l => new EgressHost(l.IpAddress.ToString(), l.Hostname, l.MacAddress.ToString()))
                .OrderBy(h => h.Hostname ?? h.Ip, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "DHCP lease fetch failed for egress picker");
            return Array.Empty<EgressHost>();
        }
    }

    private static IReadOnlyList<string> LanSubnets(IReadOnlyList<NetFirewall.Models.Firewall.FwInterface> ifaces) =>
        ifaces
            .Where(i => i.Type == "LAN" && i.Enabled && i.IpAddress is not null && i.SubnetMask is not null)
            .Select(i => ToCidr(i.IpAddress!, i.SubnetMask!))
            .Where(c => c is not null).Select(c => c!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    private static string? ToCidr(IPAddress ip, IPAddress mask)
    {
        var mb = mask.GetAddressBytes();
        int bits = mb.Sum(b => System.Numerics.BitOperations.PopCount((uint)b));
        var ib = ip.GetAddressBytes();
        if (ib.Length != mb.Length) return null;
        for (int i = 0; i < ib.Length; i++) ib[i] &= mb[i];
        return $"{new IPAddress(ib)}/{bits}";
    }
}
