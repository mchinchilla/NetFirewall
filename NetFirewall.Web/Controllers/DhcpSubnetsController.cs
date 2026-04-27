using System.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Settings;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models.Dhcp;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// CRUD over <c>dhcp_subnets</c>. Honors rule #10 — every IO call goes
/// through <see cref="IDhcpAdminService"/>; the controller only orchestrates
/// + maps view models.
/// </summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Dhcp/Subnets")]
public sealed class DhcpSubnetsController : Controller
{
    private readonly IDhcpAdminService _admin;
    private readonly IFirewallService _firewall;
    private readonly IAppSettingsService _settings;
    private readonly ILogger<DhcpSubnetsController> _logger;

    public DhcpSubnetsController(
        IDhcpAdminService admin,
        IFirewallService firewall,
        IAppSettingsService settings,
        ILogger<DhcpSubnetsController> logger)
    {
        _admin = admin;
        _firewall = firewall;
        _settings = settings;
        _logger = logger;
    }

    [HttpGet("")]
    public IActionResult Index() => View();

    [HttpGet("table")]
    public async Task<IActionResult> Table(CancellationToken ct)
    {
        var subnetsTask    = _admin.GetSubnetsAsync(ct);
        var exclusionsTask = _admin.GetExclusionsAsync(null, ct);
        var poolsTask      = _admin.GetPoolsAsync(null, ct);
        await Task.WhenAll(subnetsTask, exclusionsTask, poolsTask);

        ViewBag.ExclusionCounts = exclusionsTask.Result
            .GroupBy(e => e.SubnetId)
            .ToDictionary(g => g.Key, g => g.Count());
        ViewBag.PoolCounts = poolsTask.Result
            .Where(p => p.SubnetId.HasValue)
            .GroupBy(p => p.SubnetId!.Value)
            .ToDictionary(g => g.Key, g => g.Count());

        return PartialView("_SubnetsTable", subnetsTask.Result);
    }

    [HttpGet("edit/{id:guid?}")]
    public async Task<IActionResult> Edit(Guid? id, CancellationToken ct)
    {
        ViewBag.Interfaces = await _firewall.GetInterfacesAsync(ct);
        if (id is null)
        {
            // Pre-fill new subnet with the operator's defaults from app_settings.
            var leaseSec = await _settings.GetIntAsync("dhcp.default_lease_seconds", ct);
            var dnsRaw   = await _settings.GetStringAsync("dhcp.default_dns_servers", ct);
            return PartialView("_SubnetForm", new SubnetFormViewModel
            {
                DefaultLeaseTime = leaseSec > 0 ? leaseSec : 86400,
                MaxLeaseTime     = leaseSec > 0 ? leaseSec * 2 : 172800,
                DnsServersRaw    = dnsRaw,
            });
        }

        var subnet = await _admin.GetSubnetByIdAsync(id.Value, ct);
        return subnet is null ? NotFound() : PartialView("_SubnetForm", FromEntity(subnet));
    }

    [HttpPost("save"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(SubnetFormViewModel form, CancellationToken ct)
    {
        try
        {
            var entity = ToEntity(form);
            DhcpSubnet saved;
            if (form.Id.HasValue && await _admin.GetSubnetByIdAsync(form.Id.Value, ct) is not null)
            {
                entity.Id = form.Id.Value;
                saved = await _admin.UpdateSubnetAsync(entity, ct);
            }
            else
            {
                saved = await _admin.CreateSubnetAsync(entity, ct);
            }

            var envelope = ServiceResponse<DhcpSubnet>.Ok(saved, $"Subnet {saved.Name} saved.");
            this.AttachToastTrigger(envelope);
            Response.Headers["HX-Trigger"] = MergeTrigger(Response.Headers["HX-Trigger"].ToString(), "refreshSubnets");
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save subnet");
            return this.ToHtmxResponse(ServiceResponse<DhcpSubnet>.Fail($"Save failed: {ex.Message}"));
        }
    }

    [HttpPost("delete/{id:guid}"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var ok = await _admin.DeleteSubnetAsync(id, ct);
        var envelope = ok
            ? ServiceResponse<object>.Ok(new { }, "Subnet deleted.")
            : ServiceResponse<object>.Fail("Subnet not found or has dependent records.");
        Response.Headers["HX-Trigger"] = MergeTrigger(Response.Headers["HX-Trigger"].ToString(), "refreshSubnets");
        return this.ToHtmxResponse(envelope);
    }

    // ---------- mapping helpers (pure, no IO — OK in controller) ----------

    private static SubnetFormViewModel FromEntity(DhcpSubnet s) => new()
    {
        Id = s.Id,
        Name = s.Name,
        Network = s.Network,
        SubnetMask = s.SubnetMask?.ToString() ?? "255.255.255.0",
        Router = s.Router?.ToString(),
        Broadcast = s.Broadcast?.ToString(),
        DomainName = s.DomainName,
        DnsServersRaw = JoinIps(s.DnsServers),
        NtpServersRaw = JoinIps(s.NtpServers),
        WinsServersRaw = JoinIps(s.WinsServers),
        DefaultLeaseTime = s.DefaultLeaseTime,
        MaxLeaseTime = s.MaxLeaseTime,
        InterfaceMtu = s.InterfaceMtu,
        TftpServer = s.TftpServer,
        BootFilename = s.BootFilename,
        BootFilenameUefi = s.BootFilenameUefi,
        DomainSearchList = s.DomainSearchList,
        InterfaceId = s.InterfaceId,
        Enabled = s.Enabled
    };

    private static DhcpSubnet ToEntity(SubnetFormViewModel f) => new()
    {
        Name = f.Name,
        Network = f.Network,
        SubnetMask = IPAddress.Parse(f.SubnetMask),
        Router = string.IsNullOrWhiteSpace(f.Router) ? null : IPAddress.Parse(f.Router),
        Broadcast = string.IsNullOrWhiteSpace(f.Broadcast) ? null : IPAddress.Parse(f.Broadcast),
        DomainName = f.DomainName,
        DnsServers = ParseIps(f.DnsServersRaw),
        NtpServers = ParseIps(f.NtpServersRaw),
        WinsServers = ParseIps(f.WinsServersRaw),
        DefaultLeaseTime = f.DefaultLeaseTime,
        MaxLeaseTime = f.MaxLeaseTime,
        InterfaceMtu = f.InterfaceMtu,
        TftpServer = f.TftpServer,
        BootFilename = f.BootFilename,
        BootFilenameUefi = f.BootFilenameUefi,
        DomainSearchList = f.DomainSearchList,
        InterfaceId = f.InterfaceId,
        Enabled = f.Enabled
    };

    private static string? JoinIps(IPAddress[]? arr) =>
        arr is { Length: > 0 } ? string.Join(", ", arr.Select(a => a.ToString())) : null;

    private static IPAddress[]? ParseIps(string? raw) =>
        string.IsNullOrWhiteSpace(raw)
            ? null
            : raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                 .Select(IPAddress.Parse).ToArray();

    private static string MergeTrigger(string existing, string evt)
    {
        if (string.IsNullOrEmpty(existing)) return $"{{\"{evt}\":{{}}}}";
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(existing);
            var dict = doc.RootElement.EnumerateObject().ToDictionary(p => p.Name, p => (object)p.Value.Clone());
            dict[evt] = new { };
            return System.Text.Json.JsonSerializer.Serialize(dict);
        }
        catch { return existing; }
    }
}
