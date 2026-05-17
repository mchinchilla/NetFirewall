using System.Net;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Daemon;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models.Network;

namespace NetFirewall.Web.Controllers;

public sealed class NetworkController : Controller
{
    private readonly ILinuxDistroService _distroService;
    private readonly IFirewallService _firewallService;
    private readonly INetworkConfigResolver _configResolver;
    private readonly IDaemonClient _daemon;
    private readonly ILogger<NetworkController> _logger;

    public NetworkController(
        ILinuxDistroService distroService,
        IFirewallService firewallService,
        INetworkConfigResolver configResolver,
        IDaemonClient daemon,
        ILogger<NetworkController> logger)
    {
        _distroService = distroService;
        _firewallService = firewallService;
        _configResolver = configResolver;
        _daemon = daemon;
        _logger = logger;
    }

    [HttpGet("/Network/Interfaces")]
    public async Task<IActionResult> Interfaces(CancellationToken ct)
    {
        var distro = await _distroService.DetectDistributionAsync(ct);
        return View(distro);
    }

    [HttpGet("/Network/InterfacesTable")]
    public async Task<IActionResult> InterfacesTable(CancellationToken ct)
    {
        var rows = await BuildRowsAsync(ct);
        return PartialView("_InterfaceTable", rows);
    }

    // Real re-detect: asks the daemon to walk /sys/class/net and reconcile
    // fw_interfaces (UPSERT ip/mask/gateway/mac/mtu, preserve operator edits).
    // The button on /Network/Interfaces points here instead of just re-listing.
    [HttpPost("/Network/Redetect")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Redetect(CancellationToken ct)
    {
        var resp = await _daemon.RedetectInterfacesAsync(ct);
        var rows = await BuildRowsAsync(ct);

        var summary = resp.Success && resp.Data is not null
            ? $"Re-detect: {resp.Data.Added} new · {resp.Data.Updated} updated · {resp.Data.Missing} missing"
            : resp.Message ?? "Re-detect failed.";

        this.AttachHxEvent("showToast", new { level = resp.Success ? "success" : "error", message = summary });
        return PartialView("_InterfaceTable", rows);
    }

    [HttpGet("/Network/Edit/{name}")]
    public async Task<IActionResult> Edit(string name, CancellationToken ct)
    {
        var configured = await _firewallService.GetInterfaceByNameAsync(name, ct);
        var detected = (await _distroService.DiscoverInterfacesAsync(ct))
            .FirstOrDefault(d => d.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

        var form = configured != null
            ? FromExisting(configured)
            : FromDetected(name, detected);

        return PartialView("_InterfaceForm", form);
    }

    [HttpPost("/Network/Save")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(InterfaceFormViewModel form, CancellationToken ct)
    {
        // ModelState invalid → ValidationToServiceResponseFilter already returned 422 with field errors.
        var iface = ApplyToEntity(form);

        try
        {
            FwInterface saved;
            if (form.Id.HasValue && await _firewallService.GetInterfaceByIdAsync(form.Id.Value, ct) != null)
            {
                iface.Id = form.Id.Value;
                saved = await _firewallService.UpdateInterfaceAsync(iface, ct);
            }
            else
            {
                saved = await _firewallService.CreateInterfaceAsync(iface, ct);
            }

            var envelope = ServiceResponse<FwInterface>.Ok(saved, $"Interface {saved.Name} saved.");
            this.AttachToastTrigger(envelope);

            // Refresh the row in the table via HTMX out-of-band swap.
            Response.Headers["HX-Trigger"] = AppendTrigger(Response.Headers["HX-Trigger"].ToString(), "refreshInterfaces");
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save interface {Name}", form.Name);
            return this.ToHtmxResponse(ServiceResponse<FwInterface>.Fail($"Save failed: {ex.Message}"));
        }
    }

    [HttpGet("/Network/Preview/{id:guid}")]
    public async Task<IActionResult> Preview(Guid id, CancellationToken ct)
    {
        var iface = await _firewallService.GetInterfaceByIdAsync(id, ct);
        if (iface == null) return NotFound();

        var writer = await _configResolver.ResolveAsync(ct);
        var config = await writer.GenerateConfigAsync(iface);

        return PartialView("_PreviewBlock", new PreviewViewModel(
            FilePath: writer.GetConfigFilePath(iface),
            Method: writer.ConfigMethod.ToString(),
            Content: config));
    }

    [HttpPost("/Network/Apply/{id:guid}")]
    [ValidateAntiForgeryToken]
    [NetFirewall.Web.Filters.RequireElevated]
    public async Task<IActionResult> Apply(Guid id, CancellationToken ct)
    {
        var iface = await _firewallService.GetInterfaceByIdAsync(id, ct);
        if (iface == null)
            return this.ToHtmxResponse(ServiceResponse<object>.Fail("Interface not found."));

        var writer = await _configResolver.ResolveAsync(ct);
        var result = await writer.ApplyConfigAsync(iface);

        var envelope = result.Success
            ? ServiceResponse<NetworkApplyResultDto>.Ok(NetworkApplyResultDto.From(result), result.Message)
            : ServiceResponse<NetworkApplyResultDto>.Fail(result.Message);

        Response.Headers["HX-Trigger"] = AppendTrigger(Response.Headers["HX-Trigger"].ToString(), "refreshInterfaces");
        return this.ToHtmxResponse(envelope);
    }

    // ---------- Helpers ----------

    private async Task<List<InterfaceRowViewModel>> BuildRowsAsync(CancellationToken ct)
    {
        var detected = await _distroService.DiscoverInterfacesAsync(ct);
        var configured = await _firewallService.GetInterfacesAsync(ct);

        var byName = configured.ToDictionary(c => c.Name, StringComparer.OrdinalIgnoreCase);
        var rows = new List<InterfaceRowViewModel>();

        foreach (var d in detected)
        {
            byName.TryGetValue(d.Name, out var fw);
            rows.Add(new InterfaceRowViewModel
            {
                Name = d.Name,
                MacAddress = d.MacAddress,
                IsUp = d.IsUp,
                IsVirtual = d.IsVirtual,
                CurrentIp = d.CurrentIp?.ToString(),
                CurrentGateway = d.CurrentGateway?.ToString(),
                SuggestedType = d.SuggestedType,
                SuggestedRole = d.SuggestedRole,
                SuggestionConfidence = d.Confidence,
                SuggestionReason = d.Reason,
                Configured = fw,
                Status = fw == null ? InterfaceRowStatus.Detected : InterfaceRowStatus.Configured
            });
        }

        // Configured interfaces no longer detected by the OS.
        foreach (var fw in configured.Where(c => !rows.Any(r => r.Name.Equals(c.Name, StringComparison.OrdinalIgnoreCase))))
        {
            rows.Add(new InterfaceRowViewModel
            {
                Name = fw.Name,
                MacAddress = fw.MacAddress,
                IsUp = false,
                Configured = fw,
                SuggestedType = fw.Type,
                SuggestedRole = fw.Role ?? string.Empty,
                Status = InterfaceRowStatus.Missing
            });
        }

        return rows.OrderBy(r => r.Status).ThenBy(r => r.Name).ToList();
    }

    private static InterfaceFormViewModel FromExisting(FwInterface fw) => new()
    {
        Id = fw.Id,
        Name = fw.Name,
        Type = fw.Type,
        Role = fw.Role,
        AddressingMode = fw.AddressingMode,
        IpAddress = fw.IpAddress?.ToString(),
        SubnetMask = fw.SubnetMask?.ToString(),
        Gateway = fw.Gateway?.ToString(),
        DnsServers = fw.DnsServers != null ? string.Join(", ", fw.DnsServers.Select(d => d.ToString())) : null,
        Mtu = fw.Mtu,
        VlanId = fw.VlanId,
        VlanParent = fw.VlanParent,
        Description = fw.Description,
        AutoStart = fw.AutoStart,
        Enabled = fw.Enabled
    };

    private static InterfaceFormViewModel FromDetected(string name, NetFirewall.Models.System.InterfaceSuggestion? d) => new()
    {
        Name = name,
        Type = d?.SuggestedType ?? "LAN",
        Role = d?.SuggestedRole,
        AddressingMode = d?.CurrentIp != null ? "static" : "dhcp",
        IpAddress = d?.CurrentIp?.ToString(),
        SubnetMask = d?.CurrentSubnet,
        Gateway = d?.CurrentGateway?.ToString(),
        Mtu = d?.Mtu,
        Description = d != null ? $"Auto-detected — confidence {d.Confidence}% ({d.Reason})" : null
    };

    private static FwInterface ApplyToEntity(InterfaceFormViewModel f)
    {
        IPAddress[]? dns = null;
        if (!string.IsNullOrWhiteSpace(f.DnsServers))
        {
            dns = f.DnsServers.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(s => IPAddress.Parse(s)).ToArray();
        }

        return new FwInterface
        {
            Name = f.Name,
            Type = f.Type,
            Role = f.Role,
            AddressingMode = f.AddressingMode,
            IpAddress = string.IsNullOrWhiteSpace(f.IpAddress) ? null : IPAddress.Parse(f.IpAddress),
            SubnetMask = string.IsNullOrWhiteSpace(f.SubnetMask) ? null : IPAddress.Parse(f.SubnetMask),
            Gateway = string.IsNullOrWhiteSpace(f.Gateway) ? null : IPAddress.Parse(f.Gateway),
            DnsServers = dns,
            Mtu = f.Mtu,
            VlanId = f.VlanId,
            VlanParent = f.VlanParent,
            Description = f.Description,
            AutoStart = f.AutoStart,
            Enabled = f.Enabled
        };
    }

    private static string AppendTrigger(string existing, string evt)
    {
        if (string.IsNullOrEmpty(existing)) return evt;
        // Existing may already be JSON (e.g. {"showToast":...}). Merge keys.
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(existing);
            var dict = doc.RootElement.EnumerateObject().ToDictionary(p => p.Name, p => (object)p.Value.Clone());
            dict[evt] = new { };
            return System.Text.Json.JsonSerializer.Serialize(dict);
        }
        catch
        {
            return $"{existing},{evt}";
        }
    }

    public sealed record PreviewViewModel(string FilePath, string Method, string Content);

    public sealed record NetworkApplyResultDto(string? FilePath, string? Backup, int ExitCode)
    {
        public static NetworkApplyResultDto From(NetFirewall.Models.System.NetworkApplyResult r) =>
            new(r.ConfigFilePath, r.BackupFilePath, r.ExitCode);
    }
}
