using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.Wol;
using NetFirewall.Services.Daemon;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Wol;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models;
using NetFirewall.Web.Models.Network;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// Wake-on-LAN (docs/wake-on-lan.md). Saved devices are plain DB rows; every
/// wake is proxied to the daemon, which re-validates and sends the magic packet
/// out of the LAN link. The device list shows ARP presence from the daemon so
/// the operator can watch a machine come up. A wake mutates nothing on the box:
/// Admin and Operator, no step-up.
/// </summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Network/WakeOnLan")]
public sealed class WakeOnLanController : Controller
{
    /// <summary>Upper bound on ticked ids in one request — a list, not a flood.</summary>
    private const int MaxSelection = 500;

    private readonly IWolDeviceService _devices;
    private readonly IWolDeviceWakeService _waker;
    private readonly IDaemonClient _daemon;
    private readonly IFirewallService _fw;

    public WakeOnLanController(IWolDeviceService devices, IWolDeviceWakeService waker, IDaemonClient daemon, IFirewallService fw)
    {
        _devices = devices;
        _waker = waker;
        _daemon = daemon;
        _fw = fw;
    }

    [HttpGet("")]
    public async Task<IActionResult> Index(CancellationToken ct) => View(new WolPageViewModel
    {
        InterfaceOptions = await InterfaceOptionsAsync(null, ct),
        DaemonEnabled = _daemon is not NullDaemonClient,
    });

    [HttpGet("table")]
    public async Task<IActionResult> Table(CancellationToken ct) =>
        PartialView("_DevicesTable", await TableModelAsync(ct));

    /// <summary>The 15 s poll: presence badges only, swapped out-of-band (see _PresenceUpdates).</summary>
    [HttpGet("presence")]
    public async Task<IActionResult> Presence(CancellationToken ct)
    {
        var model = await TableModelAsync(ct);
        return model.Rows.Count == 0 ? NoContent() : PartialView("_PresenceUpdates", model);
    }

    [HttpGet("edit/{id:guid?}")]
    public async Task<IActionResult> Edit(Guid? id, CancellationToken ct)
    {
        var form = new WolDeviceFormViewModel();
        if (id is not null)
        {
            var device = await _devices.GetByIdAsync(id.Value, ct);
            if (device is null) return NotFound();
            form = WolDeviceFormViewModel.From(device);
        }
        return await FormAsync(form, ct);
    }

    [HttpPost("save"), ValidateAntiForgeryToken]
    [Filters.HandlesOwnValidation]
    public async Task<IActionResult> Save(WolDeviceFormViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid)
        {
            // Re-render with the offending fields marked; 200 so HTMX swaps it into the drawer.
            this.AttachToastTrigger(ServiceResponse<WolDevice>.Fail(
                string.Join(" ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage))));
            return await FormAsync(form, ct);
        }

        var saved = await _devices.SaveAsync(form.ToEntity(), ct);
        if (saved.Success) this.AttachHxEvent("refreshWol", new { });
        return this.ToHtmxResponse(saved);
    }

    [HttpPost("delete/{id:guid}"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var ok = await _devices.DeleteAsync(id, ct);
        this.AttachHxEvent("refreshWol", new { });
        return this.ToHtmxResponse(ok
            ? ServiceResponse<object>.Ok(new { }, "Device removed.")
            : ServiceResponse<object>.Fail("Device not found."));
    }

    /// <summary>Wake a saved device on its own interface and port.</summary>
    [HttpPost("wake/{id:guid}"), ValidateAntiForgeryToken]
    public async Task<IActionResult> WakeDevice(Guid id, CancellationToken ct)
    {
        var sent = await _waker.WakeAsync(id, User.Identity?.Name, ct);
        if (sent.Success) this.AttachHxEvent("refreshWol", new { });
        return this.ToHtmxResponse(sent);
    }

    /// <summary>
    /// The ticked devices, or every saved device when none is ticked (the list's one
    /// "Wake all / Wake selected" button). Partial success comes back as a warning
    /// naming the ones that failed.
    /// </summary>
    [HttpPost("wake-many"), ValidateAntiForgeryToken]
    public async Task<IActionResult> WakeMany([FromForm] string? scope, [FromForm] List<Guid>? ids, CancellationToken ct)
    {
        // The scope is explicit so a selection that fails to reach us is refused,
        // never silently widened into "wake everything".
        IReadOnlyCollection<Guid>? selection;
        switch (scope)
        {
            case "all":
                selection = null;
                break;
            case "selected" when ids is { Count: > 0 and <= MaxSelection }:
                selection = ids;
                break;
            case "selected":
                return this.ToHtmxResponse(ServiceResponse<WolBatchResult>.Fail(ids is { Count: > 0 }
                    ? $"Select at most {MaxSelection} devices at a time."
                    : "Nothing is selected."));
            default:
                return this.ToHtmxResponse(ServiceResponse<WolBatchResult>.Fail("Scope must be 'all' or 'selected'."));
        }

        var sent = await _waker.WakeManyAsync(selection, User.Identity?.Name, ct);
        if (sent.Data?.Sent > 0) this.AttachHxEvent("refreshWol", new { });
        return this.ToHtmxResponse(sent);
    }

    /// <summary>One-off wake: the quick form, and the Wake buttons on DHCP reservation / lease rows.</summary>
    [HttpPost("wake"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Wake(WolWakeFormViewModel form, CancellationToken ct)
    {
        // HTMX posts never get here invalid (ValidationToServiceResponseFilter answers 422 first).
        if (!ModelState.IsValid)
            return this.ToHtmxResponse(ServiceResponse<WolWakeResult>.Fail(
                string.Join(" ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage))));

        var sent = await _daemon.WakeOnLanAsync(form.ToRequest(), ct);
        if (sent.Success)
            sent = ServiceResponse<WolWakeResult>.Ok(sent.Data!,
                $"Wake sent to {sent.Data!.Mac} on {sent.Data.Interface}"
                + (sent.Data.InterfaceSource == "requested" ? "." : $" ({sent.Data.InterfaceSource})."));
        return this.ToHtmxResponse(sent);
    }

    // ───────────────────────── helpers ─────────────────────────

    /// <summary>Saved devices plus their ARP presence. The daemon being down blanks the status, never the list.</summary>
    private async Task<WolDevicesTableViewModel> TableModelAsync(CancellationToken ct)
    {
        var devices = await _devices.GetAllAsync(ct);
        var neighbors = devices.Count == 0
            ? ServiceResponse<IReadOnlyList<NeighborEntry>>.Ok([])
            : await _daemon.GetNeighborsAsync(null, ct);
        var arp = neighbors.Data ?? [];

        return new WolDevicesTableViewModel
        {
            Rows = devices.Select(d => new WolDeviceRow(d, WolPresence.For(d.MacAddress, arp))).ToList(),
            PresenceError = neighbors.Success ? null : neighbors.Message,
        };
    }

    private async Task<IActionResult> FormAsync(WolDeviceFormViewModel form, CancellationToken ct) =>
        PartialView("_DeviceForm", new WolDeviceFormPageViewModel
        {
            Form = form,
            InterfaceOptions = await InterfaceOptionsAsync(form.Interface, ct),
        });

    /// <summary>
    /// Configured LAN-side links. WAN and VPN are left out (the daemon refuses them
    /// anyway); a saved device's current interface stays listed even if it has since
    /// been removed, so opening the drawer never silently re-points the device.
    /// </summary>
    private async Task<IReadOnlyList<FormFieldViewModel.SelectOption>> InterfaceOptionsAsync(string? current, CancellationToken ct)
    {
        var lan = (await _fw.GetInterfacesAsync(ct))
            .Where(i => !string.IsNullOrWhiteSpace(i.Name) && IsLanSide(i))
            .OrderBy(i => i.Name, StringComparer.Ordinal)
            .ToList();

        var options = new List<FormFieldViewModel.SelectOption> { new("", "(pick an interface)") };
        options.AddRange(lan.Select(i => new FormFieldViewModel.SelectOption(i.Name, Label(i))));
        if (!string.IsNullOrWhiteSpace(current) && lan.All(i => i.Name != current))
            options.Add(new(current, $"{current} (not configured)"));
        return options;

        static string Label(FwInterface i) =>
            i.IpAddress is null ? $"{i.Name} · {i.Type}" : $"{i.Name} · {i.Type} · {i.IpAddress}";
    }

    private static bool IsLanSide(FwInterface i) =>
        !string.Equals(i.Type, "WAN", StringComparison.OrdinalIgnoreCase) &&
        !string.Equals(i.Type, "VPN", StringComparison.OrdinalIgnoreCase);
}
