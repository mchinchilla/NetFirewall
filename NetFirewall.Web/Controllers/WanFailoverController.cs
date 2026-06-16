using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.WanMonitor;
using NetFirewall.Services.Daemon;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.WanMonitor;
using NetFirewall.Web.Filters;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models.Network;
using NetFirewall.Web.Services;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// WAN failover status + control, under the Network module. Shows which WAN is
/// active, lets the operator pin one (sticky override) or swap, and CRUDs the
/// per-WAN probe config. Thin: health reads + config writes go to the DB service;
/// the route swap is delegated to the daemon (CAP_NET_ADMIN).
/// </summary>
[Route("/Network/Wan")]
public sealed class WanFailoverController : Controller
{
    private readonly IWanHealthService _health;
    private readonly IFirewallService _firewall;
    private readonly IDaemonClient _daemon;
    private readonly IWanHealthCardBuilder _cardBuilder;
    private readonly ILogger<WanFailoverController> _logger;

    public WanFailoverController(
        IWanHealthService health,
        IFirewallService firewall,
        IDaemonClient daemon,
        IWanHealthCardBuilder cardBuilder,
        ILogger<WanFailoverController> logger)
    {
        _health = health;
        _firewall = firewall;
        _daemon = daemon;
        _cardBuilder = cardBuilder;
        _logger = logger;
    }

    [HttpGet("")]
    public IActionResult Index() => View();

    // Live panel — health + active/override + recent events + interactive controls.
    // Renders the shared WAN-health card (Panel mode); ManageUrl is null because
    // this *is* the manage page. Polled by the page.
    [HttpGet("panel")]
    public async Task<IActionResult> Panel(CancellationToken ct)
    {
        var vm = await _cardBuilder.BuildAsync(WanCardOptions.Panel(), ct);
        return PartialView("_WanHealthCard", vm);
    }

    // Config editor for one WAN (drawer). id = the interface id.
    [HttpGet("config/{interfaceId:guid}")]
    public async Task<IActionResult> Config(Guid interfaceId, CancellationToken ct)
    {
        var cfg = (await _health.GetAllConfigsAsync(ct)).FirstOrDefault(c => c.InterfaceId == interfaceId);
        var iface = (await _firewall.GetInterfacesAsync(ct)).FirstOrDefault(i => i.Id == interfaceId);
        if (iface is null) return NotFound();

        var form = cfg is null
            ? new WanConfigFormViewModel { InterfaceId = interfaceId, InterfaceName = iface.Name }
            : new WanConfigFormViewModel
            {
                InterfaceId       = cfg.InterfaceId,
                InterfaceName     = cfg.InterfaceName,
                Priority          = cfg.Priority,
                MonitorTargets    = cfg.MonitorTargets.Length > 0 ? string.Join(", ", cfg.MonitorTargets) : null,
                ProbeFwmark       = cfg.ProbeFwmark,
                FailoverThreshold = cfg.FailoverThreshold,
                RecoveryThreshold = cfg.RecoveryThreshold,
                Enabled           = cfg.Enabled,
            };
        return PartialView("_WanConfigForm", form);
    }

    [HttpPost("config"), ValidateAntiForgeryToken]
    public async Task<IActionResult> SaveConfig(WanConfigFormViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid)
            return this.ToHtmxResponse(ServiceResponse<bool>.ValidationFailed(CollectErrors()));

        var targets = ParseTargets(form.MonitorTargets);
        await _health.UpsertConfigAsync(new WanHealthConfig
        {
            InterfaceId       = form.InterfaceId,
            Priority          = form.Priority,
            MonitorTargets    = targets,
            ProbeFwmark       = form.ProbeFwmark,
            FailoverThreshold = form.FailoverThreshold,
            RecoveryThreshold = form.RecoveryThreshold,
            Enabled           = form.Enabled,
        }, ct);

        this.AttachHxEvent("refreshWanPanel", new { });
        return this.ToHtmxResponse(ServiceResponse<bool>.Ok(true, $"WAN probe config for {form.InterfaceName} saved."));
    }

    // Manually pin a WAN as active. Destructive (mutates kernel routing) → both
    // a TOTP-elevated Web session AND the daemon's elevated endpoint.
    [HttpPost("swap/{interfaceId:guid}"), ValidateAntiForgeryToken, RequireElevated]
    public async Task<IActionResult> Swap(Guid interfaceId, CancellationToken ct)
    {
        var envelope = await _daemon.ForceWanFailoverAsync(interfaceId, ct);
        if (envelope.Success) this.AttachHxEvent("refreshWanPanel", new { });
        return this.ToHtmxResponse(envelope);
    }

    [HttpPost("clear-override"), ValidateAntiForgeryToken, RequireElevated]
    public async Task<IActionResult> ClearOverride(CancellationToken ct)
    {
        var envelope = await _daemon.ClearWanFailoverOverrideAsync(ct);
        if (envelope.Success) this.AttachHxEvent("refreshWanPanel", new { });
        return this.ToHtmxResponse(envelope);
    }

    // ───────────── helpers ─────────────

    // Split on comma / whitespace / newlines; trim; drop empties.
    private static string[] ParseTargets(string? raw) =>
        string.IsNullOrWhiteSpace(raw)
            ? Array.Empty<string>()
            : raw.Split(new[] { ',', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private Dictionary<string, string[]> CollectErrors() =>
        ModelState.ToDictionary(
            kv => kv.Key,
            kv => kv.Value!.Errors.Select(e => e.ErrorMessage).ToArray());
}
