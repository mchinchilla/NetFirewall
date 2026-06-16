using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using NetFirewall.Models;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Processes;

namespace NetFirewall.Services.WanMonitor;

/// <summary>
/// Manual WAN failover control. Forcing an active WAN does two things, in order:
///   1. Persist a sticky override (so the monitor keeps it active and doesn't
///      immediately fail it back on the next tick by priority).
///   2. Swap the default route in the MAIN table right now — same targeted
///      `ip route replace` the monitor uses, so per-table policy routes
///      (wan1/wan2/wg0) are untouched.
/// Mirrors the automatic path in WanHealthMonitorService.ApplyFailoverAsync but
/// is operator-initiated and records to apply-history as such.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class WanFailoverControlService : IWanFailoverControlService
{
    private readonly IWanHealthService _health;
    private readonly IFirewallService _firewall;
    private readonly IApplyHistoryService _applyHistory;
    private readonly IProcessRunner _runner;
    private readonly ILogger<WanFailoverControlService> _logger;

    public WanFailoverControlService(
        IWanHealthService health,
        IFirewallService firewall,
        IApplyHistoryService applyHistory,
        IProcessRunner runner,
        ILogger<WanFailoverControlService> logger)
    {
        _health = health;
        _firewall = firewall;
        _applyHistory = applyHistory;
        _runner = runner;
        _logger = logger;
    }

    public async Task<ServiceResponse<bool>> ForceActiveAsync(Guid interfaceId, string? setBy, CancellationToken ct = default)
    {
        var iface = (await _firewall.GetInterfacesAsync(ct)).FirstOrDefault(i => i.Id == interfaceId);
        if (iface is null)
            return ServiceResponse<bool>.Fail("That interface no longer exists.");
        if (iface.Gateway is null)
            return ServiceResponse<bool>.Fail($"{iface.Name} has no gateway configured — can't make it the default route.");

        // Pin first, so even if the route swap is slow the monitor won't race us
        // and pick a different winner on its next tick.
        await _health.SetOverrideAsync(interfaceId, setBy, ct);

        var cmd = $"route replace default via {iface.Gateway} dev {iface.Name}";
        var result = await _runner.RunAsync("ip", cmd, TimeSpan.FromSeconds(5), ct);
        var ok = result.Success;
        var msg = ok
            ? $"Active WAN switched to {iface.Name} (via {iface.Gateway}) and pinned."
            : $"Failed to switch default route to {iface.Name}: {result.Error}";

        if (ok)
        {
            await _health.SetActiveAsync(interfaceId, ct);
            await _health.RecordEventAsync(interfaceId, "failover",
                $"{{\"manual\":true,\"by\":\"{setBy}\",\"gateway\":\"{iface.Gateway}\"}}", ct);
            _logger.LogWarning("Manual WAN failover → {Name} by {By}", iface.Name, setBy ?? "?");
        }
        else
        {
            // Route swap failed — don't leave a pin that points nowhere useful.
            await _health.SetOverrideAsync(null, "auto (manual swap failed)", ct);
            _logger.LogError("Manual WAN failover FAILED → {Name}: {Err}", iface.Name, result.Error);
        }

        await _applyHistory.RecordAsync("failover", ok, result.ExitCode, msg, setBy, ct);
        return ok ? ServiceResponse<bool>.Ok(true, msg) : ServiceResponse<bool>.Fail(msg);
    }

    public async Task<ServiceResponse<bool>> ClearOverrideAsync(string? setBy, CancellationToken ct = default)
    {
        await _health.SetOverrideAsync(null, setBy, ct);
        _logger.LogInformation("WAN failover override cleared by {By} — back to automatic priority selection.", setBy ?? "?");
        return ServiceResponse<bool>.Ok(true, "Override cleared — automatic priority-based failover is active.");
    }
}
