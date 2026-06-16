using System.Globalization;
using System.Net;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.WanMonitor;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Notifications;
using NetFirewall.Services.Processes;
using Npgsql;

namespace NetFirewall.Services.WanMonitor;

/// <summary>
/// Daemon-side replacement for the standalone NetFirewall.WanMonitor process.
/// One loop, owns the entire failover lifecycle:
///
///   1. Every <c>CheckInterval</c> seconds, ping each configured WAN target.
///      Targets default to the interface's gateway when no explicit list.
///   2. Apply hysteresis: <c>FailoverThreshold</c> consecutive failures flip
///      a WAN to down; <c>RecoveryThreshold</c> consecutive successes flip
///      it back up.
///   3. After every transition, recompute the active WAN: lowest-priority
///      healthy interface wins. If that changed, swap the default route in
///      the main table to that WAN's gateway (one targeted <c>ip route
///      replace</c>) and record a failover event.
///   4. Persist state + event rows for the dashboard.
///
/// We don't touch ip rule / fw_static_routes — those live in DB and are
/// applied by IPolicyRoutingApplyService. Failover is a runtime decision
/// layered on top of the static config.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed partial class WanHealthMonitorService : BackgroundService
{
    private readonly NpgsqlDataSource _ds;
    private readonly IWanHealthService _health;
    private readonly IFirewallService _firewall;
    private readonly IApplyHistoryService _applyHistory;
    private readonly INotificationDispatcher _notify;
    private readonly NetFirewall.Services.Vpn.IVpnHealthService _alerts;
    private readonly IProcessRunner _runner;
    private readonly WanHealthMonitorOptions _opts;
    private readonly ILogger<WanHealthMonitorService> _logger;

    // Tracks who is currently the active default WAN, so we only swap the
    // route when the verdict actually changes.
    private Guid? _activeInterfaceId;

    public WanHealthMonitorService(
        NpgsqlDataSource ds,
        IWanHealthService health,
        IFirewallService firewall,
        IApplyHistoryService applyHistory,
        INotificationDispatcher notify,
        // The system_alerts store happens to live on IVpnHealthService (it's a
        // cross-subsystem table). Used here for the LEVEL-triggered banner
        // reconcile — re-raising/resolving the alert row to match the current
        // verdict — without going through the email-fanning dispatcher.
        NetFirewall.Services.Vpn.IVpnHealthService alerts,
        IProcessRunner runner,
        IOptions<WanHealthMonitorOptions> opts,
        ILogger<WanHealthMonitorService> logger)
    {
        _ds = ds;
        _health = health;
        _firewall = firewall;
        _applyHistory = applyHistory;
        _notify = notify;
        _alerts = alerts;
        _runner = runner;
        _opts = opts.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_opts.Enabled)
        {
            _logger.LogInformation("WAN health monitor disabled by config.");
            return;
        }

        var period = TimeSpan.FromSeconds(Math.Max(5, _opts.CheckIntervalSeconds));
        _logger.LogInformation("WAN health monitor started — every {Sec}s, default-on-startup={Iface}",
            (int)period.TotalSeconds, _opts.DefaultActiveInterface ?? "auto");

        // First cycle: prime the active WAN from whatever has a default
        // route in main right now, or fall back to lowest priority enabled.
        await PrimeActiveWanAsync(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await TickAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex, "WAN health probe cycle failed");
            }

            try { await Task.Delay(period, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task PrimeActiveWanAsync(CancellationToken ct)
    {
        // Read the existing default route in the main table. Whichever device
        // it points to is the WAN we treat as "currently active" — failovers
        // happen relative to this baseline.
        try
        {
            var result = await _runner.RunAsync("ip", "-o route show default", TimeSpan.FromSeconds(3), ct);
            if (result.Success)
            {
                var m = DevRx().Match(result.Output);
                if (m.Success)
                {
                    var devName = m.Groups[1].Value;
                    var ifaces = await _firewall.GetInterfacesAsync(ct);
                    var match = ifaces.FirstOrDefault(i => i.Name == devName);
                    if (match is not null)
                    {
                        _activeInterfaceId = match.Id;
                        _logger.LogInformation("WAN monitor primed: active default = {Name}", devName);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not prime active WAN from kernel — will pick lazily");
        }
    }

    private async Task TickAsync(CancellationToken ct)
    {
        var configs = await _health.GetConfigsAsync(ct);
        if (configs.Count == 0) return;

        var interfaces = await _firewall.GetInterfacesAsync(ct);
        var byId = interfaces.ToDictionary(i => i.Id);

        // Probe every configured WAN in parallel — each one is bounded by its
        // own ping timeout. Avoids serial latency when there are 2+ WANs.
        var existingState = (await _health.GetStateAsync(ct)).ToDictionary(s => s.InterfaceId);
        var probeTasks = configs.Select(c => ProbeOneAsync(c, byId, existingState, ct)).ToArray();
        var results = await Task.WhenAll(probeTasks);

        // Resolve active WAN: lowest priority among IsUp=true. If none up,
        // we keep the last active one (better to point at a dead WAN than
        // to remove the default route entirely — the dead one might recover
        // fast and the kernel won't have to renegotiate ARP).
        var healthy = configs
            .Where(c => results.First(r => r.InterfaceId == c.InterfaceId).IsUp)
            .OrderBy(c => c.Priority)
            .ToList();

        if (healthy.Count == 0)
        {
            _logger.LogWarning("All WAN interfaces failing — keeping current active route.");
            return;
        }

        // Sticky manual override: if the operator pinned a WAN and it's still
        // healthy, it wins regardless of priority. If the pinned WAN is now
        // down, auto-clear the override and fall back to priority selection —
        // the whole point of failover is to not strand the operator on a dead
        // pin.
        var control = await _health.GetControlAsync(ct);
        var winner = healthy[0];
        if (control.OverrideInterfaceId is { } pinned)
        {
            var pinnedHealthy = healthy.FirstOrDefault(c => c.InterfaceId == pinned);
            if (pinnedHealthy is not null)
            {
                winner = pinnedHealthy;
            }
            else
            {
                _logger.LogWarning("Pinned WAN {Id} is down — clearing override and failing over by priority.", pinned);
                await _health.SetOverrideAsync(null, "auto (pinned WAN down)", ct);
                if (byId.TryGetValue(pinned, out var pinnedIface))
                {
                    await _notify.DispatchAsync(new NotificationMessage(
                        Source: "wan",
                        Level: NotificationLevel.Warning,
                        DedupeKey: $"wan:override-cleared:{pinned}:{DateTime.UtcNow:O}",
                        Title: "WAN override cleared",
                        Body: $"The pinned WAN {pinnedIface.Name} went down; reverting to automatic "
                              + $"priority-based failover ({winner.InterfaceName} is next).",
                        Resolved: false), ct);
                }
            }
        }

        if (_activeInterfaceId != winner.InterfaceId)
        {
            await ApplyFailoverAsync(winner, byId, ct);
            _activeInterfaceId = winner.InterfaceId;
        }

        // Persist the active WAN so the dashboard can show it and it survives a
        // daemon restart (SetActiveAsync only bumps active_since on a real change).
        await _health.SetActiveAsync(winner.InterfaceId, ct);
    }

    private async Task<WanHealthState> ProbeOneAsync(
        WanHealthConfig cfg,
        Dictionary<Guid, FwInterface> byId,
        Dictionary<Guid, WanHealthState> existing,
        CancellationToken ct)
    {
        if (!byId.TryGetValue(cfg.InterfaceId, out var iface))
        {
            return new WanHealthState { InterfaceId = cfg.InterfaceId, IsUp = false, LastError = "interface missing" };
        }

        var targets = cfg.MonitorTargets.Length > 0
            ? cfg.MonitorTargets
            : (iface.Gateway is null ? Array.Empty<string>() : new[] { iface.Gateway.ToString() });

        if (targets.Length == 0)
        {
            return new WanHealthState { InterfaceId = cfg.InterfaceId, IsUp = false, LastError = "no targets" };
        }

        // Probe all targets in parallel; ANY success = up. When ProbeFwmark
        // is set, the daemon issues `ping -m <fwmark>` so the kernel's policy
        // routing pins egress to the correct WAN even when `-I` alone loses
        // to the main table's default route.
        var pingTasks = targets.Select(t => PingAsync(iface.Name, t, cfg.ProbeFwmark, ct)).ToArray();
        var pingResults = await Task.WhenAll(pingTasks);
        var anyUp = pingResults.Any(p => p.Success);
        var bestRtt = pingResults.Where(p => p.Success && p.RttMs is not null).Select(p => p.RttMs!.Value).DefaultIfEmpty().Min();
        var firstError = pingResults.FirstOrDefault(p => !p.Success).Error;
        var probedTarget = pingResults.FirstOrDefault(p => p.Success).Target ?? targets[0];

        // Apply hysteresis.
        existing.TryGetValue(cfg.InterfaceId, out var prior);
        var newState = new WanHealthState
        {
            InterfaceId   = cfg.InterfaceId,
            InterfaceName = iface.Name,
            Role          = iface.Role ?? string.Empty,
            LastCheckAt   = DateTime.UtcNow,
            LastRttMs     = bestRtt > 0 ? bestRtt : null,
            LastTarget    = probedTarget,
            LastError     = anyUp ? null : firstError,
            LastTransitionAt = prior?.LastTransitionAt ?? DateTime.UtcNow,
        };

        var wasUp = prior?.IsUp ?? true;

        // Was this WAN in a bad state before this cycle? Reachability proxy from
        // the persisted row: not-up, or accumulating failures. Drives the
        // recovery edge so "recovered" notifies even across a daemon restart.
        var wasBad = prior is not null && (!prior.IsUp || prior.ConsecutiveFailures > 0);

        if (anyUp)
        {
            newState.ConsecutiveSuccesses = (prior?.ConsecutiveSuccesses ?? 0) + 1;
            newState.ConsecutiveFailures = 0;
            newState.IsUp = wasUp || newState.ConsecutiveSuccesses >= cfg.RecoveryThreshold;
            // Log the cooked recovery edge for the failover timeline (this is
            // about routing, so it follows hysteresis, not raw reachability).
            if (newState.IsUp && !wasUp)
            {
                newState.LastTransitionAt = DateTime.UtcNow;
                _logger.LogInformation("WAN {Name} recovered after {N} successes", iface.Name, newState.ConsecutiveSuccesses);
                await _health.RecordEventAsync(cfg.InterfaceId, "up",
                    JsonSerializer.Serialize(new { rtt = bestRtt, target = probedTarget }), ct);
            }
        }
        else
        {
            newState.ConsecutiveFailures = (prior?.ConsecutiveFailures ?? 0) + 1;
            newState.ConsecutiveSuccesses = 0;
            newState.IsUp = wasUp && newState.ConsecutiveFailures < cfg.FailoverThreshold;
            if (!newState.IsUp && wasUp)
            {
                newState.LastTransitionAt = DateTime.UtcNow;
                _logger.LogWarning("WAN {Name} flapped DOWN after {N} consecutive failures", iface.Name, newState.ConsecutiveFailures);
                await _health.RecordEventAsync(cfg.InterfaceId, "down",
                    JsonSerializer.Serialize(new { error = firstError, target = probedTarget }), ct);
            }
        }

        await _health.UpsertStateAsync(newState, ct);

        // Single owner of the down↔recovery alert pair, keyed off RAW
        // reachability (anyUp) — not the hysteresis-cooked IsUp. This is what
        // makes BOTH directions robust across a daemon restart/deploy: the down
        // banner appears for a WAN that was already down (no down→up edge to
        // catch), AND the recovery notification fires for a WAN that comes back
        // (no up-edge needed — we compare against the persisted bad state).
        //
        //   reachable + was bad  → resolve banner + dispatch "recovered" (email)
        //   reachable + was ok   → nothing (steady state)
        //   unreachable + was ok → raise banner + dispatch "is down" (email)
        //   unreachable + was bad → refresh banner (idempotent, no new email)
        //
        // Routing/failover still follows the cooked IsUp above; this only drives
        // operator-facing alerts, which should track real connectivity.
        await ReconcileAlertAsync(iface, anyUp, wasBad, newState.ConsecutiveFailures, probedTarget, firstError, ct);

        return newState;
    }

    private async Task ReconcileAlertAsync(
        FwInterface iface, bool reachable, bool wasBad, int consecutiveFailures,
        string target, string? error, CancellationToken ct)
    {
        var key = DownAlertKey(iface.Id);
        if (reachable)
        {
            // Banner clears the moment traffic returns.
            await _alerts.ResolveAlertAsync(key, ct);
            // Recovery EDGE: only when it was actually bad before. Fires the
            // all-clear email AND records a "recovered" entry for the dropdown /
            // history. It's a point-in-time event (like a failover), so we raise
            // it then immediately resolve it: it shows in the notifications feed
            // (which lists active + resolved) but never sticks as a red top
            // banner (that one filters to active-only).
            if (wasBad)
            {
                var recoveredKey = $"wan:recovered:{iface.Id}:{DateTime.UtcNow:O}";
                await _notify.DispatchAsync(new NotificationMessage(
                    Source: "wan",
                    Level: NotificationLevel.Info,
                    DedupeKey: recoveredKey,
                    Title: $"WAN {iface.Name} recovered",
                    Body: $"{iface.Name} is responding again ({target}).",
                    Resolved: false), ct);
                await _alerts.ResolveAlertAsync(recoveredKey, ct);
            }
        }
        else
        {
            // Down EDGE: dispatch (email) only on the transition into bad;
            // afterwards just refresh the banner row idempotently.
            if (!wasBad)
            {
                await _notify.DispatchAsync(new NotificationMessage(
                    Source: "wan",
                    Level: NotificationLevel.Danger,
                    DedupeKey: key,
                    Title: $"WAN {iface.Name} is down",
                    Body: DownBody(iface.Name, consecutiveFailures, target, error),
                    Resolved: false), ct);
            }
            else
            {
                await _alerts.RaiseAlertAsync(new NetFirewall.Models.Vpn.SystemAlert
                {
                    Source    = "wan",
                    Severity  = "danger",
                    DedupeKey = key,
                    Title     = $"WAN {iface.Name} is down",
                    Body      = DownBody(iface.Name, consecutiveFailures, target, error),
                });
            }
        }
    }

    private static string DownBody(string name, int failures, string target, string? error)
    {
        // failures is 0 only in odd races; phrase it gracefully either way.
        var probeCount = failures > 0 ? $"after {failures} failed probe{(failures == 1 ? "" : "s")}" : "on the latest probe";
        return $"No reply from {target} {probeCount} ({error ?? "no detail"}). "
               + "Failover to a healthy WAN will follow if one is available.";
    }

    private readonly record struct PingOutcome(bool Success, double? RttMs, string Target, string? Error);

    private async Task<PingOutcome> PingAsync(string iface, string target, long? fwmark, CancellationToken ct)
    {
        try
        {
            // When fwmark is supplied, route by mark (via `ip rule fwmark X
            // lookup wanN`). This is the only reliable way to force egress
            // through a specific WAN when the policy is fwmark-based. When
            // null, fall back to `-I iface` which works for L2-adjacent
            // targets like the local gateway.
            var args = fwmark is { } fm
                ? $"-c 1 -W 2 -m {fm} {target}"
                : $"-c 1 -W 2 -I {iface} {target}";

            var result = await _runner.RunAsync("ping", args, TimeSpan.FromSeconds(3), ct);
            if (!result.Success)
                return new PingOutcome(false, null, target, "no reply within 2s");
            var m = TimeRx().Match(result.Output);
            double? rtt = m.Success && double.TryParse(m.Groups[1].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var ms) ? ms : null;
            return new PingOutcome(true, rtt, target, null);
        }
        catch (Exception ex)
        {
            return new PingOutcome(false, null, target, ex.Message);
        }
    }

    private async Task ApplyFailoverAsync(WanHealthConfig winner, Dictionary<Guid, FwInterface> byId, CancellationToken ct)
    {
        if (!byId.TryGetValue(winner.InterfaceId, out var iface) || iface.Gateway is null)
        {
            _logger.LogWarning("Failover winner {Name} has no gateway — skipping route swap", winner.InterfaceName);
            return;
        }

        // Targeted route swap: replace the default route in the MAIN table.
        // Per-table policy routes (wan1/wan2/wg0) are NOT touched — they stay
        // pinned to their owning interface and rely on fwmark for selection.
        var cmd = $"route replace default via {iface.Gateway} dev {iface.Name}";
        var result = await _runner.RunAsync("ip", cmd, TimeSpan.FromSeconds(5), ct);

        var ok = result.Success;
        var msg = ok
            ? $"Default route switched to {iface.Name} (via {iface.Gateway})"
            : $"Failover ip route replace failed: {result.Error}";

        if (ok)
            _logger.LogWarning("WAN failover → {Name} via {Gw}", iface.Name, iface.Gateway);
        else
            _logger.LogError("WAN failover FAILED → {Name}: {Err}", iface.Name, result.Error);

        await _health.RecordEventAsync(winner.InterfaceId, "failover",
            JsonSerializer.Serialize(new { gateway = iface.Gateway.ToString(), success = ok, error = result.Error }), ct);

        // Demote whoever was active before (for the dashboard timeline).
        var fromName = "(none)";
        if (_activeInterfaceId is { } prev && prev != winner.InterfaceId)
        {
            if (byId.TryGetValue(prev, out var prevIface)) fromName = prevIface.Name;
            await _health.RecordEventAsync(prev, "demoted",
                JsonSerializer.Serialize(new { reason = $"replaced by {iface.Name}" }), ct);
        }

        await _applyHistory.RecordAsync("failover", ok, result.ExitCode, msg, "wan-monitor", ct);

        // Notify the operator the active WAN changed. Unique dedupe key per
        // event (it's a point-in-time notice, not a sticky condition that
        // recovers). Warning on success, Danger if the route swap itself failed.
        await _notify.DispatchAsync(new NotificationMessage(
            Source: "wan",
            Level: ok ? NotificationLevel.Warning : NotificationLevel.Danger,
            DedupeKey: $"wan:failover:{winner.InterfaceId}:{result.ExitCode}:{(ok ? "ok" : "fail")}:{DateTime.UtcNow:O}",
            Title: ok ? "WAN failover triggered" : "WAN failover FAILED",
            Body: ok
                ? $"Default route switched from {fromName} to {iface.Name} (via {iface.Gateway})."
                : $"Tried to switch the default route to {iface.Name} but it failed: {result.Error}. "
                  + "Traffic may be blackholed — check connectivity.",
            Resolved: false), ct);
    }

    // One dedupe key per interface for the down↔recovery pair, so a recovery
    // upserts/clears the same banner row a "down" raised.
    private static string DownAlertKey(Guid interfaceId) => $"wan:down:{interfaceId}";

    [GeneratedRegex(@"time=([\d.]+)\s*ms", RegexOptions.IgnoreCase)] private static partial Regex TimeRx();
    [GeneratedRegex(@"\bdev\s+(\S+)")]                                 private static partial Regex DevRx();
}

public sealed class WanHealthMonitorOptions
{
    public const string SectionName = "WanHealthMonitor";

    public bool Enabled { get; set; } = true;

    /// <summary>How often to probe. 30s is the legacy WanMonitor default.</summary>
    public int CheckIntervalSeconds { get; set; } = 30;

    /// <summary>Optional hint for which interface to consider active at startup if the kernel state is ambiguous.</summary>
    public string? DefaultActiveInterface { get; set; }
}
