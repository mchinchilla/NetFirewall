using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Notifications;

namespace NetFirewall.Services.Vpn;

/// <summary>
/// Daemon-side WireGuard health monitor. The live status dot in the Web only
/// changes colour while someone has the page open; this worker is the proactive
/// half — it polls <c>wg show</c> on a timer, decides when a tunnel has actually
/// gone DOWN (with hysteresis so a single missed handshake doesn't cry wolf),
/// records the transition, and fires notifications (UI banner + email).
///
/// Modelled on <c>WanHealthMonitorService</c>:
///   1. Every CheckInterval, read the server + its peers and the live wg dump.
///   2. For each peer that SHOULD be live per <see cref="WgPeerHealthEvaluator"/>
///      (the shared rule the Web's status dot also calls), classify the handshake
///      as Connected / Pending / Down. Peers that leave the monitored set
///      (deleted, disabled, reclassified) are retired: alert resolved, state dropped.
///   3. Apply hysteresis: FailoverThreshold consecutive stale cycles → down;
///      RecoveryThreshold consecutive fresh cycles → back up. Pending (never
///      handshook) counts toward neither — alerting engages after first contact.
///   4. On a transition, persist the event and dispatch a notification.
///
/// We never touch the interface — this is observe-and-alert only, not failover.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class VpnHealthMonitorService : BackgroundService
{
    private readonly IWireGuardService _wg;
    private readonly IWireGuardApplyService _apply;
    private readonly IVpnHealthService _health;
    private readonly INotificationDispatcher _notify;
    private readonly VpnHealthMonitorOptions _opts;
    private readonly ILogger<VpnHealthMonitorService> _logger;

    public VpnHealthMonitorService(
        IWireGuardService wg,
        IWireGuardApplyService apply,
        IVpnHealthService health,
        INotificationDispatcher notify,
        IOptions<VpnHealthMonitorOptions> opts,
        ILogger<VpnHealthMonitorService> logger)
    {
        _wg = wg;
        _apply = apply;
        _health = health;
        _notify = notify;
        _opts = opts.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_opts.Enabled)
        {
            _logger.LogInformation("VPN health monitor disabled by config.");
            return;
        }

        var period = TimeSpan.FromSeconds(Math.Max(15, _opts.CheckIntervalSeconds));
        _logger.LogInformation(
            "VPN health monitor started — every {Sec}s, stale>{Stale}s, down after {Down} cycles, up after {Up}",
            (int)period.TotalSeconds, _opts.StaleAfterSeconds, _opts.FailoverThreshold, _opts.RecoveryThreshold);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await TickAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex, "VPN health probe cycle failed");
            }

            try { await Task.Delay(period, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task TickAsync(CancellationToken ct)
    {
        var states = await _health.GetStateAsync(ct);

        var server = await _wg.GetServerAsync(ct);
        if (server is null || !server.Enabled)
        {
            // Monitoring is off entirely — nothing can ever emit the "up" that
            // would clear a standing alert, so retire everything now instead of
            // leaving banners orphaned.
            foreach (var s in states) await RetireAsync(s.ServerId, s.PublicKey, ct);
            return;
        }

        var peers = await _wg.GetPeersAsync(server.Id, ct);
        var live = await _apply.GetStatusAsync(server.Name, ct);
        var liveByKey = live.ToDictionary(s => s.PublicKey);

        var now = DateTime.UtcNow;
        // Evaluate every peer that's expected to stay connected (we dial its
        // endpoint, or it's a site-to-site link). Quiet inbound road-warriors are
        // skipped — a stale handshake there is a laptop asleep, not an outage.
        var monitored = peers.Where(WgPeerHealthEvaluator.ExpectedLive).ToList();
        var monitoredKeys = monitored.Select(p => p.PublicKey).ToHashSet(StringComparer.Ordinal);

        // Retire state for peers that left the monitored set (deleted, disabled,
        // or reclassified). Their alert would otherwise stand forever: the loop
        // below only evaluates peers still in the set, so nobody ever emits the
        // recovery that clears it.
        var existing = states.Where(s => s.ServerId == server.Id).ToDictionary(s => s.PublicKey);
        foreach (var (key, _) in existing)
        {
            if (monitoredKeys.Contains(key)) continue;
            await RetireAsync(server.Id, key, ct);
        }

        foreach (var peer in monitored)
        {
            liveByKey.TryGetValue(peer.PublicKey, out var liveStatus);
            await EvaluatePeerAsync(server, peer, liveStatus, existing, now, ct);
        }
    }

    /// <summary>
    /// Stop tracking a peer: resolve any standing UI alert (silently — nothing
    /// "recovered", the condition is simply moot) and drop the state row.
    /// </summary>
    private async Task RetireAsync(Guid serverId, string publicKey, CancellationToken ct)
    {
        _logger.LogInformation("VPN peer {Key} no longer monitored — retiring health state and resolving its alert",
            publicKey);
        await _health.ResolveAlertAsync($"vpn:{serverId}:{publicKey}", ct);
        await _health.DeleteStateAsync(serverId, publicKey, ct);
    }

    private async Task EvaluatePeerAsync(
        WgServer server,
        WgPeer peer,
        WgPeerLiveStatus? liveStatus,
        Dictionary<string, VpnHealthState> existing,
        DateTime now,
        CancellationToken ct)
    {
        existing.TryGetValue(peer.PublicKey, out var prior);
        var wasUp = prior?.IsUp ?? true;  // optimistic default — only alert on a real flip

        // wg resets latest-handshake to "never" when the interface restarts, so
        // fold in the persisted memory: without it a peer dying across a restart
        // would look brand-new (Pending) instead of Down, and a healthy peer
        // would false-alarm during the post-restart reconnect window.
        var handshake = liveStatus?.LastHandshakeAt ?? prior?.LastHandshakeAt;

        var verdict = WgPeerHealthEvaluator.Evaluate(
            peer, liveStatus, now,
            lastKnownHandshakeAt: prior?.LastHandshakeAt,
            staleAfter: TimeSpan.FromSeconds(_opts.StaleAfterSeconds));

        var state = new VpnHealthState
        {
            ServerId         = server.Id,
            PublicKey        = peer.PublicKey,
            LastCheckAt      = now,
            LastHandshakeAt  = handshake,
            LastEndpoint     = liveStatus?.Endpoint ?? peer.Endpoint,
            LastTransitionAt = prior?.LastTransitionAt ?? now,
            IsUp             = wasUp,
        };

        switch (verdict)
        {
            case WgPeerHealth.Connected:
                state.ConsecutiveSuccesses = (prior?.ConsecutiveSuccesses ?? 0) + 1;
                state.ConsecutiveFailures  = 0;
                state.IsUp = wasUp || state.ConsecutiveSuccesses >= _opts.RecoveryThreshold;

                if (state.IsUp && !wasUp)
                {
                    state.LastTransitionAt = now;
                    _logger.LogInformation("VPN peer {Peer} on {Iface} RECOVERED", peer.Name, server.Name);
                    await _health.RecordEventAsync(server.Id, peer.PublicKey, "up",
                        JsonSerializer.Serialize(new { endpoint = state.LastEndpoint, handshake }), ct);
                    await DispatchAsync(server, peer, resolved: true, state.LastEndpoint, ct);
                }
                break;

            case WgPeerHealth.Pending:
                // Never handshook since we started watching — a freshly provisioned
                // peer whose remote hasn't connected yet. Not an outage; alerting
                // engages after the first successful handshake. Keep counters at
                // zero so the grace period doesn't accumulate toward a DOWN flip.
                state.ConsecutiveSuccesses = 0;
                state.ConsecutiveFailures  = 0;
                break;

            default: // Down (Idle can't reach here — ExpectedLive filtered the peer list)
                state.ConsecutiveFailures  = (prior?.ConsecutiveFailures ?? 0) + 1;
                state.ConsecutiveSuccesses = 0;
                state.IsUp = wasUp && state.ConsecutiveFailures < _opts.FailoverThreshold;

                if (!state.IsUp && wasUp)
                {
                    state.LastTransitionAt = now;
                    _logger.LogWarning("VPN peer {Peer} on {Iface} went DOWN after {N} stale cycles",
                        peer.Name, server.Name, state.ConsecutiveFailures);
                    await _health.RecordEventAsync(server.Id, peer.PublicKey, "down",
                        JsonSerializer.Serialize(new { endpoint = state.LastEndpoint, lastHandshake = handshake }), ct);
                    await DispatchAsync(server, peer, resolved: false, state.LastEndpoint, ct);
                }
                break;
        }

        await _health.UpsertStateAsync(state, ct);
    }

    private async Task DispatchAsync(WgServer server, WgPeer peer, bool resolved, string? endpoint, CancellationToken ct)
    {
        // One dedupe key per logical condition so the banner upserts a single row
        // and recovery clears it.
        var key = $"vpn:{server.Id}:{peer.PublicKey}";
        var who = peer.Role.ToLowerInvariant() switch
        {
            "upstream" => $"Upstream tunnel \"{peer.Name}\" on {server.Name}",
            "site"     => $"Site-to-site tunnel \"{peer.Name}\"",
            _          => $"WireGuard peer \"{peer.Name}\"",
        };

        var message = resolved
            ? new NotificationMessage(
                Source: "vpn",
                Level: NotificationLevel.Info,
                DedupeKey: key,
                Title: $"{who} recovered",
                Body: $"{who} is handshaking again ({endpoint ?? "no endpoint"}).",
                Resolved: true)
            : new NotificationMessage(
                Source: "vpn",
                Level: NotificationLevel.Danger,
                DedupeKey: key,
                Title: $"{who} is down",
                Body: $"No WireGuard handshake from {who} for over {_opts.StaleAfterSeconds}s "
                      + $"(endpoint {endpoint ?? "unknown"}). The remote may be unreachable or its IP changed.",
                Resolved: false);

        await _notify.DispatchAsync(message, ct);
    }

}

public sealed class VpnHealthMonitorOptions
{
    public const string SectionName = "VpnHealthMonitor";

    public bool Enabled { get; set; } = true;

    /// <summary>How often to poll wg show. Floored at 15s.</summary>
    public int CheckIntervalSeconds { get; set; } = 30;

    /// <summary>Handshake older than this (seconds) counts as a failed cycle. WireGuard
    /// renews ~every 2 min under traffic and keepalive holds it open when idle, so
    /// 180s avoids false positives on a healthy-but-quiet tunnel.</summary>
    public int StaleAfterSeconds { get; set; } = 180;

    /// <summary>Consecutive stale cycles before declaring DOWN (debounce).</summary>
    public int FailoverThreshold { get; set; } = 2;

    /// <summary>Consecutive fresh cycles before declaring recovered.</summary>
    public int RecoveryThreshold { get; set; } = 2;
}
