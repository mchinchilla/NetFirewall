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
///   2. For each peer that SHOULD be live (client-mode tunnel, or a peer with
///      keepalive — same rule as WgPeerHealthEvaluator in the Web), classify the
///      handshake as fresh/stale.
///   3. Apply hysteresis: FailoverThreshold consecutive stale cycles → down;
///      RecoveryThreshold consecutive fresh cycles → back up.
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
        var server = await _wg.GetServerAsync(ct);
        if (server is null || !server.Enabled) return;

        var peers = await _wg.GetPeersAsync(server.Id, ct);
        var live = await _apply.GetStatusAsync(server.Name, ct);
        var liveByKey = live.ToDictionary(s => s.PublicKey);

        var now = DateTime.UtcNow;
        var existing = (await _health.GetStateAsync(ct))
            .Where(s => s.ServerId == server.Id)
            .ToDictionary(s => s.PublicKey);

        // Evaluate every peer that's expected to stay connected. Peers we don't
        // monitor (disabled, or idle inbound with no keepalive) are skipped — a
        // stale handshake there is normal, not an outage.
        foreach (var peer in peers)
        {
            if (!ShouldMonitor(server, peer)) continue;

            liveByKey.TryGetValue(peer.PublicKey, out var liveStatus);
            var handshake = liveStatus?.LastHandshakeAt;
            var fresh = handshake is { } h && (now - h).TotalSeconds < _opts.StaleAfterSeconds;

            await EvaluatePeerAsync(server, peer, liveStatus, fresh, handshake, existing, now, ct);
        }
    }

    private async Task EvaluatePeerAsync(
        WgServer server,
        WgPeer peer,
        WgPeerLiveStatus? liveStatus,
        bool fresh,
        DateTime? handshake,
        Dictionary<string, VpnHealthState> existing,
        DateTime now,
        CancellationToken ct)
    {
        existing.TryGetValue(peer.PublicKey, out var prior);
        var wasUp = prior?.IsUp ?? true;  // optimistic default — only alert on a real flip

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

        if (fresh)
        {
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
        }
        else
        {
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
        }

        await _health.UpsertStateAsync(state, ct);
    }

    private async Task DispatchAsync(WgServer server, WgPeer peer, bool resolved, string? endpoint, CancellationToken ct)
    {
        // One dedupe key per logical condition so the banner upserts a single row
        // and recovery clears it.
        var key = $"vpn:{server.Id}:{peer.PublicKey}";
        var who = server.Mode.Equals("client", StringComparison.OrdinalIgnoreCase)
            ? $"Upstream tunnel \"{server.Name}\""
            : $"WireGuard peer \"{peer.Name}\"";

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

    /// <summary>
    /// Same "should be live" rule as the Web's WgPeerHealthEvaluator: client-mode
    /// tunnels and keepalive peers are expected to stay connected; everything else
    /// is quiet-by-design and not an outage when stale.
    /// </summary>
    private static bool ShouldMonitor(WgServer server, WgPeer peer)
    {
        if (!peer.Enabled) return false;
        var clientMode = server.Mode.Equals("client", StringComparison.OrdinalIgnoreCase);
        var hasKeepalive = peer.PersistentKeepalive is > 0;
        return clientMode || hasKeepalive;
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
