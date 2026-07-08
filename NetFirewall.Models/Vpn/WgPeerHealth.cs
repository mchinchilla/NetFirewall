namespace NetFirewall.Models.Vpn;

/// <summary>
/// Cooked connectivity verdict for a single WireGuard peer. Consumed by the
/// Web's status dot AND the daemon's VpnHealthMonitorService — both call
/// <see cref="WgPeerHealthEvaluator"/> so the live dot and the background
/// "VPN down" alerting can never disagree on what "down" means.
/// </summary>
public enum WgPeerHealth
{
    /// <summary>Fresh handshake — the tunnel is carrying traffic. Green.</summary>
    Connected,

    /// <summary>The peer is expected to stay connected but has never completed a
    /// handshake since we started watching it — a freshly provisioned peer whose
    /// remote side hasn't connected yet, or a config that was never applied.
    /// Not an outage: alerting engages after the first successful handshake.
    /// Amber.</summary>
    Pending,

    /// <summary>The peer is enabled, was alive at some point, and *should* be
    /// live (we dial its endpoint, or it's a site-to-site link) but its handshake
    /// is stale. This is a real outage — e.g. the remote endpoint's IP changed.
    /// Red.</summary>
    Down,

    /// <summary>State we can't call an outage: the peer is disabled, or it's an
    /// inbound road-warrior peer (a laptop that's simply switched off). A stale
    /// handshake here is expected, not a failure. Grey.</summary>
    Idle,
}

/// <summary>
/// Pure (no-IO) helper that classifies a peer's live status into a
/// <see cref="WgPeerHealth"/>. This is the single source of truth for VPN peer
/// health — the Web's status dot and the daemon's alerting monitor both call
/// it. Stateless + deterministic, so it stays a static utility rather than a
/// DI service (pure-function exception to the everything-is-a-service rule).
/// </summary>
public static class WgPeerHealthEvaluator
{
    /// <summary>
    /// A handshake older than this means the peer is not actively connected.
    /// WireGuard renews the handshake roughly every 2 min while traffic flows
    /// (and keepalive keeps it alive when idle), so 3 min is a comfortable
    /// "definitely not talking" threshold with no false negatives.
    /// </summary>
    public static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(3);

    /// <summary>
    /// Whether this peer is expected to stay connected — i.e. a stale handshake
    /// is an outage rather than a laptop that went to sleep. Decided by the
    /// peer's explicit <see cref="WgPeer.Role"/> (migration 00036): 'upstream'
    /// and 'site' links are always-on by definition; 'client' road-warriors may
    /// be offline whenever they like.
    /// Deliberately NOT signals: <c>PersistentKeepalive</c> (the peer form
    /// defaults it to 25 for every road-warrior — it flows into the exported
    /// client config and says nothing about the remote being always-on) and
    /// <c>Endpoint</c> (operators mis-fill it on client peers).
    /// </summary>
    public static bool ExpectedLive(WgPeer? peer)
    {
        if (peer is null || !peer.Enabled) return false;
        return string.Equals(peer.Role, "upstream", StringComparison.OrdinalIgnoreCase)
            || string.Equals(peer.Role, "site", StringComparison.OrdinalIgnoreCase);
    }

    /// <param name="peer">The catalog row, or null when wg reports a pubkey we
    /// have no DB row for (never an outage — we know nothing about it).</param>
    /// <param name="live">Live wg-show stats, or null when the peer isn't on the
    /// interface at all (config not applied / interface down).</param>
    /// <param name="nowUtc">Current time (passed in to keep this pure/testable).</param>
    /// <param name="lastKnownHandshakeAt">Optional persisted memory of the last
    /// handshake ever observed (vpn_health_state). <c>wg</c> resets
    /// latest-handshake to "never" when the interface restarts, so without this
    /// a peer that dies across a restart would look Pending instead of Down.
    /// Callers without persisted state (the Web's per-request dot) omit it.</param>
    /// <param name="staleAfter">Override for <see cref="StaleAfter"/> (the daemon
    /// monitor passes its configured threshold).</param>
    public static WgPeerHealth Evaluate(
        WgPeer? peer,
        WgPeerLiveStatus? live,
        DateTime nowUtc,
        DateTime? lastKnownHandshakeAt = null,
        TimeSpan? staleAfter = null)
    {
        // Latest handshake we have ever seen, from wg itself or persisted state.
        var lastSeen = live?.LastHandshakeAt ?? lastKnownHandshakeAt;

        var fresh = lastSeen is { } h && (nowUtc - h) < (staleAfter ?? StaleAfter);
        if (fresh) return WgPeerHealth.Connected;

        if (!ExpectedLive(peer)) return WgPeerHealth.Idle;

        return lastSeen is null ? WgPeerHealth.Pending : WgPeerHealth.Down;
    }
}
