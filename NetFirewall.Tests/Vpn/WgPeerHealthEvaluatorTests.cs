using NetFirewall.Models.Vpn;
using Xunit;

namespace NetFirewall.Tests.Vpn;

/// <summary>
/// Pure-function coverage of <see cref="WgPeerHealthEvaluator"/> — the single
/// health rule shared by the Web's status dot and the daemon's
/// VpnHealthMonitorService. The regressions these pin down: only explicit
/// 'upstream'/'site' roles are monitored (a road-warrior client must never read
/// as an outage, no matter what keepalive or endpoint got filled into its row),
/// and a peer that has never handshaked is Pending, not Down.
/// </summary>
public class WgPeerHealthEvaluatorTests
{
    private static readonly DateTime Now = new(2026, 7, 7, 12, 0, 0, DateTimeKind.Utc);

    private static WgPeer Peer(
        string role = "client",
        bool enabled = true,
        string? endpoint = null,
        int? keepalive = null) => new()
    {
        Id = Guid.NewGuid(),
        ServerId = Guid.NewGuid(),
        Name = "peer",
        PublicKey = "PUBKEY",
        Role = role,
        Enabled = enabled,
        Endpoint = endpoint,
        PersistentKeepalive = keepalive,
    };

    private static WgPeerLiveStatus Live(DateTime? handshake) =>
        new("PUBKEY", "203.0.113.7:51820", handshake, 100, 100);

    // ── ExpectedLive: who is monitored at all ──

    [Fact]
    public void ExpectedLive_UpstreamRole_IsMonitored() =>
        Assert.True(WgPeerHealthEvaluator.ExpectedLive(Peer(role: "upstream", endpoint: "vps.example.com:51821")));

    [Fact]
    public void ExpectedLive_SiteRole_IsMonitored() =>
        Assert.True(WgPeerHealthEvaluator.ExpectedLive(Peer(role: "site")));

    [Fact]
    public void ExpectedLive_ClientRole_IsNotMonitored_EvenWithKeepaliveAndEndpoint()
    {
        // The peer form defaults keepalive to 25 for every road-warrior, and
        // operators have mis-filled Endpoint on client rows — neither may drag a
        // client into monitoring. Only the explicit role decides.
        Assert.False(WgPeerHealthEvaluator.ExpectedLive(
            Peer(role: "client", endpoint: "fw.example.net:51820", keepalive: 25)));
    }

    [Fact]
    public void ExpectedLive_DisabledPeer_IsNotMonitored() =>
        Assert.False(WgPeerHealthEvaluator.ExpectedLive(Peer(role: "upstream", enabled: false)));

    [Fact]
    public void ExpectedLive_NullPeer_IsNotMonitored() =>
        Assert.False(WgPeerHealthEvaluator.ExpectedLive(null));

    // ── Evaluate: verdicts ──

    [Fact]
    public void FreshHandshake_IsConnected_RegardlessOfRole()
    {
        var live = Live(Now.AddSeconds(-30));
        Assert.Equal(WgPeerHealth.Connected,
            WgPeerHealthEvaluator.Evaluate(Peer(role: "client"), live, Now));
        Assert.Equal(WgPeerHealth.Connected,
            WgPeerHealthEvaluator.Evaluate(Peer(role: "upstream"), live, Now));
    }

    [Fact]
    public void StaleUpstream_IsDown()
    {
        var live = Live(Now.AddMinutes(-10));
        Assert.Equal(WgPeerHealth.Down,
            WgPeerHealthEvaluator.Evaluate(Peer(role: "upstream"), live, Now));
    }

    [Fact]
    public void StaleSiteToSite_IsDown()
    {
        var live = Live(Now.AddMinutes(-10));
        Assert.Equal(WgPeerHealth.Down,
            WgPeerHealthEvaluator.Evaluate(Peer(role: "site"), live, Now));
    }

    [Fact]
    public void StaleClient_IsIdle_NotDown()
    {
        // A laptop that went to sleep — keepalive default notwithstanding.
        var live = Live(Now.AddHours(-3));
        Assert.Equal(WgPeerHealth.Idle,
            WgPeerHealthEvaluator.Evaluate(Peer(role: "client", keepalive: 25), live, Now));
    }

    [Fact]
    public void NeverHandshakedUpstream_IsPending_NotDown()
    {
        // Freshly provisioned tunnel whose remote hasn't connected yet: the exact
        // scenario that used to raise a permanent "tunnel down" banner.
        Assert.Equal(WgPeerHealth.Pending,
            WgPeerHealthEvaluator.Evaluate(Peer(role: "upstream"), Live(null), Now));
    }

    [Fact]
    public void NeverHandshakedAndNotOnInterface_IsPending()
    {
        // Peer exists in the catalog but the config was never applied (live == null).
        Assert.Equal(WgPeerHealth.Pending,
            WgPeerHealthEvaluator.Evaluate(Peer(role: "upstream"), null, Now));
    }

    [Fact]
    public void UnknownPubkeyOnInterface_IsIdle()
    {
        // wg reports a peer we have no DB row for — we know nothing, never an outage.
        Assert.Equal(WgPeerHealth.Idle,
            WgPeerHealthEvaluator.Evaluate(null, Live(Now.AddHours(-1)), Now));
    }

    [Fact]
    public void DisabledPeer_IsIdle_EvenWhenStale()
    {
        Assert.Equal(WgPeerHealth.Idle,
            WgPeerHealthEvaluator.Evaluate(Peer(role: "upstream", enabled: false),
                Live(Now.AddHours(-1)), Now));
    }

    // ── Persisted-memory semantics (wg resets latest-handshake on restart) ──

    [Fact]
    public void RecentMemory_BridgesInterfaceRestart_AsConnected()
    {
        // Interface just restarted: wg says "never handshaked", but we saw a
        // handshake 1 min ago. Grace, not a false alarm.
        Assert.Equal(WgPeerHealth.Connected,
            WgPeerHealthEvaluator.Evaluate(Peer(role: "upstream"), Live(null), Now,
                lastKnownHandshakeAt: Now.AddMinutes(-1)));
    }

    [Fact]
    public void StaleMemory_AfterRestart_IsDown_NotPending()
    {
        // The peer WAS alive once (persisted state remembers), so a missing
        // handshake after a restart is an outage, not a brand-new peer.
        Assert.Equal(WgPeerHealth.Down,
            WgPeerHealthEvaluator.Evaluate(Peer(role: "upstream"), Live(null), Now,
                lastKnownHandshakeAt: Now.AddHours(-2)));
    }

    [Fact]
    public void ConfigurableStaleThreshold_IsHonored()
    {
        var live = Live(Now.AddSeconds(-120));
        // 120s-old handshake: fresh under the default 180s...
        Assert.Equal(WgPeerHealth.Connected,
            WgPeerHealthEvaluator.Evaluate(Peer(role: "upstream"), live, Now));
        // ...but stale under a tightened 60s threshold.
        Assert.Equal(WgPeerHealth.Down,
            WgPeerHealthEvaluator.Evaluate(Peer(role: "upstream"), live, Now,
                staleAfter: TimeSpan.FromSeconds(60)));
    }
}
