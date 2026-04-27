using System.Net;
using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// Real-Postgres coverage for the slices of <see cref="FailoverService"/> that
/// don't require a live TCP peer: state-machine, load-balancing decisions
/// (split-by-MAC), config loading, partner-down forcing, and pool stats SQL.
///
/// The TCP protocol layer (Connect/BndUpd/State messages) is integration-test
/// territory and is intentionally not covered here.
/// </summary>
[Collection("Postgres")]
public sealed class FailoverServiceTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private FailoverService _svc = null!;

    public FailoverServiceTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _svc = new FailoverService(_pg.DataSource, NullLogger<FailoverService>.Instance);
    }

    public Task DisposeAsync()
    {
        _svc.Dispose();
        return Task.CompletedTask;
    }

    /// <summary>
    /// Bypass the TCP-connecting <c>StartAsync</c> by setting <c>_peerConfig</c>
    /// directly via reflection. Lets us probe state-machine semantics without
    /// spinning up a peer.
    /// </summary>
    private void SetPeerConfig(FailoverPeer cfg) =>
        typeof(FailoverService)
            .GetField("_peerConfig", BindingFlags.NonPublic | BindingFlags.Instance)!
            .SetValue(_svc, cfg);

    private async Task SeedPeerAsync(string role = "primary", string peerAddr = "10.0.0.2",
        bool enabled = true, int split = 128)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(@"
            INSERT INTO dhcp_failover_peers (id, name, role, peer_address, split, enabled)
            VALUES (gen_random_uuid(), 'test-peer', @role, @addr, @split, @enabled)", conn);
        cmd.Parameters.AddWithValue("role", role);
        cmd.Parameters.AddWithValue("addr", IPAddress.Parse(peerAddr));
        cmd.Parameters.AddWithValue("split", split);
        cmd.Parameters.AddWithValue("enabled", enabled);
        await cmd.ExecuteNonQueryAsync();
    }

    // ── No peer config: permissive defaults ────────────────────────────

    [Fact]
    public void NoPeerConfig_IsEnabledFalse_AndShouldHandleEverything()
    {
        Assert.False(_svc.IsEnabled);
        // CanServe depends on state — Startup is the default and is NOT in CanServe.
        Assert.False(_svc.CanServe);
        // Without a peer config, the server handles all requests itself.
        Assert.True(_svc.ShouldHandleRequest("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.10")));
    }

    // ── StartAsync with disabled config: early return, no connection attempt ──

    [Fact]
    public async Task StartAsync_WhenPeerDisabled_LeavesIsEnabledFalse_NoCrash()
    {
        await SeedPeerAsync(enabled: false);

        await _svc.StartAsync();

        Assert.False(_svc.IsEnabled);
        Assert.Null(_svc.GetPeerConfig()); // disabled config never gets stored
    }

    // ── State-machine transitions ──────────────────────────────────────

    [Fact]
    public async Task TransitionToStateAsync_ChangesState_AndFiresEvent()
    {
        FailoverState? observedOld = null, observedNew = null;
        _svc.StateChanged += (_, e) => { observedOld = e.OldState; observedNew = e.NewState; };

        await _svc.TransitionToStateAsync(FailoverState.Normal);

        Assert.Equal(FailoverState.Normal, _svc.CurrentState);
        Assert.Equal(FailoverState.Startup, observedOld);
        Assert.Equal(FailoverState.Normal, observedNew);
    }

    [Fact]
    public async Task TransitionToStateAsync_SameState_DoesNotFireEvent()
    {
        await _svc.TransitionToStateAsync(FailoverState.Normal);

        var fired = 0;
        _svc.StateChanged += (_, _) => fired++;

        await _svc.TransitionToStateAsync(FailoverState.Normal);

        Assert.Equal(0, fired);
    }

    [Fact]
    public async Task ForcePartnerDownAsync_TransitionsToPartnerDown()
    {
        await _svc.ForcePartnerDownAsync();
        Assert.Equal(FailoverState.PartnerDown, _svc.CurrentState);
    }

    // ── CanServe per state ─────────────────────────────────────────────

    [Theory]
    [InlineData(FailoverState.Normal, true)]
    [InlineData(FailoverState.PartnerDown, true)]
    [InlineData(FailoverState.CommunicationsInterrupted, true)]
    [InlineData(FailoverState.Startup, false)]
    [InlineData(FailoverState.Recover, false)]
    [InlineData(FailoverState.Paused, false)]
    [InlineData(FailoverState.Shutdown, false)]
    public async Task CanServe_OnlyTrueInOperationalStates(FailoverState s, bool expected)
    {
        await _svc.TransitionToStateAsync(s);
        Assert.Equal(expected, _svc.CanServe);
    }

    // ── ShouldHandleRequest with peer config (load balancing) ──────────

    [Fact]
    public void ShouldHandleRequest_PartnerDownState_HandlesAllRegardlessOfHash()
    {
        SetPeerConfig(new FailoverPeer
        {
            Enabled = true, Role = "primary", Split = 128,
            PeerAddress = IPAddress.Parse("10.0.0.2")
        });
        // Force PartnerDown without going through StartAsync's TCP setup.
        typeof(FailoverService).GetProperty("CurrentState")!
            .SetValue(_svc, FailoverState.PartnerDown);

        Assert.True(_svc.ShouldHandleRequest("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.10")));
        Assert.True(_svc.ShouldHandleRequest("ff:ff:ff:ff:ff:ff", IPAddress.Parse("10.0.0.250")));
    }

    [Fact]
    public async Task ShouldHandleRequest_NormalState_AndSecondaryFlipsForSameMac()
    {
        // Contract test (no statistical claims): the same MAC, processed by
        // the primary vs the secondary, must give complementary answers — the
        // load-balancing split is by definition a partition.
        var primary = new FailoverService(_pg.DataSource, NullLogger<FailoverService>.Instance);
        var secondary = new FailoverService(_pg.DataSource, NullLogger<FailoverService>.Instance);
        try
        {
            SetPeerConfigOn(primary, new FailoverPeer
            {
                Enabled = true, Role = "primary", Split = 128,
                PeerAddress = IPAddress.Parse("10.0.0.2")
            });
            SetPeerConfigOn(secondary, new FailoverPeer
            {
                Enabled = true, Role = "secondary", Split = 128,
                PeerAddress = IPAddress.Parse("10.0.0.2")
            });
            await primary.TransitionToStateAsync(FailoverState.Normal);
            await secondary.TransitionToStateAsync(FailoverState.Normal);

            // Try a handful of distinct MACs; for each, exactly one peer must own it.
            var pairs = new[]
            {
                "aa:bb:cc:01:02:03",
                "11:22:33:44:55:66",
                "de:ad:be:ef:00:01",
                "f0:0d:ca:fe:00:42",
                "00:01:02:03:04:05"
            };
            foreach (var mac in pairs)
            {
                var p = primary.ShouldHandleRequest(mac, IPAddress.Parse("10.0.0.10"));
                var s = secondary.ShouldHandleRequest(mac, IPAddress.Parse("10.0.0.10"));
                Assert.True(p ^ s, $"MAC {mac}: primary={p}, secondary={s} — must be exactly one owner");
            }
        }
        finally
        {
            primary.Dispose();
            secondary.Dispose();
        }
    }

    private static void SetPeerConfigOn(FailoverService svc, FailoverPeer cfg) =>
        typeof(FailoverService)
            .GetField("_peerConfig", BindingFlags.NonPublic | BindingFlags.Instance)!
            .SetValue(svc, cfg);

    [Fact]
    public void ShouldHandleRequest_CommunicationsInterrupted_SplitsByLastIpOctet()
    {
        SetPeerConfig(new FailoverPeer
        {
            Enabled = true, Role = "primary", Split = 128,
            PeerAddress = IPAddress.Parse("10.0.0.2")
        });
        typeof(FailoverService).GetProperty("CurrentState")!
            .SetValue(_svc, FailoverState.CommunicationsInterrupted);

        // Primary owns last-octet < 128.
        Assert.True(_svc.ShouldHandleRequest("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.50")));
        Assert.False(_svc.ShouldHandleRequest("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.200")));
    }

    // ── Pool stats ─────────────────────────────────────────────────────

    [Fact]
    public async Task GetPoolStatsAsync_AggregatesActiveLeasesPerPool()
    {
        // Insert one subnet+pool with 5 IPs and one active lease.
        await using (var conn = await _pg.DataSource.OpenConnectionAsync())
        await using (var cmd = new NpgsqlCommand(@"
            INSERT INTO dhcp_subnets (id, name, network, subnet_mask, enabled, created_at, updated_at)
              VALUES (gen_random_uuid(), 'a', '10.0.1.0/24'::cidr, '255.255.255.0'::inet, true, now(), now());
            INSERT INTO dhcp_pools (id, subnet_id, range_start, range_end, enabled)
              SELECT gen_random_uuid(), s.id, '10.0.1.10', '10.0.1.14', true FROM dhcp_subnets s WHERE s.name = 'a';
            INSERT INTO dhcp_leases (id, mac_address, ip_address, start_time, end_time)
              VALUES (gen_random_uuid(), '11:11:11:11:11:11'::macaddr, '10.0.1.10', now(), now() + interval '1 hour');
            INSERT INTO dhcp_leases (id, mac_address, ip_address, start_time, end_time)
              VALUES (gen_random_uuid(), '22:22:22:22:22:22'::macaddr, '10.0.1.99', now() - interval '1 day', now() - interval '1 hour');", conn))
            await cmd.ExecuteNonQueryAsync();

        var stats = await _svc.GetPoolStatsAsync();

        var single = Assert.Single(stats);
        Assert.Equal(5, single.TotalAddresses);
        Assert.Equal(1, single.ActiveLeases); // only the in-window lease counted
    }

    [Fact]
    public async Task GetPoolStatsAsync_NoPools_ReturnsEmpty()
    {
        var stats = await _svc.GetPoolStatsAsync();
        Assert.Empty(stats);
    }
}
