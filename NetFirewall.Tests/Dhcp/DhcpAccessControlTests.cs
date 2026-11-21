using System.Collections.Frozen;
using System.Net;
using System.Net.NetworkInformation;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>MAC block list and trusted relays: the pure policy and what the server does with it.</summary>
public sealed class DhcpAccessPolicyTests
{
    private static readonly IPAddress Relay1 = IPAddress.Parse("10.20.0.1");
    private static readonly IPAddress Relay2 = IPAddress.Parse("10.30.0.1");

    private static DhcpRelayPolicy Policy(params (IPAddress Ip, bool Trusted)[] relays) =>
        DhcpRelayPolicy.From(relays.Select(r => new DhcpRelayAgent { IpAddress = r.Ip, Trusted = r.Trusted }));

    [Fact]
    public void NoRelaysListed_EverythingIsAccepted()
    {
        var p = DhcpRelayPolicy.Open;
        Assert.False(p.IsEnforced);
        Assert.Equal(DhcpRelayVerdict.Accept, p.Evaluate(Relay1, hasOption82: true));
        Assert.Equal(DhcpRelayVerdict.Accept, p.Evaluate(IPAddress.Any, hasOption82: true));
    }

    [Fact]
    public void OneTrustedRelay_DropsEveryOtherRelay()
    {
        var p = Policy((Relay1, true));
        Assert.True(p.IsEnforced);
        Assert.Equal(DhcpRelayVerdict.Accept, p.Evaluate(Relay1, hasOption82: true));
        Assert.Equal(DhcpRelayVerdict.Drop, p.Evaluate(Relay2, hasOption82: false));
    }

    [Fact]
    public void Enforced_DirectPacketWithOption82_IsAnswered_ButItsOption82IsNotTrusted()
    {
        // DHCP-snooping switches insert option 82 with giaddr 0 — dropping those would cut LANs off.
        var p = Policy((Relay1, true));
        Assert.Equal(DhcpRelayVerdict.AcceptIgnoringOption82, p.Evaluate(IPAddress.Any, hasOption82: true));
        Assert.Equal(DhcpRelayVerdict.Accept, p.Evaluate(IPAddress.Any, hasOption82: false));
    }

    [Fact]
    public void RefusedRelay_IsDropped_EvenWhenNoRelayIsTrusted()
    {
        var p = Policy((Relay2, false));
        Assert.False(p.IsEnforced);
        Assert.Equal(DhcpRelayVerdict.Drop, p.Evaluate(Relay2, hasOption82: false));
        Assert.Equal(DhcpRelayVerdict.Accept, p.Evaluate(Relay1, hasOption82: false));
    }

    [Fact]
    public void UntrustedOption82_CannotSelectAClass()
    {
        var cls = new DhcpClass { MatchType = DhcpClassMatchTypes.RelayAgent, MatchValue = "0106" };
        var request = new DhcpRequest { RelayAgentInformation = [1, 6, 1, 2, 3, 4, 5, 6] };
        Assert.True(DhcpClassMatcher.Matches(request, cls));
        request.RelayAgentInfoTrusted = false;
        Assert.False(DhcpClassMatcher.Matches(request, cls));
        Assert.False(DhcpClassMatcher.Matches(request, new DhcpClass { MatchType = DhcpClassMatchTypes.Option, MatchValue = "82=0106" }));
    }

    // ── In the server ──

    private const string Mac = "aa:bb:cc:00:00:01";

    private static DhcpRequest Discover(IPAddress? giaddr = null, byte[]? option82 = null) => new()
    {
        ClientMac = Mac, ChAddr = new byte[16], Xid = [1, 2, 3, 4], MessageType = DhcpMessageType.Discover,
        CiAddr = IPAddress.Any, YiAddr = IPAddress.Any, SiAddr = IPAddress.Any, GiAddr = giaddr ?? IPAddress.Any,
        RelayAgentInformation = option82,
    };

    private static (DhcpServerService Svc, Mock<IDhcpSubnetService> Subnets) Server(IDhcpBlocklistCache? blocklist = null, IDhcpRelayTrustCache? relays = null)
    {
        var subnet = new DhcpSubnet
        {
            Id = Guid.NewGuid(), Name = "LAN", Network = "192.168.50.0/24", SubnetMask = IPAddress.Parse("255.255.255.0"),
            Router = IPAddress.Parse("192.168.50.1"), DefaultLeaseTime = 3600,
        };
        var subnets = new Mock<IDhcpSubnetService>();
        subnets.Setup(x => x.FindSubnetForRequestAsync(It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>())).ReturnsAsync(subnet);
        subnets.Setup(x => x.MatchClientClassAsync(It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>())).ReturnsAsync((DhcpClass?)null);
        subnets.Setup(x => x.FindAvailableIpInSubnetAsync(subnet, Mac, It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>()))
               .ReturnsAsync((IPAddress.Parse("192.168.50.120"), null));
        var svc = new DhcpServerService(new Mock<IDhcpLeasesService>().Object, subnets.Object, NullLogger<DhcpServerService>.Instance,
            Options.Create(new DhcpConfig()), blocklist: blocklist, relayTrust: relays);
        return (svc, subnets);
    }

    private static IDhcpRelayTrustCache Relays(DhcpRelayPolicy policy)
    {
        var m = new Mock<IDhcpRelayTrustCache>();
        m.Setup(x => x.GetPolicyAsync(It.IsAny<CancellationToken>())).ReturnsAsync(policy);
        return m.Object;
    }

    [Fact]
    public async Task BlockedMac_GetsNoReply_AndNoPoolLookup()
    {
        var blocklist = new Mock<IDhcpBlocklistCache>();
        blocklist.Setup(x => x.IsBlockedAsync(Mac, It.IsAny<CancellationToken>())).ReturnsAsync(true);
        var (svc, subnets) = Server(blocklist.Object);

        using var r = await svc.CreateDhcpResponseAsync(Discover());

        Assert.True(r.IsEmpty);
        subnets.Verify(x => x.FindAvailableIpInSubnetAsync(It.IsAny<DhcpSubnet>(), It.IsAny<string>(), It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task UnblockedMac_IsServed()
    {
        var blocklist = new Mock<IDhcpBlocklistCache>();
        blocklist.Setup(x => x.IsBlockedAsync(Mac, It.IsAny<CancellationToken>())).ReturnsAsync(false);
        using var r = await Server(blocklist.Object).Svc.CreateDhcpResponseAsync(Discover());
        Assert.False(r.IsEmpty);
    }

    [Fact]
    public async Task UntrustedRelay_IsDropped_TrustedRelay_IsServed()
    {
        var policy = DhcpRelayPolicy.From([new DhcpRelayAgent { IpAddress = Relay1, Trusted = true }]);
        var (svc, _) = Server(relays: Relays(policy));

        using var fromStranger = await svc.CreateDhcpResponseAsync(Discover(Relay2));
        Assert.True(fromStranger.IsEmpty);

        using var fromTrusted = await svc.CreateDhcpResponseAsync(Discover(Relay1, [1, 2, 0x47, 0x69]));
        Assert.False(fromTrusted.IsEmpty);
    }

    [Fact]
    public async Task Enforced_DirectOption82_IsEchoed_ButMarkedUntrustedForClassMatching()
    {
        var policy = DhcpRelayPolicy.From([new DhcpRelayAgent { IpAddress = Relay1, Trusted = true }]);
        var (svc, subnets) = Server(relays: Relays(policy));
        DhcpRequest? seen = null;
        subnets.Setup(x => x.MatchClientClassAsync(It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>()))
               .Callback<DhcpRequest, CancellationToken>((req, _) => seen = req).ReturnsAsync((DhcpClass?)null);

        using var r = await svc.CreateDhcpResponseAsync(Discover(IPAddress.Any, [1, 2, 0x47, 0x69]));

        Assert.False(r.IsEmpty);
        Assert.False(seen!.RelayAgentInfoTrusted);
        var span = r.Span;
        var echoed = false;
        for (var i = 240; i < span.Length - 1;)
        {
            if (span[i] == 255) break;
            if (span[i] == 0) { i++; continue; }
            if (span[i] == 82) { echoed = true; break; }
            i += 2 + span[i + 1];
        }
        Assert.True(echoed, "option 82 must still be echoed (RFC 3046 §2.2)");
    }
}

/// <summary>Real Postgres: the block list / relay CRUD, the lease purge, the caches and their triggers (00053/00054).</summary>
[Collection("Postgres")]
public sealed class DhcpAccessControlPersistenceTests(PostgresFixture pg) : IAsyncLifetime
{
    private DhcpAccessControlService _svc = null!;
    private readonly List<string> _notified = [];

    public async Task InitializeAsync()
    {
        await pg.ResetSchemaAsync();
        await pg.BootstrapApplicationSchemaAsync();
        var notifier = new Mock<IDhcpCacheNotifier>();
        notifier.Setup(n => n.NotifySubnetChangedAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Callback<string, CancellationToken>((reason, _) => _notified.Add(reason))
                .Returns(Task.CompletedTask);
        _svc = new DhcpAccessControlService(pg.DataSource, notifier.Object, NullLogger<DhcpAccessControlService>.Instance);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private async Task ExecAsync(string sql)
    {
        await using var conn = await pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(sql, conn);
        await cmd.ExecuteNonQueryAsync();
    }

    private static PhysicalAddress Mac(string text) => PhysicalAddress.Parse(text.Replace(":", "-").ToUpperInvariant());

    [Fact]
    public async Task Blocking_PurgesTheLease_TellsTheServer_AndTheCacheSeesIt()
    {
        await ExecAsync("INSERT INTO dhcp_leases (mac_address, ip_address, start_time, end_time) VALUES ('aa:bb:cc:00:00:01', '10.9.0.50', now(), now() + interval '1 hour')");
        var cache = new DhcpBlocklistCache(pg.DataSource, NullLogger<DhcpBlocklistCache>.Instance);
        Assert.False(await cache.IsBlockedAsync("aa:bb:cc:00:00:01"));

        var saved = await _svc.SaveBlockedMacAsync(new DhcpBlockedMac { MacAddress = Mac("aa:bb:cc:00:00:01"), Reason = "lost phone" });

        Assert.True(saved.Success, saved.Message);
        Assert.Contains("10.9.0.50", saved.Message);
        Assert.Contains("lease.release:10.9.0.50", _notified);
        await using (var conn = await pg.DataSource.OpenConnectionAsync())
        await using (var count = new NpgsqlCommand("SELECT count(*) FROM dhcp_leases", conn))
            Assert.Equal(0L, (long)(await count.ExecuteScalarAsync())!);

        cache.Invalidate();   // what the blocklist.changed NOTIFY does
        Assert.True(await cache.IsBlockedAsync("AA-BB-CC-00-00-01"));

        var dup = await _svc.SaveBlockedMacAsync(new DhcpBlockedMac { MacAddress = Mac("aa:bb:cc:00:00:01") });
        Assert.False(dup.Success);
        Assert.Contains("already", dup.Message);

        Assert.True((await _svc.DeleteBlockedMacAsync(saved.Data!.Id)).Success);
        cache.Invalidate();
        Assert.False(await cache.IsBlockedAsync("aa:bb:cc:00:00:01"));
    }

    [Fact]
    public async Task Blocking_RefusesBroadcastAndZeroMacs()
    {
        Assert.False((await _svc.SaveBlockedMacAsync(new DhcpBlockedMac { MacAddress = Mac("ff:ff:ff:ff:ff:ff") })).Success);
        Assert.False((await _svc.SaveBlockedMacAsync(new DhcpBlockedMac { MacAddress = Mac("00:00:00:00:00:00") })).Success);
    }

    [Fact]
    public async Task Relays_FirstTrustedOneSwitchesEnforcementOn_AndTheCacheFollows()
    {
        var cache = new DhcpRelayTrustCache(pg.DataSource, NullLogger<DhcpRelayTrustCache>.Instance);
        Assert.False((await cache.GetPolicyAsync()).IsEnforced);

        var first = await _svc.SaveRelayAgentAsync(new DhcpRelayAgent { IpAddress = IPAddress.Parse("10.20.0.1"), Trusted = true });
        Assert.True(first.Success, first.Message);
        Assert.Contains("now ON", first.Message);

        var second = await _svc.SaveRelayAgentAsync(new DhcpRelayAgent { IpAddress = IPAddress.Parse("10.30.0.1"), Trusted = true });
        Assert.DoesNotContain("now ON", second.Message);

        cache.Invalidate();
        var policy = await cache.GetPolicyAsync();
        Assert.True(policy.IsEnforced);
        Assert.Equal(DhcpRelayVerdict.Drop, policy.Evaluate(IPAddress.Parse("10.40.0.1"), false));

        Assert.False((await _svc.SaveRelayAgentAsync(new DhcpRelayAgent { IpAddress = IPAddress.Parse("10.20.0.1") })).Success);   // duplicate
        Assert.False((await _svc.SaveRelayAgentAsync(new DhcpRelayAgent { IpAddress = IPAddress.Parse("127.0.0.1") })).Success);  // loopback

        await _svc.DeleteRelayAgentAsync(second.Data!.Id);
        var last = await _svc.DeleteRelayAgentAsync(first.Data!.Id);
        Assert.Contains("every relay is answered again", last.Message);
    }

    [Theory]
    [InlineData("INSERT INTO dhcp_mac_blocklist (mac_address) VALUES ('aa:bb:cc:00:00:09')", "blocklist.changed")]
    [InlineData("INSERT INTO dhcp_relay_agents (ip_address) VALUES ('10.50.0.1')", "relay.changed")]
    public async Task AnyWrite_NotifiesTheDhcpServer(string sql, string expected)
    {
        await using var listen = await pg.DataSource.OpenConnectionAsync();
        var got = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        listen.Notification += (_, e) => got.TrySetResult(e.Payload);
        await using (var cmd = new NpgsqlCommand($"LISTEN {IDhcpCacheNotifier.SubnetChannel}", listen))
            await cmd.ExecuteNonQueryAsync();

        await ExecAsync(sql);

        _ = listen.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(expected, await got.Task.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task ReservationLeaseTime_IsReadByTheCache_AndCheckedByTheDb()
    {
        await ExecAsync("INSERT INTO dhcp_mac_reservations (mac_address, reserved_ip, lease_time) VALUES ('aa:bb:cc:00:00:01', '10.9.0.42', 604800)");
        await ExecAsync("INSERT INTO dhcp_mac_reservations (mac_address, reserved_ip) VALUES ('aa:bb:cc:00:00:02', '10.9.0.43')");
        var cache = new DhcpReservationCache(pg.DataSource, NullLogger<DhcpReservationCache>.Instance);

        Assert.Equal(604800, await cache.GetLeaseTimeAsync("aa:bb:cc:00:00:01"));
        Assert.Null(await cache.GetLeaseTimeAsync("aa:bb:cc:00:00:02"));
        await Assert.ThrowsAsync<PostgresException>(() =>
            ExecAsync("INSERT INTO dhcp_mac_reservations (mac_address, reserved_ip, lease_time) VALUES ('aa:bb:cc:00:00:03', '10.9.0.44', 5)"));
    }
}
