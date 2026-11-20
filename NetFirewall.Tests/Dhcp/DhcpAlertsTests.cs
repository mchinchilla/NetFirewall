using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.DhcpServer;
using NetFirewall.Models.Dhcp;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Dhcp;
using NetFirewall.Services.Monitoring;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>Banner alerts: a pool about to run dry, another DHCP server on the LAN.</summary>
public sealed class DhcpAlertsTests
{
    private static PoolUsage Usage(long used) => new(Guid.NewGuid(), "LAN", "main", used, 100);

    [Theory]
    [InlineData(70, false, null)]
    [InlineData(84, false, null)]
    [InlineData(85, false, "warning")]
    [InlineData(95, false, "danger")]
    [InlineData(82, true, "warning")]     // inside the band while alerting: stays up (no flapping)
    [InlineData(79, true, null)]          // below 80: resolves
    public void PoolSeverity_HasHysteresis(long used, bool alerting, string? expected) =>
        Assert.Equal(expected, DhcpPoolAlertService.SeverityFor(Usage(used), alerting));

    private static byte[] ReplyFrame(byte[] srcIp, ushort srcPort = 67, ushort dstPort = 68, byte op = 2)
    {
        var f = new byte[14 + 20 + 8 + 240];
        byte[] mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        mac.CopyTo(f, 6);
        f[12] = 0x08; f[13] = 0x00;
        f[14] = 0x45; f[14 + 9] = 17;
        srcIp.CopyTo(f, 14 + 12);
        f[34] = (byte)(srcPort >> 8); f[35] = (byte)srcPort; f[36] = (byte)(dstPort >> 8); f[37] = (byte)dstPort;
        f[42] = op;
        return f;
    }

    [Fact]
    public void RawSocket_RecognisesAServerReply()
    {
        Assert.True(LinuxRawSocket.TryReadServerReply(ReplyFrame([192, 168, 1, 254]), out var ip, out var mac));
        Assert.Equal(IPAddress.Parse("192.168.1.254"), ip);
        Assert.Equal("02:11:22:33:44:55", mac);
    }

    [Theory]
    [InlineData(68, 67, 2)]   // client → server
    [InlineData(67, 68, 1)]   // BOOTREQUEST on the reply ports
    public void RawSocket_IgnoresAnythingElse(int src, int dst, int op) =>
        Assert.False(LinuxRawSocket.TryReadServerReply(ReplyFrame([10, 0, 0, 1], (ushort)src, (ushort)dst, (byte)op), out _, out _));

    [Fact]
    public async Task RogueMonitor_RaisesOncePerWindow_AndResolvesAfterSilence()
    {
        var writer = new Mock<ISystemAlertWriter>();
        var scopes = new ServiceCollection().AddScoped(_ => writer.Object).BuildServiceProvider().GetRequiredService<IServiceScopeFactory>();
        var monitor = new RogueDhcpMonitor(scopes, NullLogger<RogueDhcpMonitor>.Instance);
        var reply = new ForeignDhcpReply("eth1", IPAddress.Parse("192.168.1.254"), "02:11:22:33:44:55");
        var t0 = DateTime.UtcNow;

        await monitor.HandleAsync(reply, t0, default);
        await monitor.HandleAsync(reply, t0.AddMinutes(2), default);          // same window: no re-raise
        await monitor.HandleAsync(reply, t0.AddMinutes(11), default);         // next window: re-raise
        writer.Verify(w => w.RaiseAlertAsync(It.Is<SystemAlert>(a => a.DedupeKey == "dhcp-rogue:eth1:192.168.1.254" && a.Severity == "danger"),
            It.IsAny<CancellationToken>()), Times.Exactly(2));

        await monitor.SweepAsync(t0.AddMinutes(40), default);                 // seen 29 min ago: still active
        writer.Verify(w => w.ResolveAlertAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        await monitor.SweepAsync(t0.AddMinutes(75), default);                 // silent for an hour: resolved
        writer.Verify(w => w.ResolveAlertAsync("dhcp-rogue:eth1:192.168.1.254", It.IsAny<CancellationToken>()), Times.Once);
    }
}

[Collection("Postgres")]
public sealed class DhcpPoolUsageTests(PostgresFixture pg) : IAsyncLifetime
{
    public async Task InitializeAsync()
    {
        await pg.ResetSchemaAsync();
        await pg.BootstrapApplicationSchemaAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Usage_CountsActiveLeasesInTheRange_AndCapacityExcludesExclusions()
    {
        var subnets = new DhcpSubnetService(pg.DataSource, NullLogger<DhcpSubnetService>.Instance);
        var s = await subnets.CreateSubnetAsync(new DhcpSubnet { Name = "home", Network = "10.91.0.0/24", SubnetMask = IPAddress.Parse("255.255.255.0"), Router = IPAddress.Parse("10.91.0.1"), Enabled = true });
        await subnets.CreatePoolAsync(new DhcpPool { SubnetId = s.Id, Name = "main", RangeStart = IPAddress.Parse("10.91.0.100"), RangeEnd = IPAddress.Parse("10.91.0.119"), Enabled = true });
        await using (var c = await pg.DataSource.OpenConnectionAsync())
        await using (var cmd = new NpgsqlCommand($"""
            INSERT INTO dhcp_exclusions (subnet_id, ip_start, ip_end) VALUES ('{s.Id}', '10.91.0.115', '10.91.0.119');
            INSERT INTO dhcp_leases (id, mac_address, ip_address, start_time, end_time) VALUES
              (uuid_generate_v4(), '02:00:00:00:00:01', '10.91.0.100', now(), now() + interval '1 h'),
              (uuid_generate_v4(), '02:00:00:00:00:02', '10.91.0.101', now(), now() + interval '1 h'),
              (uuid_generate_v4(), '02:00:00:00:00:03', '10.91.0.102', now() - interval '2 h', now() - interval '1 h'),
              (uuid_generate_v4(), '02:00:00:00:00:04', '10.91.0.20',  now(), now() + interval '1 h');
            """, c))
            await cmd.ExecuteNonQueryAsync();
        var svc = new DhcpPoolAlertService(pg.DataSource, new ServiceCollection().BuildServiceProvider().GetRequiredService<IServiceScopeFactory>(), NullLogger<DhcpPoolAlertService>.Instance);

        var usage = Assert.Single(await svc.UsageAsync(default));

        Assert.Equal(2, usage.Used);        // the expired lease and the one outside the range don't count
        Assert.Equal(15, usage.Capacity);   // 20 addresses minus 5 excluded
    }
}
