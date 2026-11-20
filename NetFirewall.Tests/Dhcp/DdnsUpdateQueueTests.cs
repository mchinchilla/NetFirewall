using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>DDNS runs after the reply, off the packet path, honouring the subnet's config.</summary>
[Collection("Postgres")]
public sealed class DdnsUpdateQueueTests(PostgresFixture pg) : IAsyncLifetime
{
    private readonly Mock<IDdnsService> _ddns = new();
    private static readonly IPAddress Ip = IPAddress.Parse("192.168.50.120");
    private static readonly DdnsConfig Enabled = new() { Enabled = true, DnsServer = IPAddress.Parse("192.168.50.1") };

    public async Task InitializeAsync()
    {
        await pg.ResetSchemaAsync();
        await pg.BootstrapApplicationSchemaAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private DdnsUpdateQueue Queue() => new(
        new ServiceCollection().AddScoped(_ => _ddns.Object).BuildServiceProvider().GetRequiredService<IServiceScopeFactory>(),
        pg.DataSource, NullLogger<DdnsUpdateQueue>.Instance);

    private async Task<List<(string Action, bool Ok)>> LogAsync()
    {
        await using var c = await pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand("SELECT action, success FROM dhcp_ddns_log ORDER BY created_at, action", c);
        await using var r = await cmd.ExecuteReaderAsync();
        var list = new List<(string, bool)>();
        while (await r.ReadAsync()) list.Add((r.GetString(0), r.GetBoolean(1)));
        return list;
    }

    [Fact]
    public async Task Register_WhenTheSubnetHasDdns_UpdatesDnsAndLogs()
    {
        _ddns.Setup(x => x.GetConfigForSubnetAsync(It.IsAny<Guid?>(), It.IsAny<CancellationToken>())).ReturnsAsync(Enabled);
        _ddns.Setup(x => x.UpdateLeaseRecordsAsync("laptop", Ip, "aa:bb:cc:00:00:01", Enabled, It.IsAny<CancellationToken>()))
             .ReturnsAsync(new DdnsUpdateResult { ForwardSuccess = true, ReverseSuccess = true, Fqdn = "laptop.home.lan" });

        await Queue().ProcessAsync(new DdnsWork(DdnsAction.Register, "aa:bb:cc:00:00:01", Ip, "laptop", null), default);

        Assert.Equal([("add_forward", true), ("add_reverse", true)], await LogAsync());
    }

    [Fact]
    public async Task Nothing_WhenDdnsIsNotConfigured()
    {
        _ddns.Setup(x => x.GetConfigForSubnetAsync(It.IsAny<Guid?>(), It.IsAny<CancellationToken>())).ReturnsAsync((DdnsConfig?)null);
        await Queue().ProcessAsync(new DdnsWork(DdnsAction.Register, "aa:bb:cc:00:00:01", Ip, "laptop", null), default);
        _ddns.Verify(x => x.UpdateLeaseRecordsAsync(It.IsAny<string>(), It.IsAny<IPAddress>(), It.IsAny<string>(), It.IsAny<DdnsConfig>(), It.IsAny<CancellationToken>()), Times.Never);
        Assert.Empty(await LogAsync());
    }

    [Fact]
    public async Task Remove_TakesTheHostnameFromTheLastRegistration()
    {
        _ddns.Setup(x => x.GetConfigForSubnetAsync(It.IsAny<Guid?>(), It.IsAny<CancellationToken>())).ReturnsAsync(Enabled);
        _ddns.Setup(x => x.UpdateLeaseRecordsAsync(It.IsAny<string>(), Ip, It.IsAny<string>(), Enabled, It.IsAny<CancellationToken>()))
             .ReturnsAsync(new DdnsUpdateResult { ForwardSuccess = true, ReverseSuccess = true, Fqdn = "nas.home.lan" });
        _ddns.Setup(x => x.RemoveLeaseRecordsAsync("nas", Ip, Enabled, It.IsAny<CancellationToken>()))
             .ReturnsAsync(new DdnsUpdateResult { ForwardSuccess = true, ReverseSuccess = true });
        var q = Queue();

        await q.ProcessAsync(new DdnsWork(DdnsAction.Register, "aa:bb:cc:00:00:02", Ip, "nas", null), default);
        await q.ProcessAsync(new DdnsWork(DdnsAction.Remove, "aa:bb:cc:00:00:02", Ip, null, null), default);   // RELEASE: no hostname

        _ddns.Verify(x => x.RemoveLeaseRecordsAsync("nas", Ip, Enabled, It.IsAny<CancellationToken>()), Times.Once);
    }
}

/// <summary>The reply path only enqueues — never calls DNS inline.</summary>
public sealed class DdnsEnqueueOnAckTests
{
    [Fact]
    public async Task Ack_WithAHostname_EnqueuesARegistration_AndStillAcks()
    {
        var mac = "aa:bb:cc:00:00:01"; var ip = IPAddress.Parse("192.168.50.120");
        var subnet = new DhcpSubnet { Id = Guid.NewGuid(), Name = "LAN", Network = "192.168.50.0/24",
            SubnetMask = IPAddress.Parse("255.255.255.0"), Router = IPAddress.Parse("192.168.50.1"), DefaultLeaseTime = 3600 };
        var subnets = new Mock<IDhcpSubnetService>();
        subnets.Setup(x => x.FindSubnetForRequestAsync(It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>())).ReturnsAsync(subnet);
        subnets.Setup(x => x.CheckRequestedIpAsync(subnet, mac, ip, It.IsAny<CancellationToken>())).ReturnsAsync(RequestedIpVerdict.Allowed);
        var leases = new Mock<IDhcpLeasesService>();
        leases.Setup(x => x.CanAssignIpAsync(mac, ip)).ReturnsAsync(true);
        var queue = new Mock<IDdnsUpdateQueue>();
        var svc = new DhcpServerService(leases.Object, subnets.Object, NullLogger<DhcpServerService>.Instance,
            Options.Create(new DhcpConfig()), ddnsQueue: queue.Object);

        using var r = await svc.CreateDhcpResponseAsync(new DhcpRequest
        {
            ClientMac = mac, ChAddr = new byte[16], Xid = [1, 2, 3, 4], MessageType = DhcpMessageType.Request,
            CiAddr = IPAddress.Any, YiAddr = IPAddress.Any, SiAddr = IPAddress.Any, GiAddr = IPAddress.Any,
            RequestedIp = ip, Hostname = "laptop",
        });

        Assert.False(r.IsEmpty);
        queue.Verify(x => x.TryEnqueue(new DdnsWork(DdnsAction.Register, mac, ip, "laptop", subnet.Id)), Times.Once);
    }
}
