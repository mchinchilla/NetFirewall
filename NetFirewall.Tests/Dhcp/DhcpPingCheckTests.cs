using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetFirewall.Tests.Infra;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>Ping check before offering a new address (a hand-set static IP inside the pool).</summary>
[Collection("Postgres")]
public sealed class DhcpPingCheckTests(PostgresFixture pg) : IAsyncLifetime
{
    private sealed class Answers(params string[] alive) : IAddressProbe
    {
        public List<IPAddress> Probed { get; } = [];
        public Task<bool> IsInUseAsync(IPAddress address, CancellationToken ct = default)
        {
            Probed.Add(address);
            return Task.FromResult(alive.Contains(address.ToString()));
        }
    }

    private LeaseCache _cache = null!;
    private DhcpSubnet _subnet = null!;

    public async Task InitializeAsync()
    {
        await pg.ResetSchemaAsync();
        await pg.BootstrapApplicationSchemaAsync();
        _cache = new LeaseCache(pg.DataSource, NullLogger<LeaseCache>.Instance, batchSize: 100, batchIntervalMs: 20, cleanupIntervalSeconds: 60);
        var setup = new DhcpSubnetService(pg.DataSource, NullLogger<DhcpSubnetService>.Instance, _cache);
        _subnet = await setup.CreateSubnetAsync(new DhcpSubnet { Name = "home", Network = "10.91.0.0/24", SubnetMask = IPAddress.Parse("255.255.255.0"), Router = IPAddress.Parse("10.91.0.1"), Enabled = true });
        await setup.CreatePoolAsync(new DhcpPool { SubnetId = _subnet.Id, Name = "p", RangeStart = IPAddress.Parse("10.91.0.100"), RangeEnd = IPAddress.Parse("10.91.0.200"), Enabled = true });
    }

    public Task DisposeAsync() { _cache.Dispose(); return Task.CompletedTask; }

    private static DhcpRequest Discover(string mac) => new()
    {
        ClientMac = mac, MessageType = DhcpMessageType.Discover,
        CiAddr = IPAddress.Any, GiAddr = IPAddress.Any, YiAddr = IPAddress.Any, SiAddr = IPAddress.Any,
    };

    [Fact]
    public async Task AnAddressThatAnswersPing_IsQuarantined_AndTheNextOneOffered()
    {
        var probe = new Answers("10.91.0.100");
        var svc = new DhcpSubnetService(pg.DataSource, NullLogger<DhcpSubnetService>.Instance, _cache, addressProbe: probe);

        var (ip, _) = await svc.FindAvailableIpInSubnetAsync(_subnet, "aa:bb:cc:00:00:01", Discover("aa:bb:cc:00:00:01"));

        Assert.Equal(IPAddress.Parse("10.91.0.101"), ip);
        Assert.True(_cache.IsIpDeclined(IPAddress.Parse("10.91.0.100")));
    }

    [Fact]
    public async Task TheClientsCurrentAddress_IsNeverPinged()
    {
        var probe = new Answers("10.91.0.150");                      // its own device answers, of course
        await _cache.SetLeaseAsync("aa:bb:cc:00:00:02", IPAddress.Parse("10.91.0.150"), 3600);
        var svc = new DhcpSubnetService(pg.DataSource, NullLogger<DhcpSubnetService>.Instance, _cache, addressProbe: probe);

        var (ip, _) = await svc.FindAvailableIpInSubnetAsync(_subnet, "aa:bb:cc:00:00:02", Discover("aa:bb:cc:00:00:02"));

        Assert.Equal(IPAddress.Parse("10.91.0.150"), ip);
        Assert.Empty(probe.Probed);
    }
}
