using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Services.Dhcp;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// End-to-end LISTEN/NOTIFY coverage. Regression focus: the notifier used
/// `NOTIFY channel, @p` — a Postgres utility statement that rejects bind
/// parameters — so every notify silently failed (the catch swallowed it) and
/// the DHCP server's caches only ever refreshed on TTL. Also covers the new
/// lease.release payload that purges the DHCP server's in-memory LeaseCache
/// when an admin releases a lease from the Web UI.
/// </summary>
[Collection("Postgres")]
public sealed class DhcpCacheNotifyTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;

    public DhcpCacheNotifyTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private static async Task<bool> WaitForAsync(Func<bool> p, int timeoutMs = 5000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTime.UtcNow < deadline)
        {
            if (p()) return true;
            await Task.Delay(25);
        }
        return p();
    }

    [Fact]
    public async Task Notifier_DeliversPayload_ToListeningConnection()
    {
        string? received = null;

        await using var listenConn = await _pg.DataSource.OpenConnectionAsync();
        listenConn.Notification += (_, e) => received = e.Payload;
        await using (var listen = new NpgsqlCommand($"LISTEN {IDhcpCacheNotifier.SubnetChannel}", listenConn))
        {
            await listen.ExecuteNonQueryAsync();
        }

        var notifier = new DhcpCacheNotifier(_pg.DataSource, NullLogger<DhcpCacheNotifier>.Instance);
        await notifier.NotifySubnetChangedAsync("subnet.update:test-payload");

        // Pump the listening connection until the notification lands.
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            while (received is null)
            {
                await listenConn.WaitAsync(cts.Token);
            }
        }
        catch (OperationCanceledException)
        {
            // fall through to the assert with whatever we got
        }

        Assert.Equal("subnet.update:test-payload", received);
    }

    [Fact]
    public async Task Listener_LeaseReleasePayload_PurgesLeaseCacheEntry()
    {
        using var cache = new LeaseCache(_pg.DataSource, NullLogger<LeaseCache>.Instance,
            batchSize: 100, batchIntervalMs: 20, cleanupIntervalSeconds: 3600);
        var ip = IPAddress.Parse("10.70.0.42");
        await cache.SetLeaseAsync("aa:bb:cc:00:70:01", ip, 3600);
        Assert.True(cache.IsIpLeased(ip));

        var subnets = new Mock<IDhcpSubnetService>();
        var listener = new DhcpCacheRefreshListener(
            _pg.DataSource, subnets.Object, NullLogger<DhcpCacheRefreshListener>.Instance, cache);

        await listener.StartAsync(CancellationToken.None);
        try
        {
            // Give the LISTEN a moment to be registered, then notify.
            var notifier = new DhcpCacheNotifier(_pg.DataSource, NullLogger<DhcpCacheNotifier>.Instance);
            await Task.Delay(250);
            await notifier.NotifySubnetChangedAsync($"lease.release:{ip}");

            Assert.True(await WaitForAsync(() => !cache.IsIpLeased(ip)),
                "lease.release notification did not purge the cache entry");
            // Lease events must NOT nuke the subnet cache.
            subnets.Verify(s => s.InvalidateCache(), Times.Never);
        }
        finally
        {
            await listener.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task Listener_SubnetPayload_InvalidatesSubnetCache()
    {
        var subnets = new Mock<IDhcpSubnetService>();
        var listener = new DhcpCacheRefreshListener(
            _pg.DataSource, subnets.Object, NullLogger<DhcpCacheRefreshListener>.Instance);

        await listener.StartAsync(CancellationToken.None);
        try
        {
            var notifier = new DhcpCacheNotifier(_pg.DataSource, NullLogger<DhcpCacheNotifier>.Instance);
            await Task.Delay(250);
            await notifier.NotifySubnetChangedAsync("subnet.update:some-id");

            Assert.True(await WaitForAsync(
                () => subnets.Invocations.Any(i => i.Method.Name == nameof(IDhcpSubnetService.InvalidateCache))),
                "subnet notification did not invalidate the subnet cache");
        }
        finally
        {
            await listener.StopAsync(CancellationToken.None);
        }
    }
}
