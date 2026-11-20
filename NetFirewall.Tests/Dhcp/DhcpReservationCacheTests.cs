using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// Reservations served from memory on the DHCP hot path (DhcpReservationCache) instead of
/// 1–2 queries per DISCOVER/REQUEST. Real PostgreSQL: the lookups, MAC spellings, the
/// statement trigger that announces a change (migration 00044), and allocation through it.
/// </summary>
[Collection("Postgres")]
public sealed class DhcpReservationCacheTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private DhcpReservationCache _cache = null!;

    public DhcpReservationCacheTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _cache = new DhcpReservationCache(_pg.DataSource, NullLogger<DhcpReservationCache>.Instance);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private async Task ExecAsync(string sql)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(sql, conn);
        await cmd.ExecuteNonQueryAsync();
    }

    [Fact]
    public async Task Lookups_AcceptAnyMacSpelling_AndAnswerTheOwnerOfAnIp()
    {
        await ExecAsync("INSERT INTO dhcp_mac_reservations (id, mac_address, reserved_ip) VALUES (uuid_generate_v4(), 'aa:bb:cc:00:00:01', '10.90.0.42')");

        Assert.Equal(IPAddress.Parse("10.90.0.42"), await _cache.GetReservedIpAsync("AA-BB-CC-00-00-01"));
        Assert.Equal(IPAddress.Parse("10.90.0.42"), await _cache.GetReservedIpAsync("aabbcc000001"));
        Assert.Equal("aa:bb:cc:00:00:01", await _cache.GetOwnerMacAsync(IPAddress.Parse("10.90.0.42")));
        Assert.Null(await _cache.GetReservedIpAsync("aa:bb:cc:00:00:02"));
        Assert.Null(await _cache.GetReservedIpAsync("not-a-mac"));
    }

    [Fact]
    public async Task Invalidate_PicksUpARepointedReservation()
    {
        await ExecAsync("INSERT INTO dhcp_mac_reservations (id, mac_address, reserved_ip) VALUES (uuid_generate_v4(), 'aa:bb:cc:00:00:01', '10.90.0.42')");
        Assert.Equal(IPAddress.Parse("10.90.0.42"), await _cache.GetReservedIpAsync("aa:bb:cc:00:00:01"));

        await ExecAsync("UPDATE dhcp_mac_reservations SET reserved_ip = '10.90.0.43'");
        _cache.Invalidate();   // what the reservation.changed NOTIFY triggers

        Assert.Equal(IPAddress.Parse("10.90.0.43"), await _cache.GetReservedIpAsync("aa:bb:cc:00:00:01"));
        Assert.Null(await _cache.GetOwnerMacAsync(IPAddress.Parse("10.90.0.42")));
    }

    [Fact]
    public async Task AnyReservationWrite_NotifiesTheDhcpServer()
    {
        await using var listen = await _pg.DataSource.OpenConnectionAsync();
        var got = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        listen.Notification += (_, e) => got.TrySetResult(e.Payload);
        await using (var cmd = new NpgsqlCommand($"LISTEN {IDhcpCacheNotifier.SubnetChannel}", listen))
            await cmd.ExecuteNonQueryAsync();

        await ExecAsync("INSERT INTO dhcp_mac_reservations (id, mac_address, reserved_ip) VALUES (uuid_generate_v4(), 'aa:bb:cc:00:00:09', '10.90.0.9')");

        var wait = listen.WaitAsync(TimeSpan.FromSeconds(5));
        var payload = await got.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("reservation.changed", payload);
    }

    [Fact]
    public async Task Allocation_ThroughTheCache_ReturnsTheReservedIp()
    {
        using var leases = new LeaseCache(_pg.DataSource, NullLogger<LeaseCache>.Instance,
            batchSize: 100, batchIntervalMs: 20, cleanupIntervalSeconds: 60);
        var svc = new DhcpSubnetService(_pg.DataSource, NullLogger<DhcpSubnetService>.Instance, leases, _cache);
        var subnet = await svc.CreateSubnetAsync(new DhcpSubnet
        {
            Name = "home", Network = "10.91.0.0/24", SubnetMask = IPAddress.Parse("255.255.255.0"),
            Router = IPAddress.Parse("10.91.0.1"), Enabled = true,
        });
        await svc.CreatePoolAsync(new DhcpPool { SubnetId = subnet.Id, Name = "p", RangeStart = IPAddress.Parse("10.91.0.100"), RangeEnd = IPAddress.Parse("10.91.0.200"), Enabled = true });
        await ExecAsync("INSERT INTO dhcp_mac_reservations (id, mac_address, reserved_ip) VALUES (uuid_generate_v4(), 'aa:bb:cc:00:00:01', '10.91.0.42')");

        var (ip, pool) = await svc.FindAvailableIpInSubnetAsync(subnet, "aa:bb:cc:00:00:01", new DhcpRequest
        {
            ClientMac = "aa:bb:cc:00:00:01", CiAddr = IPAddress.Any, GiAddr = IPAddress.Any,
            YiAddr = IPAddress.Any, SiAddr = IPAddress.Any, RequestedIp = IPAddress.Any,
        });

        Assert.Equal("10.91.0.42", ip?.ToString());
        Assert.Null(pool);
    }
}
