using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using NetFirewall.Services.Dhcp;
using NetFirewall.Tests.Infra;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// The write-behind flush sends every queued upsert/delete in ONE NpgsqlBatch (positional
/// parameters). Pins that it really reaches PostgreSQL: a NULL hostname, an update of the
/// same MAC (ON CONFLICT), and a release (DELETE) in the same flush window.
/// </summary>
[Collection("Postgres")]
public sealed class LeaseCachePersistenceTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private LeaseCache _cache = null!;

    public LeaseCachePersistenceTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _cache = new LeaseCache(_pg.DataSource, NullLogger<LeaseCache>.Instance,
            batchSize: 100, batchIntervalMs: 20, cleanupIntervalSeconds: 3600);
    }

    public Task DisposeAsync()
    {
        _cache.Dispose();
        return Task.CompletedTask;
    }

    private async Task<(string? Ip, string? Host)?> RowAsync(string mac)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT host(ip_address), hostname FROM dhcp_leases WHERE mac_address = @m::macaddr", conn);
        cmd.Parameters.AddWithValue("m", mac);
        await using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync()) return null;
        return (r.IsDBNull(0) ? null : r.GetString(0), r.IsDBNull(1) ? null : r.GetString(1));
    }

    private static async Task<T> EventuallyAsync<T>(Func<Task<T>> probe, Func<T, bool> done)
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        T value;
        do
        {
            value = await probe();
            if (done(value)) return value;
            await Task.Delay(25);
        } while (DateTime.UtcNow < deadline);
        return value;
    }

    [Fact]
    public async Task Flush_PersistsUpsertWithNullHostname_ThenUpdate_ThenDelete()
    {
        const string mac = "aa:bb:cc:dd:ee:01";
        const string other = "aa:bb:cc:dd:ee:02";

        await _cache.SetLeaseAsync(mac, IPAddress.Parse("10.60.0.10"), 3600, hostname: null);
        await _cache.SetLeaseAsync(other, IPAddress.Parse("10.60.0.11"), 3600, hostname: "printer");

        var first = await EventuallyAsync(() => RowAsync(mac), r => r is not null);
        Assert.Equal(("10.60.0.10", (string?)null), first);
        Assert.Equal(("10.60.0.11", (string?)"printer"), await EventuallyAsync(() => RowAsync(other), r => r is not null));

        // Same MAC, new IP + hostname: ON CONFLICT (mac_address) updates in place.
        await _cache.SetLeaseAsync(mac, IPAddress.Parse("10.60.0.12"), 3600, hostname: "laptop");
        var moved = await EventuallyAsync(() => RowAsync(mac), r => r?.Ip == "10.60.0.12");
        Assert.Equal(("10.60.0.12", (string?)"laptop"), moved);

        await _cache.ReleaseLeaseAsync(other);
        Assert.Null(await EventuallyAsync(() => RowAsync(other), r => r is null));
    }

    // ── Set-based flush: one statement per kind, coalesced per MAC ──

    private static LeaseWriteOperation Up(string mac, string ip, string? host = null) => new()
    {
        Type = LeaseWriteType.Upsert, MacAddress = mac, IpAddress = IPAddress.Parse(ip), Hostname = host,
        StartTime = DateTime.UtcNow, EndTime = DateTime.UtcNow.AddHours(1),
    };

    private static LeaseWriteOperation Del(string mac) => new()
        { Type = LeaseWriteType.Delete, MacAddress = mac, IpAddress = IPAddress.Any };

    private async Task FlushAsync(params LeaseWriteOperation[] ops)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var batch = new NpgsqlBatch(conn);
        foreach (var c in LeaseCache.SetBasedCommands(ops)) batch.BatchCommands.Add(c);
        await batch.ExecuteNonQueryAsync();
    }

    [Fact]
    public async Task OneFlush_WithTheSameMacSeveralTimes_LastOperationWins_AndDoesNotFail()
    {
        // In ONE statement ON CONFLICT can't touch a row twice — without coalescing this threw
        // "ON CONFLICT DO UPDATE command cannot affect row a second time".
        await FlushAsync(
            Up("aa:bb:cc:dd:ee:10", "10.60.0.20", "first"),
            Up("aa:bb:cc:dd:ee:10", "10.60.0.21", "renewed"),   // two renewals → the later one
            Up("aa:bb:cc:dd:ee:11", "10.60.0.22"),
            Del("AA:BB:CC:DD:EE:11"),                            // upsert then release → gone (any MAC case)
            Del("aa:bb:cc:dd:ee:12"),
            Up("aa:bb:cc:dd:ee:12", "10.60.0.23", "back"));      // release then renew → present

        Assert.Equal(("10.60.0.21", (string?)"renewed"), await RowAsync("aa:bb:cc:dd:ee:10"));
        Assert.Null(await RowAsync("aa:bb:cc:dd:ee:11"));
        Assert.Equal(("10.60.0.23", (string?)"back"), await RowAsync("aa:bb:cc:dd:ee:12"));
    }

    [Fact]
    public async Task OneFlush_OfAHundredLeases_PersistsThemAll_AsTwoCommandsAtMost()
    {
        var ops = Enumerable.Range(0, 100)
            .Select(i => Up($"02:00:00:00:00:{i:x2}", $"10.61.0.{i + 1}", i % 2 == 0 ? null : $"h{i}"))
            .ToArray();
        Assert.Single(LeaseCache.SetBasedCommands(ops));        // one INSERT … unnest, not 100

        await FlushAsync(ops);

        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand("SELECT count(*) FROM dhcp_leases WHERE host(ip_address) LIKE '10.61.0.%'", conn);
        Assert.Equal(100L, await cmd.ExecuteScalarAsync());
        Assert.Equal(("10.61.0.2", (string?)"h1"), await RowAsync("02:00:00:00:00:01"));
        Assert.Equal(("10.61.0.1", (string?)null), await RowAsync("02:00:00:00:00:00"));
    }
}
