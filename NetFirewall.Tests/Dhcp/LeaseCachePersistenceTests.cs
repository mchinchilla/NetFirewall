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
}
