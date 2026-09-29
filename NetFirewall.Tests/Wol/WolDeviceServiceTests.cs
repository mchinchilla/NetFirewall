using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Models.Wol;
using NetFirewall.Services.Wol;
using NetFirewall.Tests.Infra;
using Npgsql;

namespace NetFirewall.Tests.Wol;

/// <summary>Real Postgres: migration 00042 applies, the CRUD round-trips, DHCP joins by MAC, search indexes the row.</summary>
[Collection("Postgres")]
public sealed class WolDeviceServiceTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private WolDeviceService _svc = null!;

    public WolDeviceServiceTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _svc = new WolDeviceService(_pg.DataSource, NullLogger<WolDeviceService>.Instance);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private static WolDevice Device(string name = "office-pc", string mac = "00-11-32-ab-cd-ef") =>
        new() { Name = name, MacAddress = mac, Interface = "ens256", Description = "  under the desk  " };

    private async Task ExecAsync(string sql)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(sql, conn);
        await cmd.ExecuteNonQueryAsync();
    }

    [Fact]
    public async Task Save_CreatesAndNormalises_ThenUpdates()
    {
        var created = await _svc.SaveAsync(Device());
        Assert.True(created.Success, created.Message);
        var d = created.Data!;
        Assert.NotEqual(Guid.Empty, d.Id);
        Assert.Equal("00:11:32:AB:CD:EF", d.MacAddress);
        Assert.Equal("under the desk", d.Description);
        Assert.Equal(WolDefaults.Port, d.Port);

        d.Name = "office-desktop";
        d.Port = 7;
        var updated = await _svc.SaveAsync(d);
        Assert.True(updated.Success, updated.Message);

        var all = await _svc.GetAllAsync();
        var only = Assert.Single(all);
        Assert.Equal("office-desktop", only.Name);
        Assert.Equal(7, only.Port);
    }

    [Fact]
    public async Task Save_RefusesDuplicateMacAndName_WithoutThrowing()
    {
        Assert.True((await _svc.SaveAsync(Device())).Success);

        var sameMac = await _svc.SaveAsync(Device(name: "other", mac: "001132ABCDEF"));
        Assert.False(sameMac.Success);
        Assert.Contains("already saved", sameMac.Message);

        var sameName = await _svc.SaveAsync(Device(name: "OFFICE-PC", mac: "00:11:32:00:00:01"));
        Assert.False(sameName.Success);
        Assert.Contains("already named", sameName.Message);
    }

    [Fact]
    public async Task Save_RefusesInvalidFields()
    {
        var bad = await _svc.SaveAsync(new WolDevice { Name = "x", MacAddress = "01:00:5E:00:00:FB", Interface = "ens256" });
        Assert.False(bad.Success);
        Assert.Empty(await _svc.GetAllAsync());
    }

    [Fact]
    public async Task Read_JoinsReservationFirst_ThenLease()
    {
        var d = (await _svc.SaveAsync(Device())).Data!;
        await ExecAsync("""
            INSERT INTO dhcp_leases (mac_address, ip_address, start_time, end_time, hostname)
            VALUES ('00:11:32:ab:cd:ef', '192.168.10.77', now() - interval '2 days', now() - interval '1 day', 'office-pc.lan')
            """);

        var viaLease = await _svc.GetByIdAsync(d.Id);
        Assert.Equal("192.168.10.77", viaLease!.KnownIp);
        Assert.Equal("office-pc.lan", viaLease.KnownHostname);

        await ExecAsync("INSERT INTO dhcp_mac_reservations (mac_address, reserved_ip) VALUES ('00:11:32:ab:cd:ef', '192.168.10.20')");
        Assert.Equal("192.168.10.20", (await _svc.GetByIdAsync(d.Id))!.KnownIp);
    }

    [Fact]
    public async Task MarkWoken_StampsTimeAndUser_AndDeleteRemoves()
    {
        var d = (await _svc.SaveAsync(Device())).Data!;
        Assert.Null(d.LastWokenAt);

        await _svc.MarkWokenAsync(d.Id, "marvin");
        var woken = await _svc.GetByIdAsync(d.Id);
        Assert.NotNull(woken!.LastWokenAt);
        Assert.Equal("marvin", woken.LastWokenBy);

        Assert.True(await _svc.DeleteAsync(d.Id));
        Assert.False(await _svc.DeleteAsync(d.Id));
        Assert.Null(await _svc.GetByIdAsync(d.Id));
    }

    [Fact]
    public async Task SearchIndex_FollowsTheRow()
    {
        var d = (await _svc.SaveAsync(Device())).Data!;

        await using (var conn = await _pg.DataSource.OpenConnectionAsync())
        await using (var cmd = new NpgsqlCommand(
            "SELECT count(*) FROM search_index WHERE entity_type = 'wol_device' AND tsv @@ to_tsquery('simple', '001132abcdef')", conn))
        {
            Assert.Equal(1L, await cmd.ExecuteScalarAsync());
        }

        await _svc.DeleteAsync(d.Id);
        await using (var conn = await _pg.DataSource.OpenConnectionAsync())
        await using (var cmd = new NpgsqlCommand("SELECT count(*) FROM search_index WHERE entity_type = 'wol_device'", conn))
        {
            Assert.Equal(0L, await cmd.ExecuteScalarAsync());
        }
    }
}
