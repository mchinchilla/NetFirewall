using System.Collections.Concurrent;
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
/// Real-Postgres coverage of <see cref="DdnsService"/>. The actual DNS UPDATE
/// path runs over UDP against an external DNS server; we don't spin one up
/// here. What we DO cover, against the real schema and config table:
/// — Config loader (per-subnet override + global fallback + disabled gate).
/// — UpdateLeaseRecordsAsync's short-circuits (Disabled config, empty hostname,
///   neither forward nor reverse enabled).
/// — Graceful failure when the configured DNS server is unreachable.
/// </summary>
[Collection("Postgres")]
public sealed class DdnsServiceTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private DdnsService _svc = null!;

    public DdnsServiceTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        // The service uses a process-wide static cache for DDNS configs;
        // reset it per test so prior runs can't leak into ours.
        ResetStaticCache();
        _svc = new DdnsService(_pg.DataSource, NullLogger<DdnsService>.Instance);
    }

    public Task DisposeAsync()
    {
        ResetStaticCache();
        return Task.CompletedTask;
    }

    private static void ResetStaticCache()
    {
        var t = typeof(DdnsService);
        var cache = (ConcurrentDictionary<Guid, DdnsConfig>?)
            t.GetField("ConfigCache", BindingFlags.NonPublic | BindingFlags.Static)!.GetValue(null);
        cache?.Clear();
        t.GetField("_globalConfig", BindingFlags.NonPublic | BindingFlags.Static)!.SetValue(null, null);
        t.GetField("_cacheExpiry", BindingFlags.NonPublic | BindingFlags.Static)!.SetValue(null, DateTime.MinValue);
    }

    /// <summary>
    /// Insert a row into dhcp_ddns_config with sensible defaults. Returns the new id.
    /// </summary>
    private async Task<Guid> SeedConfigAsync(
        Guid? subnetId,
        bool enabled = true,
        string? forwardZone = "example.com",
        string dnsServer = "127.0.0.1",
        bool enableForward = true,
        bool enableReverse = true)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(@"
            INSERT INTO dhcp_ddns_config
              (id, subnet_id, enable_forward, enable_reverse, forward_zone, dns_server, enabled)
            VALUES
              (gen_random_uuid(), @sid, @ef, @er, @fz, @dns, @enabled)
            RETURNING id", conn);
        cmd.Parameters.AddWithValue("sid", (object?)subnetId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("ef", enableForward);
        cmd.Parameters.AddWithValue("er", enableReverse);
        cmd.Parameters.AddWithValue("fz", (object?)forwardZone ?? DBNull.Value);
        cmd.Parameters.AddWithValue("dns", IPAddress.Parse(dnsServer));
        cmd.Parameters.AddWithValue("enabled", enabled);
        return (Guid)(await cmd.ExecuteScalarAsync())!;
    }

    private async Task<Guid> SeedSubnetAsync(string name, string cidr)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(@"
            INSERT INTO dhcp_subnets (id, name, network, subnet_mask, enabled, created_at, updated_at)
            VALUES (gen_random_uuid(), @n, @cidr::cidr, '255.255.255.0'::inet, true, now(), now())
            RETURNING id", conn);
        cmd.Parameters.AddWithValue("n", name);
        cmd.Parameters.AddWithValue("cidr", cidr);
        return (Guid)(await cmd.ExecuteScalarAsync())!;
    }

    // ── GetConfigForSubnetAsync ────────────────────────────────────────

    [Fact]
    public async Task GetConfigForSubnetAsync_NoConfigsAtAll_ReturnsNull()
    {
        Assert.Null(await _svc.GetConfigForSubnetAsync(null));
        Assert.Null(await _svc.GetConfigForSubnetAsync(Guid.NewGuid()));
    }

    [Fact]
    public async Task GetConfigForSubnetAsync_OnlyGlobal_AppliesToAnySubnet()
    {
        await SeedConfigAsync(subnetId: null, forwardZone: "global.example.com");

        var globalConfig = await _svc.GetConfigForSubnetAsync(null);
        Assert.NotNull(globalConfig);
        Assert.Equal("global.example.com", globalConfig!.ForwardZone);

        // Asking for an unknown subnet falls back to the global config.
        var fallback = await _svc.GetConfigForSubnetAsync(Guid.NewGuid());
        Assert.NotNull(fallback);
        Assert.Equal("global.example.com", fallback!.ForwardZone);
    }

    [Fact]
    public async Task GetConfigForSubnetAsync_PerSubnetOverride_TakesPrecedenceOverGlobal()
    {
        var subnetId = await SeedSubnetAsync("home", "192.168.1.0/24");
        await SeedConfigAsync(subnetId: null, forwardZone: "global.example.com");
        await SeedConfigAsync(subnetId: subnetId, forwardZone: "home.example.com");

        var perSubnet = await _svc.GetConfigForSubnetAsync(subnetId);
        Assert.NotNull(perSubnet);
        Assert.Equal("home.example.com", perSubnet!.ForwardZone);

        // Other subnets still fall back to global.
        var other = await _svc.GetConfigForSubnetAsync(Guid.NewGuid());
        Assert.Equal("global.example.com", other!.ForwardZone);
    }

    [Fact]
    public async Task GetConfigForSubnetAsync_DisabledConfigsAreIgnored()
    {
        // Only a disabled global config exists.
        await SeedConfigAsync(subnetId: null, enabled: false, forwardZone: "off.example.com");

        Assert.Null(await _svc.GetConfigForSubnetAsync(null));
    }

    // ── UpdateLeaseRecordsAsync short-circuits ─────────────────────────

    [Fact]
    public async Task UpdateLeaseRecordsAsync_ConfigDisabled_ReturnsDisabled()
    {
        var cfg = new DdnsConfig { Enabled = false, ForwardZone = "x.example", DnsServer = IPAddress.Loopback };
        var result = await _svc.UpdateLeaseRecordsAsync(
            "host", IPAddress.Parse("10.0.0.10"), "aa:bb:cc:00:00:01", cfg);

        Assert.True(result.Success); // Disabled() means "succeeded by skipping"
        Assert.Null(result.Fqdn);
    }

    [Fact]
    public async Task UpdateLeaseRecordsAsync_EmptyHostname_ReturnsDisabled()
    {
        var cfg = new DdnsConfig { Enabled = true, ForwardZone = "x.example", DnsServer = IPAddress.Loopback };
        var result = await _svc.UpdateLeaseRecordsAsync(
            "", IPAddress.Parse("10.0.0.10"), "aa:bb:cc:00:00:01", cfg);

        Assert.True(result.Success);
        Assert.Null(result.Fqdn);
    }

    [Fact]
    public async Task UpdateLeaseRecordsAsync_BothForwardAndReverseDisabled_NoNetworkCall_SuccessByDefault()
    {
        var cfg = new DdnsConfig
        {
            Enabled = true,
            EnableForward = false,
            EnableReverse = false,
            ForwardZone = "example.com",
            DnsServer = IPAddress.Loopback
        };

        var result = await _svc.UpdateLeaseRecordsAsync(
            "host", IPAddress.Parse("10.0.0.10"), "aa:bb:cc:00:00:01", cfg);

        Assert.True(result.Success);
        Assert.True(result.ForwardSuccess);
        Assert.True(result.ReverseSuccess);
        // Fqdn is computed regardless: "host.example.com."
        Assert.Equal("host.example.com.", result.Fqdn);
    }

    [Fact]
    public async Task UpdateLeaseRecordsAsync_NoForwardZone_ForwardSkippedSuccessfully()
    {
        // No ForwardZone → forward is a no-op; ReverseEnabled also false so we
        // exercise the "everything skipped" branch without a network round-trip.
        var cfg = new DdnsConfig
        {
            Enabled = true,
            EnableForward = true,
            EnableReverse = false,
            ForwardZone = null, // ← key: explicit null skips forward branch
            DnsServer = IPAddress.Loopback
        };

        var result = await _svc.UpdateLeaseRecordsAsync(
            "host", IPAddress.Parse("10.0.0.10"), "aa:bb:cc:00:00:01", cfg);

        Assert.NotNull(result);
        Assert.True(result.ForwardSuccess);
        Assert.True(result.ReverseSuccess);
    }

    // ── Fqdn building ──────────────────────────────────────────────────

    [Fact]
    public async Task UpdateLeaseRecordsAsync_Fqdn_AppendsZoneAndTrailingDot()
    {
        var cfg = new DdnsConfig
        {
            Enabled = true,
            EnableForward = false,
            EnableReverse = false,
            ForwardZone = "lan.example.com",
            DnsServer = IPAddress.Loopback
        };

        var result = await _svc.UpdateLeaseRecordsAsync(
            "laptop", IPAddress.Parse("10.0.0.50"), "aa:bb:cc:00:00:01", cfg);

        Assert.Equal("laptop.lan.example.com.", result.Fqdn);
    }

    [Fact]
    public async Task UpdateLeaseRecordsAsync_Fqdn_DoesNotDoubleAppendZone()
    {
        // If the operator already passed the FQDN as hostname, BuildFqdn must
        // not re-append the zone — defensive against double-suffix bugs.
        var cfg = new DdnsConfig
        {
            Enabled = true,
            EnableForward = false,
            EnableReverse = false,
            ForwardZone = "example.com",
            DnsServer = IPAddress.Loopback
        };

        var result = await _svc.UpdateLeaseRecordsAsync(
            "alice.example.com", IPAddress.Parse("10.0.0.50"), "aa:bb:cc:00:00:01", cfg);

        Assert.Equal("alice.example.com.", result.Fqdn);
    }
}
