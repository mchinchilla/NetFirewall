using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Services.Settings;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Settings;

/// <summary>
/// Real-Postgres coverage for <see cref="AppSettingsService"/>. Settings are
/// keyed by string and typed at the call site; the service hides the
/// descriptor-default fallback, type coercion, and the enum/int validation
/// that the UI relies on for "save" buttons not to push junk into prod.
/// </summary>
[Collection("Postgres")]
public sealed class AppSettingsServiceTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private AppSettingsService _svc = null!;

    // Pick stable real keys from the descriptor catalog.
    private const string IntKey = "dhcp.default_lease_seconds";   // Int, default "86400"
    private const string EnumKey = "appearance.default_theme";    // Enum, default "boulder"
    private const string StringKey = "vpn.public_endpoint";       // String, default ""

    public AppSettingsServiceTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _svc = new AppSettingsService(_pg.DataSource, NullLogger<AppSettingsService>.Instance);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<string?> RawValueAsync(string key)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand("SELECT value FROM app_settings WHERE key = @k", conn);
        cmd.Parameters.AddWithValue("k", key);
        return (string?)await cmd.ExecuteScalarAsync();
    }

    // ── defaults / fallbacks ───────────────────────────────────────────

    [Fact]
    public async Task GetStringAsync_UnknownKey_ReturnsEmpty()
    {
        Assert.Equal(string.Empty, await _svc.GetStringAsync("does.not.exist"));
    }

    [Fact]
    public async Task GetIntAsync_KeyUnsetInDb_FallsBackToDescriptorDefault()
    {
        Assert.Equal(86400, await _svc.GetIntAsync(IntKey));
    }

    [Fact]
    public async Task GetStringAsync_KeyUnsetInDb_FallsBackToDescriptorDefault()
    {
        Assert.Equal("boulder", await _svc.GetStringAsync(EnumKey));
    }

    [Fact]
    public async Task GetBoolAsync_UnparsableDefault_ReturnsFalse()
    {
        // "vpn.public_endpoint" is a string with default "" — bool fallback is false.
        Assert.False(await _svc.GetBoolAsync(StringKey));
    }

    // ── set + read-back (cache invalidation) ───────────────────────────

    [Fact]
    public async Task SetAsync_PersistsValue_AndCacheReflectsImmediately()
    {
        // Force a load so the cache is initialized.
        Assert.Equal(86400, await _svc.GetIntAsync(IntKey));

        await _svc.SetAsync(IntKey, "7200", updatedBy: "alice");

        // Cache reflects the new value without going to DB again.
        Assert.Equal(7200, await _svc.GetIntAsync(IntKey));
        Assert.Equal("7200", await RawValueAsync(IntKey));
    }

    [Fact]
    public async Task SetAsync_RecordsUpdatedBy_AndUpsertsOnSecondCall()
    {
        await _svc.SetAsync(StringKey, "vpn.example.com:51820", updatedBy: "alice");
        await _svc.SetAsync(StringKey, "vpn2.example.com:51820", updatedBy: "bob");

        // Second call upserts: only one row, latest value, latest updatedBy.
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT value, updated_by FROM app_settings WHERE key = @k", conn);
        cmd.Parameters.AddWithValue("k", StringKey);
        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal("vpn2.example.com:51820", reader.GetString(0));
        Assert.Equal("bob", reader.GetString(1));
        Assert.False(await reader.ReadAsync()); // exactly one row
    }

    // ── validation ─────────────────────────────────────────────────────

    [Fact]
    public async Task SetAsync_UnknownKey_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            _svc.SetAsync("does.not.exist", "x", updatedBy: null));
        Assert.Contains("Unknown setting key", ex.Message);
    }

    [Fact]
    public async Task SetAsync_IntKey_NonInteger_Throws()
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            _svc.SetAsync(IntKey, "not-a-number", updatedBy: null));
    }

    [Fact]
    public async Task SetAsync_EnumKey_DisallowedValue_Throws()
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            _svc.SetAsync(EnumKey, "rainbow-pony", updatedBy: null));
    }

    [Fact]
    public async Task SetAsync_EnumKey_AllowedValue_Persists()
    {
        // appearance.default_theme allowed values include "magic-mint" et al.
        // We don't hardcode them here — we look them up via the descriptor.
        var allowed = AppSettingDescriptors.Find(EnumKey)!.AllowedValues!;
        Assert.True(allowed.Length > 1);
        var newVal = allowed.First(v => v != "boulder"); // pick a non-default option

        await _svc.SetAsync(EnumKey, newVal, updatedBy: null);

        Assert.Equal(newVal, await _svc.GetStringAsync(EnumKey));
    }

    // ── GetAll: catalog + isDefault flag ───────────────────────────────

    [Fact]
    public async Task GetAllAsync_AllDescriptors_FlagsIsDefaultPerEntry()
    {
        // Override one setting; the rest should report IsDefault=true.
        await _svc.SetAsync(IntKey, "1234", updatedBy: null);

        var all = await _svc.GetAllAsync();

        Assert.Equal(AppSettingDescriptors.All.Count, all.Count);
        var overridden = all.Single(s => s.Descriptor.Key == IntKey);
        Assert.False(overridden.IsDefault);
        Assert.Equal("1234", overridden.Value);

        var pristineSample = all.Single(s => s.Descriptor.Key == StringKey);
        Assert.True(pristineSample.IsDefault);
    }

    // ── tolerance for missing app_settings table (pre-migration) ───────

    [Fact]
    public async Task GetStringAsync_AppSettingsTableMissing_ReturnsDefaults_NoCrash()
    {
        // Drop the table to simulate a pre-migration-13 environment.
        await using (var conn = await _pg.DataSource.OpenConnectionAsync())
        await using (var cmd = new NpgsqlCommand("DROP TABLE IF EXISTS app_settings CASCADE", conn))
            await cmd.ExecuteNonQueryAsync();

        // Fresh service so the cache hasn't been seeded yet.
        var freshSvc = new AppSettingsService(_pg.DataSource, NullLogger<AppSettingsService>.Instance);
        var v = await freshSvc.GetStringAsync(EnumKey);

        Assert.Equal("boulder", v); // descriptor default still served
    }
}
