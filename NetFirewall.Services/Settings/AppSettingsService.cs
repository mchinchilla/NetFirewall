using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace NetFirewall.Services.Settings;

public sealed class AppSettingsService : IAppSettingsService
{
    private readonly NpgsqlDataSource _ds;
    private readonly ILogger<AppSettingsService> _logger;
    private readonly ConcurrentDictionary<string, string> _cache = new();
    private bool _cacheLoaded;
    private readonly SemaphoreSlim _loadGate = new(1, 1);

    public AppSettingsService(NpgsqlDataSource ds, ILogger<AppSettingsService> logger)
    {
        _ds = ds;
        _logger = logger;
    }

    public async Task<IReadOnlyList<AppSettingValue>> GetAllAsync(CancellationToken ct = default)
    {
        await EnsureLoadedAsync(ct);
        return AppSettingDescriptors.All
            .Select(d => _cache.TryGetValue(d.Key, out var v)
                ? new AppSettingValue(d, v, IsDefault: false)
                : new AppSettingValue(d, d.DefaultValue, IsDefault: true))
            .ToList();
    }

    public async Task<string> GetStringAsync(string key, CancellationToken ct = default)
    {
        await EnsureLoadedAsync(ct);
        if (_cache.TryGetValue(key, out var v)) return v;
        return AppSettingDescriptors.Find(key)?.DefaultValue ?? string.Empty;
    }

    public async Task<int> GetIntAsync(string key, CancellationToken ct = default)
    {
        var s = await GetStringAsync(key, ct);
        return int.TryParse(s, out var n) ? n
             : int.TryParse(AppSettingDescriptors.Find(key)?.DefaultValue, out var d) ? d
             : 0;
    }

    public async Task<bool> GetBoolAsync(string key, CancellationToken ct = default)
    {
        var s = await GetStringAsync(key, ct);
        return bool.TryParse(s, out var b) ? b
             : bool.TryParse(AppSettingDescriptors.Find(key)?.DefaultValue, out var d) && d;
    }

    public async Task SetAsync(string key, string value, string? updatedBy, CancellationToken ct = default)
    {
        var desc = AppSettingDescriptors.Find(key)
            ?? throw new ArgumentException($"Unknown setting key '{key}'.", nameof(key));

        ValidateValue(desc, value);

        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            @"INSERT INTO app_settings (key, value, updated_at, updated_by)
              VALUES (@k, @v, NOW(), @u)
              ON CONFLICT (key) DO UPDATE
                  SET value = EXCLUDED.value,
                      updated_at = EXCLUDED.updated_at,
                      updated_by = EXCLUDED.updated_by", conn);
        cmd.Parameters.AddWithValue("k", key);
        cmd.Parameters.AddWithValue("v", value);
        cmd.Parameters.AddWithValue("u", (object?)updatedBy ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);

        _cache[key] = value;
        _logger.LogInformation("Setting {Key} updated by {User}", key, updatedBy ?? "(unknown)");
    }

    private static void ValidateValue(AppSettingDescriptor desc, string value)
    {
        switch (desc.Type)
        {
            case AppSettingType.Int:
                if (!int.TryParse(value, out _))
                    throw new ArgumentException($"'{desc.Label}' must be an integer.");
                break;
            case AppSettingType.Bool:
                if (!bool.TryParse(value, out _))
                    throw new ArgumentException($"'{desc.Label}' must be true or false.");
                break;
            case AppSettingType.Enum:
                if (desc.AllowedValues is null || !desc.AllowedValues.Contains(value))
                    throw new ArgumentException($"'{desc.Label}' must be one of: {string.Join(", ", desc.AllowedValues ?? [])}.");
                break;
            case AppSettingType.String:
                // anything goes — the descriptor doesn't constrain length here yet
                break;
        }
    }

    private async Task EnsureLoadedAsync(CancellationToken ct)
    {
        if (_cacheLoaded) return;
        await _loadGate.WaitAsync(ct);
        try
        {
            if (_cacheLoaded) return;
            await using var conn = await _ds.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand("SELECT key, value FROM app_settings", conn);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                _cache[reader.GetString(0)] = reader.GetString(1);
            }
            _cacheLoaded = true;
        }
        catch (PostgresException ex) when (ex.SqlState == "42P01") // undefined_table
        {
            _logger.LogWarning("app_settings table missing — using descriptor defaults. Run migration 13.");
            _cacheLoaded = true; // don't keep retrying every call
        }
        finally
        {
            _loadGate.Release();
        }
    }
}
