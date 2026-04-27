namespace NetFirewall.Services.Settings;

/// <summary>
/// Read/write façade over the app_settings table. Settings are keyed by string
/// (matching <see cref="AppSettingDescriptor.Key"/>) and typed at the call site.
/// Reads are cached in-memory; <see cref="SetAsync"/> invalidates.
///
/// Lives in NetFirewall.Services so the daemon (collector + audit pruner) can
/// read settings the same way the Web does.
/// </summary>
public interface IAppSettingsService
{
    /// <summary>Every descriptor with its current effective value (DB or default).</summary>
    Task<IReadOnlyList<AppSettingValue>> GetAllAsync(CancellationToken ct = default);

    /// <summary>Effective string value for one key. Returns descriptor default if unset / unknown.</summary>
    Task<string> GetStringAsync(string key, CancellationToken ct = default);

    /// <summary>Effective int value. Returns descriptor default if unset, malformed, or unknown.</summary>
    Task<int> GetIntAsync(string key, CancellationToken ct = default);

    /// <summary>Effective bool value. "true"/"false" parsed case-insensitively.</summary>
    Task<bool> GetBoolAsync(string key, CancellationToken ct = default);

    /// <summary>
    /// Persist a value. Validates against the descriptor (type + allowed values).
    /// Throws ArgumentException on invalid input. <paramref name="updatedBy"/> is
    /// stamped on the row for audit.
    /// </summary>
    Task SetAsync(string key, string value, string? updatedBy, CancellationToken ct = default);
}

public sealed record AppSettingValue(AppSettingDescriptor Descriptor, string Value, bool IsDefault);
