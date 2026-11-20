using NetFirewall.Services.Settings;

namespace NetFirewall.Web.Theming;

/// <summary>
/// Reads the <c>nf_ui</c> cookie over <c>appearance.default_theme</c> / <c>appearance.default_mode</c>
/// from <see cref="IAppSettingsService"/> (cached by that service). A stored default that is no
/// longer a preset (the old palette names) falls back to <see cref="Appearance.Default"/>.
/// </summary>
public sealed class AppearanceProvider(IHttpContextAccessor http, IAppSettingsService settings) : IAppearanceProvider
{
    public async Task<Appearance> GetAsync(CancellationToken ct = default)
    {
        var defaults = await GetDefaultsAsync(ct);
        var cookie = http.HttpContext?.Request.Cookies[Appearance.CookieName];
        return Appearance.FromCookie(cookie, defaults);
    }

    public async Task<Appearance> GetDefaultsAsync(CancellationToken ct = default)
    {
        var preset = await settings.GetStringAsync("appearance.default_theme", ct);
        var mode = await settings.GetStringAsync("appearance.default_mode", ct);
        var d = Appearance.Default;
        return d with
        {
            Preset = preset is not null && Appearance.Presets.Contains(preset) ? preset : d.Preset,
            Mode = mode is not null && Appearance.Modes.Contains(mode) ? mode : d.Mode,
        };
    }
}
