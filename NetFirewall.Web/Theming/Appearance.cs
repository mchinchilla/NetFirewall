using System.Diagnostics.CodeAnalysis;

namespace NetFirewall.Web.Theming;

/// <summary>
/// The appearance axes: scheme mode, accent preset, sidebar state and density. Every axis is a
/// closed list — a value outside it never reaches the HTML. Persisted per browser in the
/// <c>nf_ui</c> cookie as <c>mode|preset|sidebar|density</c> (written by
/// <c>POST /preferences/appearance</c>, read by the layouts before first paint). Pure: no IO.
/// </summary>
public sealed record Appearance(string Mode, string Preset, string Sidebar, string Density)
{
    public const string CookieName = "nf_ui";

    public static IReadOnlyList<string> Modes { get; } = ["light", "dark", "system"];
    public static IReadOnlyList<string> Presets { get; } = ["teal", "coral", "blue", "violet", "sage", "amber", "rose", "graphite"];
    public static IReadOnlyList<string> Sidebars { get; } = ["expanded", "collapsed"];
    public static IReadOnlyList<string> Densities { get; } = ["comfortable", "compact"];

    public static Appearance Default { get; } = new("light", "teal", "expanded", "comfortable");

    /// <summary>Reads the cookie over <paramref name="fallback"/>; each missing or invalid axis keeps the fallback's value.</summary>
    public static Appearance FromCookie(string? cookie, Appearance fallback)
    {
        if (string.IsNullOrEmpty(cookie) || cookie.Length > 64) return fallback;
        var parts = cookie.Split('|');
        if (parts.Length > 4) return fallback;
        return new Appearance(
            Pick(parts, 0, Modes, fallback.Mode),
            Pick(parts, 1, Presets, fallback.Preset),
            Pick(parts, 2, Sidebars, fallback.Sidebar),
            Pick(parts, 3, Densities, fallback.Density));
    }

    public string ToCookie() => $"{Mode}|{Preset}|{Sidebar}|{Density}";

    /// <summary>The scheme to paint before JS runs; "system" starts light and site.js resolves it.</summary>
    public string ResolvedModeGuess => Mode == "dark" ? "dark" : "light";

    /// <summary>Changes one axis by name if the value is in that axis' catalogue.</summary>
    public bool TryWith(string axis, string? value, [NotNullWhen(true)] out Appearance? result)
    {
        result = (axis, value) switch
        {
            ("mode", { } v) when Modes.Contains(v) => this with { Mode = v },
            ("preset", { } v) when Presets.Contains(v) => this with { Preset = v },
            ("sidebar", { } v) when Sidebars.Contains(v) => this with { Sidebar = v },
            ("density", { } v) when Densities.Contains(v) => this with { Density = v },
            _ => null,
        };
        return result is not null;
    }

    private static string Pick(string[] parts, int index, IReadOnlyList<string> allowed, string fallback) =>
        index < parts.Length && allowed.Contains(parts[index]) ? parts[index] : fallback;
}
