namespace NetFirewall.Web.Services;

public enum AppSettingType { String, Int, Bool, Enum }

/// <summary>
/// Static description of one tunable setting. The catalog lives in code so
/// adding a new setting is one line — no migration required. The DB only
/// stores values that differ from the descriptor's default.
/// </summary>
public sealed record AppSettingDescriptor(
    string Key,
    string Category,
    string Label,
    string? Description,
    AppSettingType Type,
    string DefaultValue,
    string[]? AllowedValues = null);

/// <summary>
/// THE catalog. Order within a category is preserved in the UI. Add new
/// settings here. Don't reuse a key — past values stay in <c>app_settings</c>
/// and would resurface unexpectedly.
/// </summary>
public static class AppSettingDescriptors
{
    public static readonly IReadOnlyList<AppSettingDescriptor> All = new AppSettingDescriptor[]
    {
        // ===== Appearance — defaults applied to anonymous / first-visit users =====
        new("appearance.default_theme", "Appearance",
            "Default palette",
            "Theme shown to anonymous users (login page) and as the default for new accounts.",
            AppSettingType.Enum, "boulder",
            ["boulder", "jordy-blue", "magic-mint", "taupe-gray", "twilight", "pearl-bush", "woodsmoke"]),

        new("appearance.default_mode", "Appearance",
            "Default mode",
            "Light or dark — applied before the user's local preference loads.",
            AppSettingType.Enum, "light",
            ["light", "dark"]),

        // ===== System identity =====
        new("system.firewall_name", "System",
            "Firewall display name",
            "Shown in the top bar and login system-info card. Defaults to OS hostname when empty.",
            AppSettingType.String, ""),

        // ===== DHCP defaults applied when creating a new subnet =====
        new("dhcp.default_lease_seconds", "DHCP defaults",
            "Default lease time (seconds)",
            "Pre-fill value for new subnets — 86400 = 24h.",
            AppSettingType.Int, "86400"),

        new("dhcp.default_dns_servers", "DHCP defaults",
            "Default DNS servers",
            "Comma-separated. Pre-filled for new subnets.",
            AppSettingType.String, "1.1.1.1, 8.8.8.8"),

        // ===== Monitoring — collector reads these on next sample tick =====
        new("monitoring.raw_retention_hours", "Monitoring",
            "Raw sample retention (hours)",
            "How long the 5-second samples stay in system_metrics. Hourly aggregates keep going.",
            AppSettingType.Int, "48"),

        new("monitoring.hourly_retention_days", "Monitoring",
            "Hourly aggregate retention (days)",
            "Drives the History tab's 7d view — increase for longer trend windows.",
            AppSettingType.Int, "30"),

        // ===== Audit log =====
        new("audit.retention_days", "Audit log",
            "Firewall audit retention (days)",
            "Older entries are pruned by the next maintenance pass. 0 = keep forever.",
            AppSettingType.Int, "365"),
    };

    public static AppSettingDescriptor? Find(string key) =>
        All.FirstOrDefault(d => d.Key == key);
}
