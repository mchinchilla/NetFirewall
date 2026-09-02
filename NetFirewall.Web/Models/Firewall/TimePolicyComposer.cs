using NetFirewall.Models.Firewall;

namespace NetFirewall.Web.Models.Firewall;

/// <summary>
/// Turns a time-policy form into the filter rule the generator understands.
/// Both modes are a DROP: "allow during the window" inverts the schedule so
/// the drop is live <em>outside</em> it; "block during" uses the window as-is.
/// Priority defaults to 2 so the drop sits before the established-allow
/// (typically priority 3) and existing streams actually stop.
/// </summary>
public static class TimePolicyComposer
{
    public const int DefaultPriority = 2;
    public const string LogPrefix = FwFilterRule.TimeLimitLogPrefix;

    public static FwFilterRule Compose(TimePolicyFormViewModel form, string scheduleName)
    {
        if (form.ScheduleId is null)
            throw new ArgumentException("Pick a schedule.");
        var sources = FwArrayHelpers.Split(form.Sources)
                      ?? throw new ArgumentException("Pick at least one network object or address.");
        var allowDuring = string.Equals(form.Mode, "allow-during", StringComparison.OrdinalIgnoreCase);
        var who = string.Join(", ", sources);
        var desc = string.IsNullOrWhiteSpace(form.Description)
            ? (allowDuring
                ? $"Time limit · allow {who} during {scheduleName}"
                : $"Time limit · block {who} during {scheduleName}")
            : form.Description.Trim();

        return new FwFilterRule
        {
            Chain = form.Chain,
            Action = "drop",
            Description = desc,
            SourceAddresses = sources,
            ScheduleId = form.ScheduleId.Value,
            ScheduleInvert = allowDuring,
            Priority = form.Priority,
            Enabled = form.Enabled,
            LogPrefix = LogPrefix
        };
    }

    /// <summary>
    /// Same schedule + chain + invert + sources. Used to update-in-place
    /// instead of inserting another TIME-LIMIT drop every time Apply is clicked.
    /// </summary>
    public static bool SamePolicy(FwFilterRule a, FwFilterRule b)
    {
        if (a.ScheduleId != b.ScheduleId) return false;
        if (!string.Equals(a.Chain, b.Chain, StringComparison.OrdinalIgnoreCase)) return false;
        if (a.ScheduleInvert != b.ScheduleInvert) return false;
        if (!string.Equals(a.LogPrefix ?? "", b.LogPrefix ?? "", StringComparison.Ordinal)) return false;
        return SameSources(a.SourceAddresses, b.SourceAddresses);
    }

    private static bool SameSources(string[]? a, string[]? b)
    {
        var left = Normalize(a);
        var right = Normalize(b);
        return left.SetEquals(right);
    }

    private static HashSet<string> Normalize(string[]? values) =>
        new((values ?? Array.Empty<string>())
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim()),
            StringComparer.OrdinalIgnoreCase);
}
