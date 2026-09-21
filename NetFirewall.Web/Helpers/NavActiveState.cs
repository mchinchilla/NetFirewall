namespace NetFirewall.Web.Helpers;

/// <summary>
/// Which sidebar link is "here".
///
/// A link matches its own path and anything under it, so that /Firewall/Qos stays
/// lit while /Firewall/Qos/{id}/Classes is open. That prefix rule also means a
/// section index matches its own children: /Diagnostics ("All tools") lit up at
/// the same time as /Diagnostics/Vpn, so two items looked selected at once.
///
/// Inside a group, the longest match wins — only the most specific link is active.
/// Pure and static on purpose: the rule is worth a test, and it has no state.
/// </summary>
public static class NavActiveState
{
    /// <summary>The request path is this href, or a route beneath it.</summary>
    public static bool Matches(string? path, string? href)
    {
        if (string.IsNullOrEmpty(href) || href == "#") return false;
        path ??= "/";
        if (href == "/") return path == "/";
        return string.Equals(path, href, StringComparison.OrdinalIgnoreCase)
               || path.StartsWith(href + "/", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Active when this href matches and no sibling in <paramref name="group"/>
    /// matches more specifically. Pass the group's full href list; omit it for a
    /// standalone link that owns its whole subtree.
    /// </summary>
    public static bool IsActive(string? path, string? href, IReadOnlyList<string?>? group = null)
    {
        if (!Matches(path, href)) return false;
        if (group is null) return true;

        return !group.Any(other =>
            other is not null &&
            other.Length > href!.Length &&
            Matches(path, other));
    }

    /// <summary>Any link in the group matches — used to auto-open a collapsed section.</summary>
    public static bool AnyActive(string? path, IReadOnlyList<string?> group) =>
        group.Any(h => Matches(path, h));
}
