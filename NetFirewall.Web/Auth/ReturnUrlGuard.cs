namespace NetFirewall.Web.Auth;

/// <summary>
/// Validates post-login <c>returnUrl</c> values so a session-expiry redirect
/// never lands the user on a partial-only endpoint (which would render bare
/// HTML with no layout, or raw JSON, in the browser).
///
/// Two failure shapes this guards against:
///   1. HTMX polling endpoints (e.g. <c>/Home/Throughput</c>) that fire while
///      the page is open. When the session expires the handler's challenge
///      stores their path as <c>returnUrl</c>; after re-login the redirect
///      then lands on the partial.
///   2. Plain <c>fetch()</c> calls from Alpine helpers (liveSparkline /
///      liveStat) that hit JSON endpoints (<c>/Home/ThroughputSeries</c>,
///      <c>/Home/SystemSeries</c>) without HTMX headers. Same outcome.
/// </summary>
public static class ReturnUrlGuard
{
    private static readonly string[] PartialOnlyPrefixes =
    {
        "/Home/Throughput",
        "/Home/ThroughputSeries",
        "/Home/TopDestinations",
        "/Home/SystemSeries",
    };

    private static readonly string[] NonNavigablePaths =
    {
        "/logout",
    };

    /// <summary>
    /// Returns <paramref name="url"/> if it is a safe local path that points
    /// at a full page; otherwise returns <c>"/"</c>. Safe means: non-empty,
    /// starts with a single <c>/</c> (rejects protocol-relative <c>//host</c>
    /// open-redirects), does not start with <c>/login</c>, and is not one of
    /// the known partial-only / JSON polling endpoints.
    /// </summary>
    public static string Sanitize(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return "/";
        if (!url.StartsWith('/') || url.StartsWith("//")) return "/";
        if (url.StartsWith("/login", StringComparison.OrdinalIgnoreCase)) return "/";

        var pathOnly = url;
        var queryIdx = pathOnly.IndexOf('?');
        if (queryIdx >= 0) pathOnly = pathOnly[..queryIdx];

        foreach (var prefix in PartialOnlyPrefixes)
        {
            if (pathOnly.Equals(prefix, StringComparison.OrdinalIgnoreCase)) return "/";
        }

        // POST-only endpoints can't be navigated to with GET — re-bouncing
        // there after login yields 405 Method Not Allowed. Most common case:
        // the session expires just as the user clicks Sign out, so the
        // challenge stores /logout as returnUrl.
        foreach (var path in NonNavigablePaths)
        {
            if (pathOnly.Equals(path, StringComparison.OrdinalIgnoreCase)) return "/";
        }

        return url;
    }
}
