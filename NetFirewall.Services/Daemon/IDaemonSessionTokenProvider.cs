namespace NetFirewall.Services.Daemon;

/// <summary>
/// Source of the per-call session token that <see cref="DaemonClient"/> forwards
/// to the daemon via the <c>X-NetFw-Session</c> header. Abstracts the
/// "where do I get the current user's session" question so the same client
/// works from any host:
///
/// <list type="bullet">
///   <item><b>Web</b> — reads it out of the inbound request's <c>__Host-NetFw</c>
///   cookie via <c>IHttpContextAccessor</c>.</item>
///   <item><b>TUI</b> — holds the token in memory after a local login (or
///   returns null when relying on peer-cred auth on the daemon side).</item>
///   <item><b>Background services</b> — return null; auth-protected endpoints
///   then return 401 and the caller surfaces the error rather than mutating
///   on behalf of "no one".</item>
/// </list>
/// </summary>
public interface IDaemonSessionTokenProvider
{
    /// <summary>
    /// Current session token, or null when no session is available. Null
    /// causes the client to omit the session header entirely; the daemon
    /// then evaluates the request against its anonymous policy (today: only
    /// <c>/health</c> is reachable that way).
    /// </summary>
    string? GetCurrentToken();
}

/// <summary>
/// Trivial provider that always returns null — daemon will receive no
/// session header. Useful for hosts that only need the read-only / probe
/// surface (e.g. background workers checking <c>IsAliveAsync</c>) and for
/// TUI sessions that haven't logged in yet.
/// </summary>
public sealed class NullDaemonSessionTokenProvider : IDaemonSessionTokenProvider
{
    public string? GetCurrentToken() => null;
}
