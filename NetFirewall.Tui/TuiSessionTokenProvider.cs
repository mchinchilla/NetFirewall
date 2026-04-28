using NetFirewall.Services.Daemon;

namespace NetFirewall.Tui;

/// <summary>
/// In-memory holder for the TUI's session token. Starts empty (anonymous —
/// only the daemon's <c>/health</c> probe is reachable that way). When the
/// user logs in via a future <c>LoginScreen</c>, the screen calls
/// <see cref="SetToken"/> with the issued session ID and subsequent daemon
/// calls authenticate as that user.
///
/// <para>Phase 2 will add a peer-cred path: the daemon detects the connecting
/// process's UID via <c>SO_PEERCRED</c> and skips the session check for
/// root / <c>netfirewall-tui</c> group. Until then, the TUI is anonymous-only.</para>
/// </summary>
public sealed class TuiSessionTokenProvider : IDaemonSessionTokenProvider
{
    private string? _token;
    private readonly Lock _gate = new();

    public string? GetCurrentToken()
    {
        lock (_gate) return _token;
    }

    public void SetToken(string? token)
    {
        lock (_gate) _token = token;
    }
}
