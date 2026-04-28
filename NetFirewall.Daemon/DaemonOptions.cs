namespace NetFirewall.Daemon;

/// <summary>
/// Configuration for the daemon. Bound from the <c>Daemon</c> section of
/// <c>appsettings.json</c> + environment overrides.
/// </summary>
public sealed class DaemonOptions
{
    public const string SectionName = "Daemon";

    /// <summary>Absolute or repo-relative path to the Unix socket.</summary>
    public string SocketPath { get; set; } = "./var/run/netfirewall.sock";

    /// <summary>
    /// Octal mode applied to the socket file after creation. <c>0660</c> in
    /// production (root + netfirewall group). In dev we leave it at <c>0600</c>
    /// (current user only) so testing on macOS / single-user setups doesn't
    /// require fiddling with groups.
    /// </summary>
    public string SocketMode { get; set; } = "0660";

    /// <summary>
    /// Legacy single-UID gate. When set, the daemon accepts connections from
    /// this UID. Kept for backwards-compat — <see cref="AcceptedPeerUids"/>
    /// supersedes it for new deployments. If both are set, a peer is accepted
    /// when it matches EITHER. <c>null</c> = no single-UID restriction.
    /// </summary>
    public int? ExpectedPeerUid { get; set; }

    /// <summary>
    /// List of UIDs allowed to connect. Production deployments populate this
    /// with the Web user's UID AND root (0) so the TUI invoked via <c>sudo</c>
    /// can reach the socket. Empty / null = no list-based restriction.
    /// If both <see cref="ExpectedPeerUid"/> and this list are unset, the
    /// daemon accepts any peer (DEV ONLY — combine with 0600 socket mode so
    /// only the running user can connect).
    /// </summary>
    public int[]? AcceptedPeerUids { get; set; }

    /// <summary>
    /// HTTP header carrying the Web's session cookie value for per-request
    /// authentication. The daemon validates it against <c>user_sessions</c>.
    /// </summary>
    public string SessionHeader { get; set; } = "X-NetFw-Session";
}
