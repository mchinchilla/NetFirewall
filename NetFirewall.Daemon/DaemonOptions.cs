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
    /// When set, the daemon refuses connections whose peer UID is anything
    /// other than this. <c>null</c> = accept any peer (DEV ONLY — combine with
    /// 0600 mode so only the running user can connect).
    /// </summary>
    public int? ExpectedPeerUid { get; set; }

    /// <summary>
    /// HTTP header carrying the Web's session cookie value for per-request
    /// authentication. The daemon validates it against <c>user_sessions</c>.
    /// </summary>
    public string SessionHeader { get; set; } = "X-NetFw-Session";
}
