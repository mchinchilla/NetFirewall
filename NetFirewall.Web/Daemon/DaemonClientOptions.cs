namespace NetFirewall.Web.Daemon;

/// <summary>
/// Web-side configuration for the daemon client. Bound from the
/// <c>Daemon</c> section of the Web's appsettings.
/// </summary>
public sealed class DaemonClientOptions
{
    public const string SectionName = "Daemon";

    /// <summary>
    /// When false, the Web bypasses the daemon and runs OS mutations in-process
    /// (the legacy path). Useful for dev environments without socket plumbing.
    /// Default <c>true</c>; flip to false in <c>appsettings.Development.json</c> if needed.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Path to the daemon's Unix socket (must match the daemon's <c>SocketPath</c>).</summary>
    public string SocketPath { get; set; } = "./var/run/netfirewall.sock";

    /// <summary>HTTP header name used to relay the Web's session cookie to the daemon.</summary>
    public string SessionHeader { get; set; } = "X-NetFw-Session";

    /// <summary>Per-request timeout. Apply ops can take a few seconds (ifup waits).</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
}
