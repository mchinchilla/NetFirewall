namespace NetFirewall.Services.Daemon;

/// <summary>
/// Configuration for the daemon client. Bound from the <c>Daemon</c>
/// section of any host's appsettings (Web, TUI, background workers).
/// </summary>
public sealed class DaemonClientOptions
{
    public const string SectionName = "Daemon";

    /// <summary>
    /// When false, the host bypasses the daemon and runs OS mutations in-process
    /// (the legacy Web path). Useful for dev environments without socket plumbing.
    /// Default <c>true</c>; flip to false in <c>appsettings.Development.json</c> if needed.
    /// The TUI ignores this flag — it always talks to the daemon (its whole reason for existing).
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Path to the daemon's Unix socket (must match the daemon's <c>SocketPath</c>).</summary>
    public string SocketPath { get; set; } = "./var/run/netfirewall.sock";

    /// <summary>HTTP header name used to relay the caller's session token to the daemon.</summary>
    public string SessionHeader { get; set; } = "X-NetFw-Session";

    /// <summary>Per-request timeout. Apply ops can take a few seconds (ifup waits).</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// When true (default) the host proxies TOTP encrypt/decrypt to the daemon so
    /// the master key never lives in this process. Set to false only if you're
    /// running without a daemon (dev) — then the key has to live in the host's env
    /// and a host compromise can decrypt all stored TOTP secrets.
    /// </summary>
    public bool UseForTotp { get; set; } = true;
}
