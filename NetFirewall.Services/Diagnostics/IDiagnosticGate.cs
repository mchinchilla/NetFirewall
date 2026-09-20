namespace NetFirewall.Services.Diagnostics;

/// <summary>
/// Per-family concurrency limiter for tools that spawn processes. Diagnostics
/// are operator-triggered and cheap individually, but the daemon unit runs with
/// <c>TasksMax=128</c> and one click-happy operator (or a stuck browser retry)
/// must not be able to fork-bomb the box. Busy attempts are refused, not queued —
/// the UI tells the operator a run is already in progress.
/// </summary>
public interface IDiagnosticGate
{
    /// <summary>Try to take a slot for <paramref name="family"/>. Dispose the lease to release it; <c>null</c> = family is at capacity.</summary>
    IDisposable? TryEnter(string family);
}

/// <summary>Gate families and their slot counts (see <see cref="DiagnosticGate"/>).</summary>
public static class DiagFamilies
{
    public const string Doctor    = "doctor";
    public const string Ping      = "ping";
    public const string Route     = "route";
    public const string Conntrack = "conntrack";
    public const string Journal   = "journal";
    public const string Probe     = "probe";
    public const string Iface     = "iface";
}
