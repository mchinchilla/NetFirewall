namespace NetFirewall.Services.Diagnostics;

/// <summary>
/// Daemon-side knobs for the Diagnostics tools (bound from the <c>Diagnostics</c>
/// configuration section). Operator-tunable values that should change without a
/// restart live in app settings instead (<c>diagnostics.*</c> keys in
/// <see cref="Settings.AppSettingDescriptors"/>).
///
/// SHELL SAFETY: every tool in this namespace spawns processes through
/// <see cref="Processes.IProcessRunner.RunAsync(string, IReadOnlyList{string}, TimeSpan?, CancellationToken)"/>
/// — the argument-VECTOR overload. Interpolating a request value into the
/// string overload is forbidden; <c>NoInterpolatedProcessArgsTest</c> fails the
/// build if it sees one.
/// </summary>
public sealed class DiagnosticsOptions
{
    public const string SectionName = "Diagnostics";

    public string PingPath        { get; set; } = "ping";
    public string TraceroutePath  { get; set; } = "traceroute";
    public string IpPath          { get; set; } = "ip";
    public string ConntrackPath   { get; set; } = "conntrack";
    public string JournalctlPath  { get; set; } = "journalctl";
    public string WgPath          { get; set; } = "wg";
    public string NftPath         { get; set; } = "/usr/sbin/nft";
    public string TcpdumpPath     { get; set; } = "tcpdump";
    public string TimeoutPath     { get; set; } = "timeout";

    /// <summary>
    /// Where capture pcaps are written. Must stay inside the unit's ReadWritePaths
    /// (/var/lib/netfirewall) — PrivateTmp=yes makes /tmp useless for artifacts the
    /// Web has to hand back.
    /// </summary>
    public string CaptureDirectory { get; set; } = "/var/lib/netfirewall/daemon/captures";

    /// <summary>Wall-clock budget for a whole doctor run. Must stay under the daemon client's 30 s timeout.</summary>
    public int DoctorBudgetSeconds { get; set; } = 25;

    /// <summary>Per-check budget inside a doctor run; a check past it is reported as Skip ("timed out").</summary>
    public int CheckTimeoutSeconds { get; set; } = 6;

    /// <summary>How many checks may spawn processes concurrently (TasksMax=128 on the unit).</summary>
    public int DoctorParallelism { get; set; } = 4;

    public int MaxJournalLines { get; set; } = 2000;

    /// <summary>Raw command output kept as evidence is cut here (the rest is dropped with Truncated=true).</summary>
    public int MaxEvidenceBytes { get; set; } = 64 * 1024;
}
