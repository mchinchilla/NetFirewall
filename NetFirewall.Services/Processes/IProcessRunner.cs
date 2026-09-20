namespace NetFirewall.Services.Processes;

/// <summary>
/// Abstraction over <c>System.Diagnostics.Process.Start</c> so every process spawn
/// is mockable, replaceable, and centrally logged. Required by project rule #8 —
/// services that shell out (network writers, nft applier, distro probes) must take
/// this dependency instead of calling <c>Process.Start</c> directly.
/// </summary>
public interface IProcessRunner
{
    /// <summary>Run a command and capture stdout/stderr.</summary>
    /// <param name="fileName">Executable name (resolved via PATH) or absolute path.</param>
    /// <param name="arguments">Argument string passed verbatim.</param>
    /// <param name="timeout">Optional timeout. <c>null</c> waits forever.</param>
    /// <param name="ct">Cancellation token; on cancel the child process is killed.</param>
    Task<ProcessResult> RunAsync(
        string fileName,
        string arguments,
        TimeSpan? timeout = null,
        CancellationToken ct = default);

    /// <summary>
    /// Run a command with an explicit argument vector — no shell, no quoting.
    /// Every element reaches the child verbatim through
    /// <see cref="System.Diagnostics.ProcessStartInfo.ArgumentList"/>, so a value
    /// that came from a user can never be re-split into extra arguments or read
    /// as shell syntax. This is the ONLY overload the Diagnostics tools may use
    /// (a source-lint test in NetFirewall.Tests enforces it).
    /// </summary>
    Task<ProcessResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        TimeSpan? timeout = null,
        CancellationToken ct = default);

    /// <summary>
    /// Start a long-running command and read its stdout as it arrives, instead of
    /// buffering everything until exit. For tools that never stop on their own and
    /// are terminated by the caller (<c>nft monitor trace</c>). Same argument-vector
    /// safety as the overload above. The caller MUST dispose the returned handle,
    /// which terminates the process.
    /// </summary>
    IRunningProcess Start(string fileName, IReadOnlyList<string> arguments, CancellationToken ct = default);
}

public readonly record struct ProcessResult(int ExitCode, string Output, string Error)
{
    public bool Success => ExitCode == 0;
}
