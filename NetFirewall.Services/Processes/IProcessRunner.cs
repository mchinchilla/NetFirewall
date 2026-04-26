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
}

public readonly record struct ProcessResult(int ExitCode, string Output, string Error)
{
    public bool Success => ExitCode == 0;
}
