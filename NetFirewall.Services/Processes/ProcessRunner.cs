using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace NetFirewall.Services.Processes;

public sealed class ProcessRunner : IProcessRunner
{
    private readonly ILogger<ProcessRunner> _logger;

    public ProcessRunner(ILogger<ProcessRunner> logger) => _logger = logger;

    public async Task<ProcessResult> RunAsync(
        string fileName,
        string arguments,
        TimeSpan? timeout = null,
        CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        _logger.LogDebug("exec: {File} {Args}", fileName, arguments);

        try
        {
            using var process = Process.Start(psi);
            if (process == null)
                return new ProcessResult(-1, string.Empty, "Failed to start process");

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            if (timeout.HasValue) linkedCts.CancelAfter(timeout.Value);

            var stdoutTask = process.StandardOutput.ReadToEndAsync(linkedCts.Token);
            var stderrTask = process.StandardError.ReadToEndAsync(linkedCts.Token);

            try
            {
                await process.WaitForExitAsync(linkedCts.Token);
            }
            catch (OperationCanceledException)
            {
                try { process.Kill(entireProcessTree: true); } catch { /* best effort */ }
                throw;
            }

            var output = await stdoutTask;
            var error = await stderrTask;

            if (process.ExitCode != 0)
            {
                _logger.LogWarning(
                    "exec failed: {File} {Args} → exit {Code}, stderr={Stderr}",
                    fileName, arguments, process.ExitCode, error.Trim());
            }

            return new ProcessResult(process.ExitCode, output, error);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Failed to run {File} {Args}", fileName, arguments);
            return new ProcessResult(-1, string.Empty, ex.Message);
        }
    }
}
