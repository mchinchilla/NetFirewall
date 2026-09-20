using System.Diagnostics;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;

namespace NetFirewall.Services.Processes;

public sealed class ProcessRunner : IProcessRunner
{
    private readonly ILogger<ProcessRunner> _logger;

    public ProcessRunner(ILogger<ProcessRunner> logger) => _logger = logger;

    public Task<ProcessResult> RunAsync(
        string fileName,
        string arguments,
        TimeSpan? timeout = null,
        CancellationToken ct = default)
    {
        var psi = NewStartInfo(fileName);
        psi.Arguments = arguments;
        return RunCoreAsync(psi, fileName, arguments, timeout, ct);
    }

    public Task<ProcessResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        TimeSpan? timeout = null,
        CancellationToken ct = default)
    {
        var psi = NewStartInfo(fileName);
        foreach (var arg in arguments) psi.ArgumentList.Add(arg);
        // Joined for LOGGING only — the child receives the vector untouched.
        return RunCoreAsync(psi, fileName, string.Join(' ', arguments), timeout, ct);
    }

    private static ProcessStartInfo NewStartInfo(string fileName) => new()
    {
        FileName = fileName,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
        CreateNoWindow = true
    };

    public IRunningProcess Start(string fileName, IReadOnlyList<string> arguments, CancellationToken ct = default)
    {
        var psi = NewStartInfo(fileName);
        foreach (var arg in arguments) psi.ArgumentList.Add(arg);
        _logger.LogDebug("exec (streaming): {File} {Args}", fileName, string.Join(' ', arguments));
        return new RunningProcess(psi, fileName, _logger, ct);
    }

    private async Task<ProcessResult> RunCoreAsync(
        ProcessStartInfo psi, string fileName, string display, TimeSpan? timeout, CancellationToken ct)
    {
        _logger.LogDebug("exec: {File} {Args}", fileName, display);

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
                    fileName, display, process.ExitCode, error.Trim());
            }

            return new ProcessResult(process.ExitCode, output, error);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Failed to run {File} {Args}", fileName, display);
            return new ProcessResult(-1, string.Empty, ex.Message);
        }
    }

    /// <summary>
    /// Pumps stdout into a bounded channel. Bounded on purpose: a trace of a busy
    /// interface can outrun the consumer, and dropping old lines (counted, and
    /// surfaced as "truncated") is better than growing memory without limit inside
    /// the daemon.
    /// </summary>
    private sealed class RunningProcess : IRunningProcess
    {
        private const int Capacity = 4096;

        private readonly Process _process;
        private readonly Channel<string> _channel;
        private readonly TaskCompletionSource<int> _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly CancellationTokenRegistration _ctReg;
        private readonly ILogger _logger;
        private readonly string _fileName;
        private int _dropped;
        private int _stopped;

        public RunningProcess(ProcessStartInfo psi, string fileName, ILogger logger, CancellationToken ct)
        {
            _fileName = fileName;
            _logger = logger;
            _channel = Channel.CreateBounded<string>(new BoundedChannelOptions(Capacity)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
                SingleWriter = true,
            });

            _process = Process.Start(psi) ?? throw new InvalidOperationException($"Failed to start {fileName}");
            _ctReg = ct.Register(() => _ = StopAsync());
            _ = PumpAsync();
        }

        public ChannelReader<string> Output => _channel.Reader;
        public Task<int> Completion => _completion.Task;
        public int DroppedLines => Volatile.Read(ref _dropped);

        private async Task PumpAsync()
        {
            try
            {
                while (await _process.StandardOutput.ReadLineAsync() is { } line)
                {
                    if (!_channel.Writer.TryWrite(line)) Interlocked.Increment(ref _dropped);
                }
                await _process.WaitForExitAsync();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "streaming read of {File} ended", _fileName);
            }
            finally
            {
                _channel.Writer.TryComplete();
                var code = TryExitCode();
                _completion.TrySetResult(code);
            }
        }

        public async Task StopAsync(TimeSpan? grace = null)
        {
            if (Interlocked.Exchange(ref _stopped, 1) == 1) { await WaitQuietlyAsync(grace); return; }
            if (_process.HasExited) return;

            // SIGTERM first: tools that buffer output (and tcpdump's pcap writer)
            // only flush on a clean signal. .NET has no portable "send SIGTERM",
            // so shell out to kill(1) and fall back to SIGKILL.
            try
            {
                using var term = Process.Start(new ProcessStartInfo("kill", $"-TERM {_process.Id}") { UseShellExecute = false, CreateNoWindow = true });
                if (term is not null) await term.WaitForExitAsync();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "SIGTERM to {File} failed; escalating", _fileName);
            }

            await WaitQuietlyAsync(grace);
            if (!_process.HasExited)
            {
                try { _process.Kill(entireProcessTree: true); } catch { /* already gone */ }
            }
        }

        private async Task WaitQuietlyAsync(TimeSpan? grace)
        {
            try
            {
                using var cts = new CancellationTokenSource(grace ?? TimeSpan.FromSeconds(3));
                await _process.WaitForExitAsync(cts.Token);
            }
            catch (OperationCanceledException) { /* escalate in the caller */ }
            catch (Exception ex) { _logger.LogDebug(ex, "wait for {File} failed", _fileName); }
        }

        private int TryExitCode()
        {
            try { return _process.HasExited ? _process.ExitCode : -1; }
            catch { return -1; }
        }

        public async ValueTask DisposeAsync()
        {
            await StopAsync();
            _ctReg.Dispose();
            _process.Dispose();
        }
    }
}
