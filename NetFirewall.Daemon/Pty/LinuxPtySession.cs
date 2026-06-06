using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using NetFirewall.Services.Processes;

namespace NetFirewall.Daemon.Pty;

/// <summary>
/// A live PTY + child. <see cref="Master"/> is a <see cref="FileStream"/> over the
/// master fd for async read/write. Teardown (dispose) sends SIGHUP then SIGKILL and
/// reaps the child, guaranteeing no detached root shell survives a dropped
/// WebSocket.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed class LinuxPtySession : IPtySession
{
    private readonly int _masterFd;
    private readonly FileStream _master;
    private readonly object _lock = new();
    private readonly TaskCompletionSource<int> _exited =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly CancellationTokenSource _reaperCts = new();
    private int _disposed;

    public LinuxPtySession(int masterFd, int pid)
    {
        _masterFd = masterFd;
        ProcessId = pid;
        // ownsHandle:false — we close the fd ourselves in dispose AFTER reaping,
        // so the FileStream finalizer can't race the close.
        _master = new FileStream(new SafeFileHandle((IntPtr)masterFd, ownsHandle: false),
            FileAccess.ReadWrite);
        // Poll-based reaper: a SIGCHLD handler would fight the .NET runtime, so we
        // waitpid(WNOHANG) on a background loop. Cheap (250ms) and the master-EOF
        // detection in the caller is the fast path; this just guarantees the child
        // is reaped and WaitForExitAsync completes even if no one reads the master.
        _ = Task.Run(ReaperLoopAsync);
    }

    public Stream Master => _master;
    public int ProcessId { get; }
    public bool HasExited => _exited.Task.IsCompleted;

    public void Resize(PtySize size)
    {
        if (HasExited) return;
        var win = new Native.Winsize { ws_row = size.Rows, ws_col = size.Cols };
        // Best-effort: a resize on a dying tty can fail benignly.
        Native.ioctl(_masterFd, Native.TIOCSWINSZ, ref win);
    }

    public Task<int> WaitForExitAsync(CancellationToken ct = default)
    {
        if (HasExited || !ct.CanBeCanceled) return _exited.Task;
        return _exited.Task.WaitAsync(ct);
    }

    private async Task ReaperLoopAsync()
    {
        try
        {
            while (!_reaperCts.IsCancellationRequested)
            {
                int rc = Native.waitpid(ProcessId, out int status, Native.WNOHANG);
                if (rc == ProcessId)
                {
                    _exited.TrySetResult(DecodeStatus(status));
                    return;
                }
                if (rc < 0) // ECHILD etc. — already reaped or gone.
                {
                    _exited.TrySetResult(-1);
                    return;
                }
                await Task.Delay(250, _reaperCts.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { /* disposing */ }
    }

    private static int DecodeStatus(int status)
    {
        // WIFEXITED → WEXITSTATUS ; WIFSIGNALED → -signal
        if ((status & 0x7f) == 0) return (status >> 8) & 0xff;
        return -(status & 0x7f);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

        // Stop reading/writing the master first.
        try { _master.Dispose(); } catch { /* best effort */ }

        // Terminate the child if it's still alive: SIGHUP (let the shell clean up),
        // brief grace, then SIGKILL.
        if (!HasExited)
        {
            Native.kill(ProcessId, Native.SIGHUP);
            try
            {
                await _exited.Task.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                Native.kill(ProcessId, Native.SIGKILL);
            }
        }

        // Make sure the reaper observes the exit (so no zombie), then stop it.
        if (!HasExited)
        {
            // Final synchronous reap attempt (blocking, but bounded — child was SIGKILLed).
            Native.waitpid(ProcessId, out _, 0);
            _exited.TrySetResult(-Native.SIGKILL);
        }
        _reaperCts.Cancel();
        _reaperCts.Dispose();

        // Close the master fd we kept ownership of.
        Native.close(_masterFd);
    }
}
