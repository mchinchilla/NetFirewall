using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using NetFirewall.Services.Processes;

namespace NetFirewall.Daemon.Pty;

/// <summary>
/// A live PTY + child. I/O goes through a SEQUENTIAL, effectively-unbuffered
/// <see cref="FileStream"/> over the master fd. NOT <see cref="RandomAccess"/>:
/// RandomAccess uses pread/pwrite, which throw "Stream does not support seeking"
/// on a PTY master (a non-seekable char device) — that was the regression that
/// closed every session instantly with reason=shell_exit. bufferSize:1 means no
/// shared buffer state, so the two pumps (read = shell output, write = keystrokes)
/// run concurrently safely — a PTY's two directions are independent in the kernel.
///
/// Teardown sends SIGHUP then SIGKILL to the child's PROCESS GROUP (negative pid —
/// setsid made it the session/group leader) so grandchildren don't orphan, then
/// reaps. The background reaper is cancelled and awaited before the final blocking
/// reap so only one thread ever calls waitpid on the pid.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed class LinuxPtySession : IPtySession
{
    private readonly int _masterFd;
    private readonly SafeFileHandle _handle;
    private readonly FileStream _master;
    private readonly TaskCompletionSource<int> _exited =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly CancellationTokenSource _reaperCts = new();
    private readonly Task _reaper;
    private int _disposed;

    public LinuxPtySession(int masterFd, int pid)
    {
        _masterFd = masterFd;
        ProcessId = pid;
        // The master is a PTY (character device) — NOT seekable. RandomAccess
        // (pread/pwrite) fails on it with ESPIPE, so use a SEQUENTIAL FileStream.
        // isAsync: FALSE — openpty's fd is a plain (synchronous, non-overlapped) fd;
        // FileStream(isAsync:true) rejects it with "Handle does not support
        // asynchronous operations". With isAsync:false, ReadAsync/WriteAsync still
        // work (offloaded to the thread pool) — fine for an interactive terminal.
        // bufferSize:1 = effectively unbuffered, so the read pump (shell output) and
        // write pump (keystrokes) don't share buffer state — a PTY's two directions
        // are independent in the kernel.
        // ownsHandle:false — we close the raw fd ourselves in dispose after reaping.
        _handle = new SafeFileHandle((IntPtr)masterFd, ownsHandle: false);
        _master = new FileStream(_handle, FileAccess.ReadWrite, bufferSize: 1, isAsync: false);
        _reaper = Task.Run(ReaperLoopAsync);
    }

    public int ProcessId { get; }
    public bool HasExited => _exited.Task.IsCompleted;

    public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        => _master.ReadAsync(buffer, ct);

    public async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        await _master.WriteAsync(buffer, ct);
        await _master.FlushAsync(ct);
    }

    public void Resize(PtySize size)
    {
        if (HasExited) return;
        var win = new Native.Winsize { ws_row = size.Rows, ws_col = size.Cols };
        Native.ioctl(_masterFd, Native.TIOCSWINSZ, ref win); // best-effort
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
                if (rc == ProcessId) { _exited.TrySetResult(DecodeStatus(status)); return; }
                if (rc < 0) { _exited.TrySetResult(-1); return; } // ECHILD: already gone
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

        // Terminate the child's whole PROCESS GROUP if still alive: SIGHUP (let the
        // shell + its jobs clean up), brief grace, then SIGKILL. Negative pid targets
        // the group led by bash (POSIX_SPAWN_SETSID made it the session/group leader),
        // so grandchildren don't orphan into detached root processes.
        if (!HasExited)
        {
            Native.kill(-ProcessId, Native.SIGHUP);
            try { await _exited.Task.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false); }
            catch (TimeoutException) { Native.kill(-ProcessId, Native.SIGKILL); }
        }

        // Stop the background reaper and AWAIT it, so no two threads ever call
        // waitpid on this pid concurrently.
        _reaperCts.Cancel();
        try { await _reaper.ConfigureAwait(false); } catch { /* cancellation */ }

        // Authoritative final reap if the reaper didn't observe the exit.
        if (!HasExited)
        {
            Native.waitpid(ProcessId, out _, 0); // bounded — child was SIGKILLed
            _exited.TrySetResult(-Native.SIGKILL);
        }

        _reaperCts.Dispose();
        _master.Dispose();          // disposes the FileStream + SafeFileHandle...
        Native.close(_masterFd);    // ...but ownsHandle:false, so we close the fd ourselves.
    }
}
