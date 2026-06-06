namespace NetFirewall.Services.Processes;

/// <summary>Terminal dimensions in character cells.</summary>
public readonly record struct PtySize(ushort Rows, ushort Cols)
{
    public static readonly PtySize Default = new(24, 80);
}

/// <summary>
/// Allocates pseudo-terminals and spawns a child process attached to one. Behind
/// an interface (rule #8) so it's mockable and the only place that touches the
/// libc PTY P/Invokes. Linux-only in practice — the concrete impl is annotated
/// <c>[SupportedOSPlatform("linux")]</c> and registered only in the daemon, which
/// is the privileged process. Validated by the Phase 3a spike: <c>openpty</c>
/// (libutil) + <c>posix_spawn</c> (never <c>forkpty</c> — it crashes the forked
/// CLR child before exec).
/// </summary>
public interface IPtyService
{
    /// <summary>
    /// Allocate a PTY and spawn <paramref name="shell"/> attached to its slave as
    /// the controlling terminal (new session via POSIX_SPAWN_SETSID). The returned
    /// session's <see cref="IPtySession.Master"/> stream is the read/write end:
    /// write keystrokes to it, read shell output from it.
    /// </summary>
    /// <param name="shell">Absolute path to the program to run (e.g. <c>/bin/bash</c>).</param>
    /// <param name="args">Extra argv after the program name (e.g. <c>-l</c> for a login shell).</param>
    /// <param name="size">Initial window size.</param>
    /// <param name="env">Environment for the child. When null, a minimal safe default
    /// (TERM + PATH) is used.</param>
    IPtySession Start(string shell, IReadOnlyList<string> args, PtySize size, IReadOnlyDictionary<string, string>? env = null);
}

/// <summary>
/// A live PTY + its child process. Disposing (async) tears the child down
/// (SIGHUP → SIGKILL) and reaps it, and closes the master fd — so a dropped
/// WebSocket can never leak a detached root shell. Idempotent.
/// </summary>
public interface IPtySession : IAsyncDisposable
{
    /// <summary>The master end. Read shell output, write keystrokes. Async I/O.
    /// A read returning 0 / throwing on EIO means the child closed the slave
    /// (shell exited).</summary>
    Stream Master { get; }

    /// <summary>PID of the spawned child.</summary>
    int ProcessId { get; }

    /// <summary>True once the child has exited (observed via wait or master EOF).</summary>
    bool HasExited { get; }

    /// <summary>Push a new window size to the kernel (ioctl TIOCSWINSZ on the master).
    /// No-op once the child has exited.</summary>
    void Resize(PtySize size);

    /// <summary>Completes when the child process exits, yielding its exit code
    /// (or the negative signal number if it was killed). Never throws.</summary>
    Task<int> WaitForExitAsync(CancellationToken ct = default);
}
