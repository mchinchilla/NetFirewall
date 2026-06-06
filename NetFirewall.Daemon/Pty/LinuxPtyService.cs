using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using NetFirewall.Services.Processes;

namespace NetFirewall.Daemon.Pty;

/// <summary>
/// Linux PTY implementation using libc/libutil. The mechanism was validated by
/// the Phase 3a spike on tekium (Debian 13) under the daemon's full systemd
/// sandbox (PrivateDevices=yes + the SystemCallFilter): <c>openpty</c> +
/// <c>posix_spawn</c> with <c>POSIX_SPAWN_SETSID</c> + a dup2 file-actions chain.
///
/// Deliberately NOT <c>forkpty</c>: forkpty fork()s and we'd return into a forked
/// .NET runtime in the child before exec — the spike showed that segfaults
/// ("Stack overflow" / SIGSEGV) because the CLR is in an undefined post-fork
/// state. <c>posix_spawn</c> does fork+exec atomically in native code, so no
/// managed code ever runs in the child.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxPtyService : IPtyService
{
    public IPtySession Start(string shell, IReadOnlyList<string> args, PtySize size,
        IReadOnlyDictionary<string, string>? env = null)
    {
        var win = new Native.Winsize { ws_row = size.Rows, ws_col = size.Cols };

        // 1) Allocate the master/slave pair. openpty lives in libutil on glibc.
        int master, slave;
        int rc = Native.openpty(out master, out slave, IntPtr.Zero, IntPtr.Zero, ref win);
        if (rc != 0)
            throw new PtyException($"openpty failed (errno {Marshal.GetLastPInvokeError()})");

        int pid;
        var fa = GCHandle.Alloc(new byte[Native.FileActionsSize], GCHandleType.Pinned);
        var attr = GCHandle.Alloc(new byte[Native.SpawnAttrSize], GCHandleType.Pinned);
        try
        {
            IntPtr faPtr = fa.AddrOfPinnedObject();
            IntPtr attrPtr = attr.AddrOfPinnedObject();
            Native.posix_spawn_file_actions_init(faPtr);
            Native.posix_spawnattr_init(attrPtr);

            // New session leader so the slave becomes the child's controlling tty.
            Native.posix_spawnattr_setflags(attrPtr, Native.POSIX_SPAWN_SETSID);

            // Wire the slave onto the child's stdio, then close the fds the child
            // doesn't need (the master, and the now-duplicated slave).
            Native.posix_spawn_file_actions_adddup2(faPtr, slave, 0);
            Native.posix_spawn_file_actions_adddup2(faPtr, slave, 1);
            Native.posix_spawn_file_actions_adddup2(faPtr, slave, 2);
            Native.posix_spawn_file_actions_addclose(faPtr, master);
            if (slave > 2) Native.posix_spawn_file_actions_addclose(faPtr, slave);

            var argv = BuildArgv(shell, args);
            var envp = BuildEnvp(env);

            rc = Native.posix_spawn(out pid, shell, faPtr, attrPtr, argv, envp);
        }
        finally
        {
            Native.posix_spawn_file_actions_destroy(fa.AddrOfPinnedObject());
            Native.posix_spawnattr_destroy(attr.AddrOfPinnedObject());
            fa.Free();
            attr.Free();
        }

        if (rc != 0)
        {
            Native.close(master);
            Native.close(slave);
            throw new PtyException($"posix_spawn '{shell}' failed (errno {rc})");
        }

        // We hand stdio to the child via dup2; close OUR copy of the slave so that
        // when the child exits and closes its fds, the master read returns EOF/EIO.
        Native.close(slave);

        return new LinuxPtySession(master, pid);
    }

    private static string?[] BuildArgv(string shell, IReadOnlyList<string> args)
    {
        var argv = new string?[args.Count + 2];
        argv[0] = shell;
        for (int i = 0; i < args.Count; i++) argv[i + 1] = args[i];
        argv[^1] = null; // execv requires a NULL terminator
        return argv;
    }

    private static string?[] BuildEnvp(IReadOnlyDictionary<string, string>? env)
    {
        if (env is null || env.Count == 0)
            return new string?[] { "TERM=xterm-256color",
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", null };

        var envp = new string?[env.Count + 1];
        int i = 0;
        foreach (var kv in env) envp[i++] = $"{kv.Key}={kv.Value}";
        envp[^1] = null;
        return envp;
    }
}

public sealed class PtyException : Exception
{
    public PtyException(string message) : base(message) { }
}
