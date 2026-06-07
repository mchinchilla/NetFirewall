using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace NetFirewall.Daemon.Pty;

/// <summary>
/// libc P/Invokes for PTY allocation + spawning. Constants and struct layout are
/// Linux/glibc (the daemon is Linux-only). openpty is loaded from libc with a
/// libutil.so.1 fallback — see <see cref="openpty"/> (libutil.so as a bare name is
/// gone on modern glibc, which threw DllNotFoundException at runtime).
/// </summary>
[SupportedOSPlatform("linux")]
internal static class Native
{
    // ── constants ──
    public const ulong TIOCSWINSZ = 0x5414;       // Linux ioctl: set window size
    public const short POSIX_SPAWN_SETSID = 0x80; // glibc flag: child is a new session leader
    public const int WNOHANG = 1;
    public const int SIGHUP = 1;
    public const int SIGKILL = 9;

    // posix_spawn_file_actions_t / posix_spawnattr_t are opaque structs (~80 bytes
    // on glibc). Back them with generously-sized pinned buffers; the spike confirmed
    // 512 is ample and the init/destroy calls keep us ABI-correct.
    public const int FileActionsSize = 512;
    public const int SpawnAttrSize = 512;

    [StructLayout(LayoutKind.Sequential)]
    public struct Winsize
    {
        public ushort ws_row;
        public ushort ws_col;
        public ushort ws_xpixel;
        public ushort ws_ypixel;
    }

    // ── PTY allocation ──
    // openpty's home moved: on modern glibc (Debian 13 / glibc ≥ 2.34) it lives in
    // libc.so and "libutil.so" no longer exists as a loadable name → [DllImport("libutil")]
    // throws DllNotFoundException at runtime (the bug that closed every session). On
    // older systems it's only in libutil. So: try libc first, fall back to libutil.so.1.
    // (Two DllImports; OpenPty picks whichever loads.)
    [DllImport("libc", SetLastError = true, EntryPoint = "openpty")]
    private static extern int openpty_libc(out int amaster, out int aslave, IntPtr name, IntPtr termp, ref Winsize win);

    [DllImport("libutil.so.1", SetLastError = true, EntryPoint = "openpty")]
    private static extern int openpty_libutil(out int amaster, out int aslave, IntPtr name, IntPtr termp, ref Winsize win);

    public static int openpty(out int amaster, out int aslave, IntPtr name, IntPtr termp, ref Winsize win)
    {
        try { return openpty_libc(out amaster, out aslave, name, termp, ref win); }
        catch (DllNotFoundException) { /* glibc<2.34 path */ }
        catch (EntryPointNotFoundException) { /* libc present but no openpty symbol */ }
        return openpty_libutil(out amaster, out aslave, name, termp, ref win);
    }

    // ── spawn (libc) ──
    [DllImport("libc", SetLastError = true)]
    public static extern int posix_spawn(out int pid, string path, IntPtr fileActions, IntPtr attrp, string?[] argv, string?[] envp);
    [DllImport("libc")]
    public static extern int posix_spawn_file_actions_init(IntPtr fa);
    [DllImport("libc")]
    public static extern int posix_spawn_file_actions_destroy(IntPtr fa);
    [DllImport("libc")]
    public static extern int posix_spawn_file_actions_adddup2(IntPtr fa, int fd, int newfd);
    [DllImport("libc")]
    public static extern int posix_spawn_file_actions_addclose(IntPtr fa, int fd);
    [DllImport("libc")]
    public static extern int posix_spawnattr_init(IntPtr attr);
    [DllImport("libc")]
    public static extern int posix_spawnattr_destroy(IntPtr attr);
    [DllImport("libc")]
    public static extern int posix_spawnattr_setflags(IntPtr attr, short flags);

    // ── tty / process control ──
    [DllImport("libc", SetLastError = true)]
    public static extern int ioctl(int fd, ulong request, ref Winsize win);
    [DllImport("libc", SetLastError = true)]
    public static extern int close(int fd);
    [DllImport("libc", SetLastError = true)]
    public static extern int waitpid(int pid, out int status, int options);
    [DllImport("libc", SetLastError = true)]
    public static extern int kill(int pid, int sig);
}
