#:sdk Microsoft.NET.Sdk
// =============================================================================
// THROWAWAY SPIKE — NetFirewall web-terminal Phase 3a, PTY probe.
//
// Answers the one question that can only be answered on a REAL systemd host:
// can the daemon allocate a PTY, spawn a child through it, resize it, read its
// output, and reap it — UNDER the hardened systemd sandbox (PrivateDevices=yes,
// the SystemCallFilter, etc.)?  Aspire/dev hosts apply NONE of those, so a local
// pass proves nothing; this must run where the daemon actually runs.
//
// Run it TWO ways and compare:
//   1) plain root:                 sudo dotnet run pty-probe.cs
//   2) under the daemon's sandbox: see the systemd-run command printed at the end,
//      OR temporarily point the daemon unit's ExecStart at it.
//
// Reads PASS/FAIL per sub-step. Reports which ptmx path worked (/dev/ptmx vs
// /dev/pts/ptmx) — that decides the real implementation. NOT part of the build.
// =============================================================================
using System.Runtime.InteropServices;

Console.WriteLine($"== NetFirewall PTY probe ==  uid={getuid()}  pid={Environment.ProcessId}");
Console.WriteLine($"OS: {RuntimeInformation.OSDescription}");
Console.WriteLine($"/dev/ptmx exists: {File.Exists("/dev/ptmx")}   /dev/pts/ptmx exists: {File.Exists("/dev/pts/ptmx")}");
Console.WriteLine();

int passes = 0, fails = 0;
void Ok(string m)   { Console.WriteLine($"  PASS  {m}"); passes++; }
void Bad(string m)  { Console.WriteLine($"  FAIL  {m}"); fails++; }

// ---- Step 1: openpty() from libutil -----------------------------------------
// Allocate a master/slave pair. This is the load-bearing call: if PrivateDevices
// blocks /dev/ptmx, this is where it fails (EACCES/ENODEV/EPERM).
int master = -1, slave = -1;
var initialWin = new winsize { ws_row = 24, ws_col = 80 };
int rc;
try
{
    rc = openpty(out master, out slave, IntPtr.Zero, IntPtr.Zero, ref initialWin);
}
catch (DllNotFoundException)
{
    // glibc: openpty lives in libutil; musl: in libc. Retry via libc entrypoint.
    rc = openpty_libc(out master, out slave, IntPtr.Zero, IntPtr.Zero, ref initialWin);
}
if (rc != 0) { Bad($"openpty() rc={rc} errno={Marshal.GetLastPInvokeError()} — PTY allocation BLOCKED. This is the PrivateDevices/sandbox failure mode."); Done(); return; }
Ok($"openpty() master={master} slave={slave}");

// Which ptmx is actually backing this? (informational — confirms the path the
// real impl should open if it ever opens ptmx directly instead of openpty.)
Console.WriteLine($"        (openpty succeeded; impl can rely on libutil openpty)");

// ---- Step 2: TIOCSWINSZ on the master (the live-resize path) -----------------
var newWin = new winsize { ws_row = 40, ws_col = 120 };
const ulong TIOCSWINSZ = 0x5414; // Linux, all common arches
rc = ioctl(master, TIOCSWINSZ, ref newWin);
if (rc != 0) Bad($"ioctl(TIOCSWINSZ) rc={rc} errno={Marshal.GetLastPInvokeError()}");
else Ok("ioctl(TIOCSWINSZ) — resize works");

// ---- Step 3: posix_spawn a child attached to the slave as its controlling tty -
// This is what the REAL daemon impl will do (NOT forkpty): posix_spawn forks+execs
// atomically in NATIVE code, so there is no window where managed/.NET code runs in
// the child — that window is what segfaulted the earlier forkpty attempt (the CLR
// is in an undefined state after fork). We:
//   - dup the slave fd onto child stdin/stdout/stderr (file_actions adddup2),
//   - close the master + the now-redundant slave fd in the child,
//   - set POSIX_SPAWN_SETSID so the child is a new session leader and the slave
//     becomes its controlling terminal (the kernel sets the ctty on first tty open
//     by a session leader with no ctty — which is exactly the dup2-onto-0 here).
// We KEEP the master/slave pair from Step 1; master is our read/write end.
var faBuf = new byte[512];   // posix_spawn_file_actions_t is opaque; 80 bytes on glibc, 512 is ample
var attrBuf = new byte[512]; // posix_spawnattr_t likewise
var faHandle = GCHandle.Alloc(faBuf, GCHandleType.Pinned);
var attrHandle = GCHandle.Alloc(attrBuf, GCHandleType.Pinned);
IntPtr fa = faHandle.AddrOfPinnedObject();
IntPtr attr = attrHandle.AddrOfPinnedObject();

posix_spawn_file_actions_init(fa);
posix_spawnattr_init(attr);

const short POSIX_SPAWN_SETSID = 0x80; // glibc value
rc = posix_spawnattr_setflags(attr, POSIX_SPAWN_SETSID);
if (rc != 0) Bad($"posix_spawnattr_setflags(SETSID) rc={rc} — may be glibc<2.26; child won't get a ctty");

// dup slave → 0,1,2 ; then close the original master+slave fds in the child.
posix_spawn_file_actions_adddup2(fa, slave, 0);
posix_spawn_file_actions_adddup2(fa, slave, 1);
posix_spawn_file_actions_adddup2(fa, slave, 2);
posix_spawn_file_actions_addclose(fa, master);
if (slave > 2) posix_spawn_file_actions_addclose(fa, slave);

string?[] argv = { "/bin/sh", "-c", "tty; echo COLUMNS=$(tput cols 2>/dev/null) LINES=$(tput lines 2>/dev/null); echo PTY_CHILD_OK; exit 7", null };
string?[] envp = { "TERM=xterm-256color", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", null };

rc = posix_spawn(out int pid, "/bin/sh", fa, attr, argv, envp);
posix_spawn_file_actions_destroy(fa);
posix_spawnattr_destroy(attr);
faHandle.Free();
attrHandle.Free();

if (rc != 0) { Bad($"posix_spawn rc={rc} errno={Marshal.GetLastPInvokeError()}"); close(master); close(slave); Done(); return; }
Ok($"posix_spawn spawned child pid={pid}");

// Close OUR copy of the slave — only the child should hold it now, so when the
// child exits the master read returns EOF/EIO.
close(slave);

// PARENT: read from master until EOF (child exits → master read returns 0 / EIO).
var fs = new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle((IntPtr)master, ownsHandle: true), FileAccess.Read);
var sb = new System.Text.StringBuilder();
var buf = new byte[4096];
try
{
    while (true)
    {
        int n;
        try { n = fs.Read(buf, 0, buf.Length); }
        catch (IOException) { break; } // EIO on master after slave closes = normal EOF on Linux PTY
        if (n <= 0) break;
        sb.Append(System.Text.Encoding.UTF8.GetString(buf, 0, n));
    }
}
catch (Exception ex) { Bad($"reading master: {ex.GetType().Name}: {ex.Message}"); }

var outp = sb.ToString();
if (outp.Contains("PTY_CHILD_OK")) Ok("child ran through the PTY and its output was read back");
else Bad("did not see PTY_CHILD_OK in child output");
if (outp.Contains("/dev/pts/")) Ok("child's tty is a /dev/pts/* slave (real PTY, not a pipe)");
else Bad("child tty was not a /dev/pts/* device");

// ---- Step 4: reap the child --------------------------------------------------
rc = waitpid(pid, out int status, 0);
if (rc == pid) Ok($"waitpid reaped child (raw status=0x{status:x}, exit≈{(status >> 8) & 0xff})");
else Bad($"waitpid rc={rc} errno={Marshal.GetLastPInvokeError()}");

Console.WriteLine();
Console.WriteLine("---- child output (verbatim) ----");
Console.Write(outp);
if (!outp.EndsWith("\n")) Console.WriteLine();
Console.WriteLine("---------------------------------");

Done();

void Done()
{
    Console.WriteLine();
    Console.WriteLine($"SPIKE-PTY: {(fails == 0 ? "PASS" : "FAIL")}  ({passes} passed, {fails} failed)");
    Console.WriteLine();
    Console.WriteLine("To run under the daemon's actual sandbox (the real test), as root:");
    Console.WriteLine("  systemd-run --pty --same-dir --wait --collect \\");
    Console.WriteLine("    -p PrivateDevices=yes -p ProtectSystem=strict -p NoNewPrivileges=yes \\");
    Console.WriteLine("    -p 'SystemCallFilter=@system-service' -p 'SystemCallFilter=~@mount @swap @reboot @raw-io @cpu-emulation' \\");
    Console.WriteLine("    /usr/bin/dotnet run " + Path.GetFullPath(Environment.GetCommandLineArgs()[0]));
    Console.WriteLine("  (if 'dotnet run <file>' is awkward under systemd-run, 'dotnet build' it to a dll first and point at the dll)");
}

// ---- P/Invokes ----
[DllImport("libutil", SetLastError = true, EntryPoint = "openpty")]
static extern int openpty(out int amaster, out int aslave, IntPtr name, IntPtr termp, ref winsize win);
[DllImport("libc", SetLastError = true, EntryPoint = "openpty")]
static extern int openpty_libc(out int amaster, out int aslave, IntPtr name, IntPtr termp, ref winsize win);

// posix_spawn family (glibc, in libc) — the real spawn path: native fork+exec,
// no managed-child window.
[DllImport("libc", SetLastError = true)]
static extern int posix_spawn(out int pid, string path, IntPtr fileActions, IntPtr attrp, string?[] argv, string?[] envp);
[DllImport("libc")]
static extern int posix_spawn_file_actions_init(IntPtr fa);
[DllImport("libc")]
static extern int posix_spawn_file_actions_destroy(IntPtr fa);
[DllImport("libc")]
static extern int posix_spawn_file_actions_adddup2(IntPtr fa, int fd, int newfd);
[DllImport("libc")]
static extern int posix_spawn_file_actions_addclose(IntPtr fa, int fd);
[DllImport("libc")]
static extern int posix_spawnattr_init(IntPtr attr);
[DllImport("libc")]
static extern int posix_spawnattr_destroy(IntPtr attr);
[DllImport("libc")]
static extern int posix_spawnattr_setflags(IntPtr attr, short flags);

[DllImport("libc", SetLastError = true)]
static extern int ioctl(int fd, ulong request, ref winsize win);
[DllImport("libc", SetLastError = true)]
static extern int close(int fd);
[DllImport("libc", SetLastError = true)]
static extern int waitpid(int pid, out int status, int options);
[DllImport("libc")]
static extern uint getuid();

[StructLayout(LayoutKind.Sequential)]
struct winsize { public ushort ws_row, ws_col, ws_xpixel, ws_ypixel; }
