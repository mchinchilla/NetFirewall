using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace NetFirewall.Daemon;

/// <summary>
/// Thin libc P/Invokes for things .NET doesn't expose. Linux-only: the daemon
/// itself is annotated <c>[assembly: SupportedOSPlatform("linux")]</c>.
/// </summary>
[SupportedOSPlatform("linux")]
internal static class NativeMethods
{
    [DllImport("libc", SetLastError = true, EntryPoint = "chown")]
    public static extern int Chown(string path, uint owner, uint group);

    [DllImport("libc", SetLastError = true, EntryPoint = "getgrnam")]
    private static extern IntPtr GetGrNam(string name);

    [StructLayout(LayoutKind.Sequential)]
    private struct Group
    {
        public IntPtr Name;
        public IntPtr Password;
        public uint Gid;
        public IntPtr Members;
    }

    /// <summary>
    /// Resolve a group name to its GID. Returns null when the group doesn't
    /// exist on the host.
    /// </summary>
    public static uint? GetGroupId(string name)
    {
        var ptr = GetGrNam(name);
        if (ptr == IntPtr.Zero) return null;
        var grp = Marshal.PtrToStructure<Group>(ptr);
        return grp.Gid;
    }
}
