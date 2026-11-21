using System.Net.Sockets;
using Microsoft.AspNetCore.Connections.Features;

namespace NetFirewall.Daemon.Auth;

/// <summary>
/// Reads the Unix-socket peer UID of the current request (<c>SO_PEERCRED</c> on
/// Linux, <c>LOCAL_PEERCRED</c> on macOS). Behind an interface so the endpoint gate
/// can be tested without a real socket.
/// </summary>
public interface IPeerUidReader
{
    /// <summary>The peer UID, or <c>null</c> when it can't be determined (not a Unix socket, unsupported platform).</summary>
    int? TryGetPeerUid(HttpContext context);
}

public sealed class SocketPeerUidReader : IPeerUidReader
{
    public int? TryGetPeerUid(HttpContext context)
    {
        var socket = context.Features.Get<IConnectionSocketFeature>()?.Socket;
        if (socket is null || socket.AddressFamily != AddressFamily.Unix) return null;

        try
        {
            if (OperatingSystem.IsLinux())
            {
                // SOL_SOCKET (1) + SO_PEERCRED (17) → ucred { pid, uid, gid }
                var buf = new byte[12];
                socket.GetRawSocketOption(1, 17, buf);
                return BitConverter.ToInt32(buf, 4);
            }
            if (OperatingSystem.IsMacOS())
            {
                // SOL_LOCAL (0) + LOCAL_PEERCRED (1) → xucred (uid at offset 4)
                var buf = new byte[76];
                socket.GetRawSocketOption(0, 1, buf);
                return BitConverter.ToInt32(buf, 4);
            }
        }
        catch
        {
            // Option unsupported or the call failed — treat as unknown.
        }
        return null;
    }
}
