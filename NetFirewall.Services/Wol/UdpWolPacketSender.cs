using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NetFirewall.Services.Wol;

/// <summary>
/// UDP broadcast pinned to one link with <c>SO_BINDTODEVICE</c>. Sent to the
/// limited broadcast address, the kernel builds the route straight from the bound
/// device without a FIB lookup — so the fwmark policy routing on this box, and
/// whichever interface happens to hold the default route, never decide where a
/// wake goes. Needs root or CAP_NET_RAW on older kernels: the daemon has both.
/// </summary>
public sealed class UdpWolPacketSender : IWolPacketSender
{
    // <asm-generic/socket.h>: SOL_SOCKET = 1, SO_BINDTODEVICE = 25 (Linux only).
    private const int SolSocket = 1;
    private const int SoBindToDevice = 25;

    private static readonly TimeSpan Gap = TimeSpan.FromMilliseconds(100);

    public async Task SendAsync(ReadOnlyMemory<byte> payload, string iface, IPAddress destination, int port, int copies, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Wake-on-LAN is sent by the daemon on Linux (SO_BINDTODEVICE).");

        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.EnableBroadcast = true;
        socket.SetRawSocketOption(SolSocket, SoBindToDevice, Encoding.ASCII.GetBytes(iface + "\0"));

        var endpoint = new IPEndPoint(destination, port);
        for (var i = 0; i < copies; i++)
        {
            if (i > 0) await Task.Delay(Gap, ct);
            await socket.SendToAsync(payload, SocketFlags.None, endpoint, ct);
        }
    }
}
