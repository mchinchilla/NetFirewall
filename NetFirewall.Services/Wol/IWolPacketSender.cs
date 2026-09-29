using System.Net;

namespace NetFirewall.Services.Wol;

/// <summary>
/// The socket half of Wake-on-LAN, kept behind an interface so the choice of
/// link and the validation around it can be tested without a network.
/// </summary>
public interface IWolPacketSender
{
    /// <summary>
    /// Sends <paramref name="payload"/> as a UDP broadcast out of <paramref name="iface"/>,
    /// <paramref name="copies"/> times. Throws <see cref="System.Net.Sockets.SocketException"/>
    /// when the kernel refuses (link down, no permission).
    /// </summary>
    Task SendAsync(ReadOnlyMemory<byte> payload, string iface, IPAddress destination, int port, int copies, CancellationToken ct = default);
}
