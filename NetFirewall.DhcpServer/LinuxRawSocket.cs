using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace NetFirewall.DhcpServer;

/// <summary>
/// Linux raw packet socket (AF_PACKET) for receiving DHCP broadcasts.
/// This is necessary because standard UDP sockets don't reliably receive
/// packets destined to 255.255.255.255 on Linux.
/// </summary>
public sealed class LinuxRawSocket : IDisposable
{
    // Socket constants
    private const int AF_PACKET = 17;
    private const int SOCK_DGRAM = 2;  // Cooked packets (no ethernet header)
    private const int SOCK_RAW = 3;    // Raw packets (with ethernet header)
    private const int ETH_P_IP = 0x0800;
    private const int ETH_P_ALL = 0x0003;

    // Ethernet header size
    private const int ETH_HEADER_SIZE = 14;
    private const int ETH_TYPE_IP = 0x0800;

    // Protocol numbers
    private const int IPPROTO_UDP = 17;

    // Socket options
    private const int SOL_SOCKET = 1;
    private const int SO_RCVTIMEO = 20;

    // Offsets in IP header
    private const int IP_HEADER_MIN_SIZE = 20;
    private const int UDP_HEADER_SIZE = 8;

    private readonly int _socketFd;
    private readonly int _interfaceIndex;
    private readonly ILogger _logger;
    private bool _disposed;

    /// <summary>
    /// The network interface name this socket is bound to.
    /// </summary>
    public string InterfaceName { get; }

    [DllImport("libc", SetLastError = true)]
    private static extern int socket(int domain, int type, int protocol);

    [DllImport("libc", SetLastError = true)]
    private static extern int bind(int sockfd, ref SockAddrLl addr, int addrlen);

    [DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);

    [DllImport("libc", SetLastError = true)]
    private static extern nint recv(int sockfd, byte[] buf, nint len, int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern nint recvfrom(int sockfd, byte[] buf, nint len, int flags,
        ref SockAddrLl srcAddr, ref int addrlen);

    [DllImport("libc", SetLastError = true)]
    private static extern int setsockopt(int sockfd, int level, int optname, ref int optval, int optlen);

    [DllImport("libc", SetLastError = true)]
    private static extern int setsockopt(int sockfd, int level, int optname, byte[] optval, int optlen);

    [DllImport("libc", SetLastError = true)]
    private static extern int setsockopt(int sockfd, int level, int optname, ref Timeval optval, int optlen);

    [StructLayout(LayoutKind.Sequential)]
    private struct SockAddrLl
    {
        public ushort sll_family;      // Always AF_PACKET
        public ushort sll_protocol;    // Physical layer protocol (network byte order)
        public int sll_ifindex;        // Interface index
        public ushort sll_hatype;      // ARP hardware type
        public byte sll_pkttype;       // Packet type
        public byte sll_halen;         // Length of address
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] sll_addr;        // Physical layer address
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Timeval
    {
        public long tv_sec;
        public long tv_usec;
    }

    public LinuxRawSocket(string interfaceName, ILogger logger)
    {
        _logger = logger;
        InterfaceName = interfaceName;

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            throw new PlatformNotSupportedException("LinuxRawSocket is only supported on Linux");
        }

        // Get interface index
        _interfaceIndex = GetInterfaceIndex(interfaceName);
        _logger.LogInformation("[RAW] Interface {Name} has index {Index}", interfaceName, _interfaceIndex);

        // Create raw packet socket with SOCK_RAW to get full ethernet frames
        // Use ETH_P_ALL to capture all protocols (including broadcasts)
        ushort protocol = (ushort)IPAddress.HostToNetworkOrder((short)ETH_P_ALL);

        _socketFd = socket(AF_PACKET, SOCK_RAW, protocol);
        if (_socketFd < 0)
        {
            int error = Marshal.GetLastWin32Error();
            throw new InvalidOperationException($"Failed to create raw socket: errno={error}. Make sure you're running as root.");
        }

        _logger.LogInformation("[RAW] Created AF_PACKET SOCK_RAW socket with fd={Fd} (captures all ethernet frames)", _socketFd);

        // Bind to interface
        var addr = new SockAddrLl
        {
            sll_family = AF_PACKET,
            sll_protocol = protocol,
            sll_ifindex = _interfaceIndex,
            sll_hatype = 0,
            sll_pkttype = 0,
            sll_halen = 0,
            sll_addr = new byte[8]
        };

        int result = bind(_socketFd, ref addr, Marshal.SizeOf<SockAddrLl>());
        if (result < 0)
        {
            int error = Marshal.GetLastWin32Error();
            close(_socketFd);
            throw new InvalidOperationException($"Failed to bind raw socket to interface: errno={error}");
        }

        _logger.LogInformation("[RAW] Bound to interface {Name}", interfaceName);

        // Set receive timeout (1 second)
        var timeout = new Timeval { tv_sec = 1, tv_usec = 0 };
        setsockopt(_socketFd, SOL_SOCKET, SO_RCVTIMEO, ref timeout, Marshal.SizeOf<Timeval>());

        _logger.LogInformation("[RAW] Filtering UDP port 67 in userspace");
    }

    private static int GetInterfaceIndex(string interfaceName)
    {
        var interfaces = NetworkInterface.GetAllNetworkInterfaces();
        foreach (var iface in interfaces)
        {
            if (iface.Name == interfaceName)
            {
                // On Linux, we can get the index from the Id property
                // which is the interface index as a string
                if (int.TryParse(iface.Id, out int index))
                {
                    return index;
                }

                // Fallback: use if_nametoindex
                return GetInterfaceIndexByName(interfaceName);
            }
        }

        throw new ArgumentException($"Interface '{interfaceName}' not found");
    }

    [DllImport("libc", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern uint if_nametoindex(string ifname);

    private static int GetInterfaceIndexByName(string interfaceName)
    {
        uint index = if_nametoindex(interfaceName);
        if (index == 0)
        {
            int error = Marshal.GetLastWin32Error();
            throw new ArgumentException($"Interface '{interfaceName}' not found: errno={error}");
        }
        return (int)index;
    }

    // Receive-path buffers, reused across calls. Receive() runs on exactly one
    // thread per socket (the per-interface receive loop), so plain fields are
    // safe — the previous per-call `new byte[2048]` was ~2KB of GC pressure
    // per packet on the hot path.
    private readonly byte[] _rawBuffer = new byte[2048];

    /// <summary>
    /// Result of parsing a raw ethernet frame down to its DHCP payload.
    /// </summary>
    internal readonly record struct DhcpFrameInfo(int PayloadOffset, int PayloadLength, IPAddress SourceIp, int SourcePort);

    /// <summary>
    /// Pure ethernet/IPv4/UDP demultiplexer for the AF_PACKET receive path:
    /// given a raw frame, locates the DHCP payload of a UDP datagram addressed
    /// to port 67. Returns false for anything else (ARP, IPv6, non-UDP,
    /// wrong port, truncated or inconsistent headers). No allocation besides
    /// the source IPAddress on success.
    /// </summary>
    internal static bool TryExtractDhcpPayload(ReadOnlySpan<byte> frame, out DhcpFrameInfo info)
    {
        info = default;

        // Ethernet header: 6 bytes dest MAC, 6 bytes src MAC, 2 bytes ethertype
        if (frame.Length < ETH_HEADER_SIZE)
        {
            return false;
        }

        int etherType = (frame[12] << 8) | frame[13];
        if (etherType != ETH_TYPE_IP)
        {
            return false; // Not IPv4 (could be ARP, IPv6, etc.)
        }

        int ipOffset = ETH_HEADER_SIZE;
        if (frame.Length < ipOffset + IP_HEADER_MIN_SIZE)
        {
            return false;
        }

        int ipVersion = (frame[ipOffset] >> 4) & 0x0F;
        int ipHeaderLength = (frame[ipOffset] & 0x0F) * 4;

        // IHL below 20 bytes is a malformed header — offsets computed from it
        // would land inside the IP header itself.
        if (ipVersion != 4 || ipHeaderLength < IP_HEADER_MIN_SIZE)
        {
            return false;
        }

        if (frame[ipOffset + 9] != IPPROTO_UDP)
        {
            return false;
        }

        if (frame.Length < ipOffset + ipHeaderLength + UDP_HEADER_SIZE)
        {
            return false;
        }

        int udpOffset = ipOffset + ipHeaderLength;
        int srcPort = (frame[udpOffset] << 8) | frame[udpOffset + 1];
        int dstPort = (frame[udpOffset + 2] << 8) | frame[udpOffset + 3];
        int udpLength = (frame[udpOffset + 4] << 8) | frame[udpOffset + 5];

        // Only DHCP server traffic
        if (dstPort != 67)
        {
            return false;
        }

        int dhcpOffset = udpOffset + UDP_HEADER_SIZE;
        int dhcpLength = udpLength - UDP_HEADER_SIZE;

        // The UDP length field is attacker-controlled — it must describe a
        // payload that actually fits inside the received frame.
        if (dhcpLength <= 0 || dhcpOffset + dhcpLength > frame.Length)
        {
            return false;
        }

        var srcIp = new IPAddress(frame.Slice(ipOffset + 12, 4));
        info = new DhcpFrameInfo(dhcpOffset, dhcpLength, srcIp, srcPort);
        return true;
    }

    /// <summary>
    /// Receive a DHCP packet. Returns the DHCP payload (without IP/UDP headers).
    /// </summary>
    public int Receive(byte[] buffer, out IPEndPoint? sourceEndPoint)
    {
        sourceEndPoint = null;

        var srcAddr = new SockAddrLl { sll_addr = new byte[8] };
        int addrLen = Marshal.SizeOf<SockAddrLl>();

        nint bytesRead = recvfrom(_socketFd, _rawBuffer, _rawBuffer.Length, 0, ref srcAddr, ref addrLen);

        if (bytesRead <= 0)
        {
            int error = Marshal.GetLastWin32Error();
            // EAGAIN (11) or EWOULDBLOCK means timeout - that's expected
            if (error == 11 || error == 0)
            {
                return 0;
            }

            _logger.LogDebug("[RAW] recvfrom returned {Bytes}, errno={Error}", bytesRead, error);
            return 0;
        }

        if (!TryExtractDhcpPayload(_rawBuffer.AsSpan(0, (int)bytesRead), out var frame))
        {
            return 0;
        }

        // Copy DHCP payload to output buffer
        int copyLen = Math.Min(frame.PayloadLength, buffer.Length);
        Array.Copy(_rawBuffer, frame.PayloadOffset, buffer, 0, copyLen);

        sourceEndPoint = new IPEndPoint(frame.SourceIp, frame.SourcePort);

        if (_logger.IsEnabled(LogLevel.Debug))
        {
            var srcMac = $"{_rawBuffer[6]:X2}:{_rawBuffer[7]:X2}:{_rawBuffer[8]:X2}:{_rawBuffer[9]:X2}:{_rawBuffer[10]:X2}:{_rawBuffer[11]:X2}";
            _logger.LogDebug("[RAW] DHCP packet received: {Len} bytes from {Mac} ({Source})",
                copyLen, srcMac, sourceEndPoint);
        }

        return copyLen;
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
            if (_socketFd >= 0)
            {
                close(_socketFd);
                _logger.LogDebug("[RAW] Closed socket fd={Fd}", _socketFd);
            }
        }
    }
}
