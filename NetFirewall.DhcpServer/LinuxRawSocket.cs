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

    /// <summary>
    /// Receive a DHCP packet. Returns the DHCP payload (without IP/UDP headers).
    /// </summary>
    public int Receive(byte[] buffer, out IPEndPoint? sourceEndPoint)
    {
        sourceEndPoint = null;

        // Buffer for raw ethernet frame (with ethernet header since we use SOCK_RAW)
        var rawBuffer = new byte[2048];
        var srcAddr = new SockAddrLl { sll_addr = new byte[8] };
        int addrLen = Marshal.SizeOf<SockAddrLl>();

        nint bytesRead = recvfrom(_socketFd, rawBuffer, rawBuffer.Length, 0, ref srcAddr, ref addrLen);

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

        // With SOCK_RAW, we get the full ethernet frame
        // Ethernet header: 6 bytes dest MAC, 6 bytes src MAC, 2 bytes ethertype
        if (bytesRead < ETH_HEADER_SIZE)
        {
            return 0; // Too short for ethernet header
        }

        // Check ethertype (bytes 12-13 of ethernet header)
        int etherType = (rawBuffer[12] << 8) | rawBuffer[13];
        if (etherType != ETH_TYPE_IP)
        {
            // Not an IP packet (could be ARP, IPv6, etc.) - silently ignore
            return 0;
        }

        // IP packet starts after ethernet header
        int ipOffset = ETH_HEADER_SIZE;

        if (bytesRead < ipOffset + IP_HEADER_MIN_SIZE)
        {
            return 0;
        }

        // IP header version and length
        int ipVersion = (rawBuffer[ipOffset] >> 4) & 0x0F;
        int ipHeaderLength = (rawBuffer[ipOffset] & 0x0F) * 4;

        if (ipVersion != 4)
        {
            return 0; // Not IPv4
        }

        // Check protocol is UDP (offset 9 in IP header)
        int protocol = rawBuffer[ipOffset + 9];
        if (protocol != IPPROTO_UDP)
        {
            return 0; // Not UDP
        }

        if (bytesRead < ipOffset + ipHeaderLength + UDP_HEADER_SIZE)
        {
            return 0;
        }

        // Extract source and destination IP (offsets 12 and 16 in IP header)
        var srcIp = new IPAddress(new ReadOnlySpan<byte>(rawBuffer, ipOffset + 12, 4));
        var dstIp = new IPAddress(new ReadOnlySpan<byte>(rawBuffer, ipOffset + 16, 4));

        // UDP header starts after IP header
        int udpOffset = ipOffset + ipHeaderLength;
        int srcPort = (rawBuffer[udpOffset] << 8) | rawBuffer[udpOffset + 1];
        int dstPort = (rawBuffer[udpOffset + 2] << 8) | rawBuffer[udpOffset + 3];
        int udpLength = (rawBuffer[udpOffset + 4] << 8) | rawBuffer[udpOffset + 5];

        // Only process packets to DHCP server port 67
        if (dstPort != 67)
        {
            return 0;
        }

        // Extract source MAC for logging
        var srcMac = $"{rawBuffer[6]:X2}:{rawBuffer[7]:X2}:{rawBuffer[8]:X2}:{rawBuffer[9]:X2}:{rawBuffer[10]:X2}:{rawBuffer[11]:X2}";

        _logger.LogDebug("[RAW] DHCP candidate: {SrcMac} {SrcIp}:{SrcPort} -> {DstIp}:{DstPort}, UDP len={UdpLen}",
            srcMac, srcIp, srcPort, dstIp, dstPort, udpLength);

        // Calculate DHCP payload offset and length
        int dhcpOffset = udpOffset + UDP_HEADER_SIZE;
        int dhcpLength = udpLength - UDP_HEADER_SIZE;

        if (dhcpLength <= 0 || dhcpOffset + dhcpLength > bytesRead)
        {
            _logger.LogWarning("[RAW] Invalid DHCP payload length: {Len}", dhcpLength);
            return 0;
        }

        // Copy DHCP payload to output buffer
        int copyLen = Math.Min(dhcpLength, buffer.Length);
        Array.Copy(rawBuffer, dhcpOffset, buffer, 0, copyLen);

        sourceEndPoint = new IPEndPoint(srcIp, srcPort);

        _logger.LogInformation("[RAW] DHCP packet received: {Len} bytes from {Mac} ({Source})",
            copyLen, srcMac, sourceEndPoint);

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
