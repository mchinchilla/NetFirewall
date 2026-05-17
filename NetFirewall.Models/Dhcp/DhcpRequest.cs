using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace NetFirewall.Models.Dhcp;

public class DhcpRequest
{
    // Fixed Fields from DHCP Header
    public byte Op { get; set; }
    public byte HType { get; set; }
    public byte HLen { get; set; }
    public byte Hops { get; set; }
    public byte[] Xid { get; set; }
    public ushort Secs { get; set; }
    public ushort Flags { get; set; }
    public IPAddress CiAddr { get; set; } = IPAddress.Any;
    public IPAddress YiAddr { get; set; } = IPAddress.Any;
    public IPAddress SiAddr { get; set; } = IPAddress.Any;
    public IPAddress GiAddr { get; set; } = IPAddress.Any;
    public string ClientMac { get; set; } = string.Empty;
    public byte[] ChAddr { get; set; } = Array.Empty<byte>();
    public string SName { get; set; } = string.Empty;
    public string File { get; set; } = string.Empty;

    // DHCP Options
    public DhcpMessageType MessageType { get; set; }
    public IPAddress RequestedIp { get; set; } = IPAddress.Any;
    public byte[] ClientIdentifier { get; set; } = Array.Empty<byte>();
    public string Hostname { get; set; } = string.Empty;
    public byte[] ParameterRequestList { get; set; } = Array.Empty<byte>();
    public string VendorClassIdentifier { get; set; } = string.Empty;
    public int LeaseTime { get; set; }

    public bool IsBootp { get; set; }
    public bool IsPxeRequest { get; set; }
    public IPEndPoint RemoteEndPoint { get; set; } = new(IPAddress.Any, 0);

    /// <summary>
    /// The network interface name on which this request was received.
    /// Used for multi-interface DHCP server to select the correct subnet.
    /// </summary>
    public string? SourceInterfaceName { get; set; }

    public DhcpRequest()
    {
        Xid = new byte[ 4 ];
        ChAddr = new byte[ 16 ];
    }
}