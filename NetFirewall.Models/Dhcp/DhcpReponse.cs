using System.Net;

namespace NetFirewall.Models.Dhcp;

public class DhcpResponse
{
    // Fixed Fields from DHCP Header - these are set based on the request
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

    // DHCP Options for Response:
    public DhcpMessageType MessageType { get; set; }
    public IPAddress ServerIdentifier { get; set; } = IPAddress.Any;
    public IPAddress SubnetMask { get; set; } = IPAddress.Any;
    public IPAddress Router { get; set; } = IPAddress.Any;
    public IPAddress[] DnsServers { get; set; } = Array.Empty<IPAddress>();
    public string DomainName { get; set; } = string.Empty;
    public int LeaseTime { get; set; }
    public int RenewalTime { get; set; }
    public int RebindingTime { get; set; }

    public bool IsBootp { get; set; }
    public IPEndPoint RemoteEndPoint { get; set; } = new(IPAddress.Any, 0);

    public DhcpResponse()
    {
        Xid = new byte[ 4 ];
        ChAddr = new byte[ 16 ];
    }

    // Constructor to initialize based on a request
    public DhcpResponse( DhcpRequest request )
    {
        Op = 2; // BOOTREPLY
        HType = request.HType;
        HLen = request.HLen;
        Hops = 0; // For direct server response
        Xid = request.Xid;
        Secs = 0; // Typically 0 for responses
        Flags = request.Flags; // Copy from request, might include broadcast flag
        CiAddr = request.CiAddr;
        ChAddr = request.ChAddr;
        ClientMac = request.ClientMac;
        GiAddr = request.GiAddr; // Might be set if through a relay
        SName = string.Empty; // Only set if applicable
        File = string.Empty; // Only set if applicable
        RemoteEndPoint = request.RemoteEndPoint;
    }
}