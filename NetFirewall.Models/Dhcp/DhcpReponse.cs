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
    public IPAddress CiAddr { get; set; }
    public IPAddress YiAddr { get; set; }
    public IPAddress SiAddr { get; set; }
    public IPAddress GiAddr { get; set; }
    public string ClientMac { get; set; }
    public byte[] ChAddr { get; set; }
    public string SName { get; set; }
    public string File { get; set; }

    // DHCP Options for Response:
    public DhcpMessageType MessageType { get; set; }
    public IPAddress ServerIdentifier { get; set; }
    public IPAddress SubnetMask { get; set; }
    public IPAddress Router { get; set; }
    public IPAddress[] DnsServers { get; set; }
    public string DomainName { get; set; }
    public int LeaseTime { get; set; }
    public int RenewalTime { get; set; }
    public int RebindingTime { get; set; }

    public bool IsBootp { get; set; }
    public IPEndPoint RemoteEndPoint { get; set; }

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