using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace NetFirewall.Models.Dhcp;

public class DhcpRequest
{
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
    public DhcpMessageType MessageType { get; set; }
    public IPAddress RequestedIp { get; set; }
    public byte[] ClientIdentifier { get; set; }
    public string Hostname { get; set; }
    public byte[] ParameterRequestList { get; set; }
    public string VendorClassIdentifier { get; set; }
    public int LeaseTime { get; set; }
    public bool IsBootp { get; set; }
    public bool IsPxeRequest { get; set; }
    public IPEndPoint RemoteEndPoint { get; set; }
}