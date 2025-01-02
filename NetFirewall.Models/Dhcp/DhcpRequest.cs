using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace NetFirewall.Models.Dhcp;

public class DhcpRequest
{
    public string ClientMac { get; set; }
    public bool IsBootp { get; set; }
    public bool IsPxeRequest { get; set; }
    public DhcpMessageType MessageType { get; set; }
    public IPAddress RequestedIp { get; set; }
    public IPAddress ClientIp { get; set; }
    public string Hostname { get; set; }
    public int LeaseTime { get; set; }
    // Add other fields as needed for BOOTP/PXE like Vendor Class Identifier, etc.
}