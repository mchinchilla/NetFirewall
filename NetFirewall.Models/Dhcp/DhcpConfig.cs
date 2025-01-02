using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace NetFirewall.Models.Dhcp;

public class DhcpConfig
{
    public Guid Id { get; set; }
    public IPAddress IpRangeStart { get; set; }
    public IPAddress IpRangeEnd { get; set; }
    public IPAddress SubnetMask { get; set; }
    public int LeaseTime { get; set; }
    public IPAddress Gateway { get; set; }
    public IPAddress[] DnsServers { get; set; }
    public string BootFileName { get; set; }
    public string ServerName { get; set; }
    public string Description { get; set; }
}