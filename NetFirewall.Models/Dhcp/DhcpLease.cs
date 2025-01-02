using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace NetFirewall.Models.Dhcp;

public class DhcpLease
{
    public Guid Id { get; set; }
    public string MacAddress { get; set; }
    public IPAddress IpAddress { get; set; }
    public DateTime StartTime { get; set; }
    public DateTime EndTime { get; set; }
    public string Hostname { get; set; }
    public string Description { get; set; }
}