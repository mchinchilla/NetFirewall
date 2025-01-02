using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetFirewall.Models.Dhcp;

public class DhcpRequest
{
    public string ClientMac { get; set; }
    public bool IsBootp { get; set; }
    public bool IsPxeRequest { get; set; }
    public int LeaseTime { get; set; }
    public string Hostname { get; set; }
}