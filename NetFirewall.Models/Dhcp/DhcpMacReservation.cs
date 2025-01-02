using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetFirewall.Models.Dhcp;

public class DhcpMacReservation
{
    public Guid Id { get; set; }
    public string MacAddress { get; set; }
    public string Hostname { get; set; }
    public string Description { get; set; }
}