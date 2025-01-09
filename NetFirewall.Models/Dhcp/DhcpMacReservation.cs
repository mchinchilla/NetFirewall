using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using RepoDb.Attributes;

namespace NetFirewall.Models.Dhcp;

public class DhcpMacReservation
{
    public Guid Id { get; set; }
    public string MacAddress { get; set; }
    public IPAddress ReservedIp { get; set; }
}