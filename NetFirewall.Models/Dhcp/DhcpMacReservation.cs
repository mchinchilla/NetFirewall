using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using RepoDb.Attributes;

namespace NetFirewall.Models.Dhcp;

public class DhcpMacReservation
{
    [Map("id")]
    public Guid Id { get; set; }
    [Map("mac_address")]
    public string MacAddress { get; set; }
    [Map("hostname")]
    public string Hostname { get; set; }
    [Map("description")]
    public string Description { get; set; }
}