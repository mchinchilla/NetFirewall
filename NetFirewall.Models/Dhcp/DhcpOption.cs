using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetFirewall.Models.Dhcp;

public class DhcpOption
{
    public byte Code { get; set; }
    public byte[] Data { get; set; }
}