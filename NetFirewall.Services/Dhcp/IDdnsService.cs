using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace NetFirewall.Services.Dhcp;

public interface IDdnsService
{
    Task UpdateDnsAsync( string hostname, IPAddress ip );
}