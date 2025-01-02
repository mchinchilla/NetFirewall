using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace NetFirewall.Services.Dhcp;

public class DdnsService : IDdnsService
{
    public async Task UpdateDnsAsync( string hostname, IPAddress ip )
    {
        // Implement DNS update logic
    }
}