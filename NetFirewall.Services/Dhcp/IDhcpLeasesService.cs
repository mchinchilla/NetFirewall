using NetFirewall.Models.Dhcp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace NetFirewall.Services.Dhcp;

public interface IDhcpLeasesService
{
    Task<IPAddress> AssignOrGetLeaseAsync( string macAddress, IPAddress rangeStart, IPAddress rangeEnd, DhcpRequest request );
}